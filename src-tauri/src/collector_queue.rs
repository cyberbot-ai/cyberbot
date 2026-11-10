use crate::{monitoring, store::Store};
use std::{collections::HashMap, sync::Mutex};
use tokio::sync::Notify;

pub(crate) const BUSY: &str = "The collector is busy";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lane {
    Background,
    Manual,
}

#[derive(Clone, Default)]
pub(crate) struct Activity {
    running: HashMap<String, Lane>,
    manual_waiters: HashMap<String, usize>,
}

impl Activity {
    pub(crate) fn occupied(&self, id: &str) -> bool {
        self.running.contains_key(id) || self.manual_waiters.contains_key(id)
    }

    pub(crate) fn background_count(&self) -> usize {
        self.running
            .values()
            .filter(|&&lane| lane == Lane::Background)
            .count()
    }

    pub(crate) fn running_count(&self) -> usize {
        self.running.len()
    }
}

#[derive(Default)]
pub(crate) struct Queue {
    activity: Mutex<Activity>,
    changed: Notify,
    pub(crate) released: Notify,
}

impl Queue {
    pub(crate) fn snapshot(&self) -> Result<Activity, String> {
        Ok(self.activity.lock().map_err(err)?.clone())
    }

    pub(crate) fn try_background(
        &self,
        id: &str,
        limit: usize,
    ) -> Result<Option<Guard<'_>>, String> {
        let mut activity = self.activity.lock().map_err(err)?;
        if activity.occupied(id) || activity.background_count() >= limit {
            return Ok(None);
        }
        activity.running.insert(id.into(), Lane::Background);
        Ok(Some(Guard {
            queue: self,
            id: id.into(),
        }))
    }

    pub(crate) async fn acquire(&self, id: &str, store: &Store) -> Result<Guard<'_>, String> {
        if monitoring::context().is_some_and(|e| e.trigger == "manual") {
            let guard = self.manual(id).await?;
            // The policy may have changed while a manual request was waiting.
            let db = store.0.lock().map_err(err)?;
            monitoring::check_commit(&db)?;
            Ok(guard)
        } else {
            self.try_background(id, store.settings()?.concurrency)?
                .ok_or_else(|| BUSY.into())
        }
    }

    pub(crate) async fn manual(&self, id: &str) -> Result<Guard<'_>, String> {
        {
            let mut activity = self.activity.lock().map_err(err)?;
            *activity.manual_waiters.entry(id.into()).or_default() += 1;
        }
        let _waiter = ManualWaiter { queue: self, id };
        loop {
            // Register before checking availability so a concurrent release is not missed.
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut activity = self.activity.lock().map_err(err)?;
                if !activity.running.contains_key(id) {
                    activity.running.insert(id.into(), Lane::Manual);
                    return Ok(Guard {
                        queue: self,
                        id: id.into(),
                    });
                }
            }
            changed.await;
        }
    }
}

pub(crate) struct Guard<'a> {
    queue: &'a Queue,
    id: String,
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if let Ok(mut activity) = self.queue.activity.lock() {
            activity.running.remove(&self.id);
        }
        self.queue.changed.notify_waiters();
        self.queue.released.notify_one();
    }
}

struct ManualWaiter<'a> {
    queue: &'a Queue,
    id: &'a str,
}

impl Drop for ManualWaiter<'_> {
    fn drop(&mut self) {
        if let Ok(mut activity) = self.queue.activity.lock() {
            if let Some(count) = activity.manual_waiters.get_mut(self.id) {
                *count -= 1;
                if *count == 0 {
                    activity.manual_waiters.remove(self.id);
                }
            }
        }
    }
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::{poll_fn, Future},
        task::Poll,
        time::Duration,
    };

    #[tokio::test]
    async fn manual_bypasses_background_capacity_and_gets_the_same_server_next() {
        let queue = Queue::default();
        let background = queue.try_background("a", 1).unwrap().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.sqlite")).unwrap();
        let manual = monitoring::run(&store, "metrics", "b", "", queue.acquire("b", &store))
            .await
            .unwrap();
        assert_eq!(queue.snapshot().unwrap().background_count(), 1);
        assert!(queue.try_background("c", 1).unwrap().is_none());

        let waiting = queue.manual("a");
        tokio::pin!(waiting);
        poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(background);
        assert!(queue.try_background("a", 1).unwrap().is_none());
        let on_a = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        assert!(queue.try_background("c", 1).unwrap().is_some());
        drop(on_a);
        drop(manual);
        assert_eq!(queue.snapshot().unwrap().running_count(), 0);
    }

    #[tokio::test]
    async fn cancelled_manual_request_does_not_reserve_the_server() {
        let queue = Queue::default();
        let background = queue.try_background("a", 1).unwrap().unwrap();
        let mut waiting = Box::pin(queue.manual("a"));
        poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(waiting);
        drop(background);
        assert!(!queue.snapshot().unwrap().occupied("a"));
        assert!(queue.try_background("a", 1).unwrap().is_some());
    }
}
