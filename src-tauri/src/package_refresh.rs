//! Coalesced bulletin refresh requests from package inventory changes.
use std::{collections::BTreeSet, sync::Mutex};
use tokio::sync::Notify;

#[derive(Default)]
pub(crate) struct Queue {
    advisories: Mutex<BTreeSet<String>>,
    pub(crate) wake: Notify,
}

impl Queue {
    pub(crate) fn prioritize_advisory(&self, source: String) {
        if let Ok(mut sources) = self.advisories.lock() {
            sources.insert(source);
            self.wake.notify_one();
        }
    }

    pub(crate) fn defer_advisories(&self, pending: impl IntoIterator<Item = String>) {
        if let Ok(mut sources) = self.advisories.lock() {
            sources.extend(pending);
        }
    }

    pub(crate) fn take_advisories(&self) -> BTreeSet<String> {
        self.advisories
            .lock()
            .map(|mut sources| std::mem::take(&mut *sources))
            .unwrap_or_default()
    }
}
