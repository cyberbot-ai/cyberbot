//! Transactional, bounded incident notification outbox. Delivery never calls a model or SSH.
mod native;
use crate::{
    activity,
    model::{now, Incident},
    store::Store,
    AppState,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};
use tauri::{Emitter, Manager};
static WAKE: LazyLock<tokio::sync::Notify> = LazyLock::new(tokio::sync::Notify::new);
static TARGET: Mutex<Option<String>> = Mutex::new(None);
const CAP: i64 = 10_000;
const WINDOW: i64 = 5;
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn text(v: &str, max: usize) -> String {
    v.chars()
        .filter(|c| !c.is_control())
        .scan(0, |n, c| {
            *n += c.len_utf8();
            (*n <= max).then_some(c)
        })
        .collect()
}

pub(crate) fn migrate(db: &Connection) -> Result<()> {
    db.execute_batch("BEGIN IMMEDIATE;
      CREATE TABLE IF NOT EXISTS notification_control(id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL DEFAULT 1,asked INTEGER NOT NULL DEFAULT 0,overflow INTEGER NOT NULL DEFAULT 0,overflow_at INTEGER NOT NULL DEFAULT 0,error TEXT);
      INSERT OR IGNORE INTO notification_control(id) VALUES(1);
      CREATE TABLE IF NOT EXISTS notification_events(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,episode TEXT NOT NULL,server_id TEXT NOT NULL,at INTEGER NOT NULL,state TEXT NOT NULL,batch_id TEXT,payload TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS notification_events_pending ON notification_events(state,at);
      CREATE INDEX IF NOT EXISTS notification_events_batch ON notification_events(batch_id);
      CREATE TABLE IF NOT EXISTS notification_batches(id TEXT PRIMARY KEY,at INTEGER NOT NULL,next_at INTEGER NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL,payload TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS notification_batches_pending ON notification_batches(state,next_at);
      PRAGMA user_version=13; COMMIT;").map_err(err)
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Event {
    incident_id: String,
    episode: String,
    server_id: String,
    server_name: String,
    title: String,
    severity: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Batch {
    pub id: String,
    pub title: String,
    pub body: String,
    pub count: usize,
    pub servers: usize,
    pub overflow: i64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub enabled: bool,
    pub permission: String,
    pub error: Option<String>,
    pub queued: i64,
    pub overflow: i64,
}
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Target {
    pub action_request_id: Option<String>,
    pub open_actions: bool,
    pub open: bool,
    pub incident_ids: Vec<String>,
}

// Called only for a new opening, on the incident transaction's connection.
pub(crate) fn enqueue(db: &Connection, incident: &Incident) -> Result<()> {
    let enabled: bool = db
        .query_row(
            "SELECT enabled FROM notification_control WHERE id=1",
            [],
            |r| r.get(0),
        )
        .map_err(err)?;
    if !enabled {
        return Ok(());
    }
    let count: i64 = db
        .query_row("SELECT count(*) FROM notification_events", [], |r| r.get(0))
        .map_err(err)?;
    if count >= CAP {
        db.execute("DELETE FROM notification_events WHERE id IN (SELECT id FROM notification_events WHERE state NOT IN ('pending','batched') ORDER BY at LIMIT 1000)",[]).map_err(err)?;
        let count: i64 = db
            .query_row("SELECT count(*) FROM notification_events", [], |r| r.get(0))
            .map_err(err)?;
        if count >= CAP {
            db.execute("UPDATE notification_control SET overflow=overflow+1,overflow_at=CASE WHEN overflow=0 THEN ?1 ELSE overflow_at END WHERE id=1",[incident.updated_at]).map_err(err)?;
            activity::info("app", "notification_overflow", None);
            WAKE.notify_one();
            return Ok(());
        }
    }
    let name: Option<String> = db
        .query_row(
            "SELECT json_extract(payload,'$.name') FROM servers WHERE id=?1",
            [&incident.server_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(err)?;
    let event = Event {
        incident_id: incident.id.clone(),
        episode: incident.episode.clone(),
        server_id: incident.server_id.clone(),
        server_name: text(name.as_deref().unwrap_or("The server is remote"), 128),
        title: text(&incident.title, 160),
        severity: incident.severity.clone(),
    };
    db.execute(
        "INSERT OR IGNORE INTO notification_events VALUES(?1,?2,?3,?4,?5,'pending',NULL,?6)",
        params![
            crate::inventory::stable_id(&incident.id, &incident.episode),
            incident.id,
            incident.episode,
            incident.server_id,
            incident.updated_at,
            serde_json::to_string(&event).map_err(err)?
        ],
    )
    .map_err(err)?;
    WAKE.notify_one();
    Ok(())
}
impl Store {
    pub(crate) fn notification_settings(&self) -> Result<Status> {
        let db = self.0.lock().map_err(err)?;
        let (enabled, error, overflow) = db
            .query_row(
                "SELECT enabled,error,overflow FROM notification_control WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(err)?;
        let queued = db
            .query_row(
                "SELECT count(*) FROM notification_events WHERE state IN ('pending','batched')",
                [],
                |r| r.get(0),
            )
            .map_err(err)?;
        Ok(Status {
            enabled,
            permission: "unknown".into(),
            error,
            queued,
            overflow,
        })
    }
    pub(crate) fn configure_notifications(&self, enabled: bool) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        tx.execute(
            "UPDATE notification_control SET enabled=?1,error=NULL,overflow=0 WHERE id=1",
            [enabled],
        )
        .map_err(err)?;
        if !enabled {
            tx.execute("UPDATE notification_events SET state='suppressed' WHERE state IN ('pending','batched')",[]).map_err(err)?;
            tx.execute(
                "UPDATE notification_batches SET state='suppressed' WHERE state='pending'",
                [],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)?;
        WAKE.notify_one();
        Ok(())
    }
    fn notification_ask_once(&self) -> Result<bool> {
        let db = self.0.lock().map_err(err)?;
        Ok(db
            .execute(
                "UPDATE notification_control SET asked=1 WHERE id=1 AND asked=0 AND enabled=1",
                [],
            )
            .map_err(err)?
            == 1)
    }
    fn recover_notifications(&self) -> Result<()> {
        let db = self.0.lock().map_err(err)?;
        // An interrupted OS handoff has an unknown result. Never blindly replay it.
        db.execute("UPDATE notification_events SET state='interrupted' WHERE batch_id IN (SELECT id FROM notification_batches WHERE state='sending')",[]).map_err(err)?;
        db.execute(
            "UPDATE notification_batches SET state='interrupted' WHERE state='sending'",
            [],
        )
        .map_err(err)?;
        Ok(())
    }
    fn next_notification(&self, at: i64) -> Result<(Option<Batch>, Option<i64>)> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        tx.execute(
            "DELETE FROM notification_events WHERE at<?1",
            [at - 7 * 86400],
        )
        .map_err(err)?;
        tx.execute("DELETE FROM notification_batches WHERE at<?1 OR id IN (SELECT id FROM notification_batches WHERE state NOT IN ('pending','sending') ORDER BY at DESC LIMIT -1 OFFSET 2000)",[at-7*86400]).map_err(err)?;
        let enabled: bool = tx
            .query_row(
                "SELECT enabled FROM notification_control WHERE id=1",
                [],
                |r| r.get(0),
            )
            .map_err(err)?;
        if !enabled {
            tx.commit().map_err(err)?;
            return Ok((None, None));
        }
        rebuild_unsent(&tx)?;
        let first: Option<i64> = tx
            .query_row(
                "SELECT min(at) FROM notification_events WHERE state='pending'",
                [],
                |r| r.get(0),
            )
            .map_err(err)?;
        let mut deadline = first.map(|t| t + WINDOW);
        if let Some(first) = first.filter(|t| t + WINDOW <= at) {
            let events = {
                let mut q=tx.prepare("SELECT payload FROM notification_events WHERE state='pending' AND at<=?1 ORDER BY at,id LIMIT 10000").map_err(err)?;
                let rows = q
                    .query_map([first + WINDOW], |r| r.get::<_, String>(0))
                    .map_err(err)?;
                rows.map(|r| serde_json::from_str::<Event>(&r.map_err(err)?).map_err(err))
                    .collect::<Result<Vec<_>>>()?
            };
            if !events.is_empty() {
                let overflow:i64=tx.query_row("SELECT CASE WHEN overflow_at<=?1 THEN overflow ELSE 0 END FROM notification_control WHERE id=1",[first+WINDOW],|r|r.get(0)).map_err(err)?;
                let worst = events
                    .iter()
                    .max_by_key(|e| if e.severity == "critical" { 2 } else { 1 })
                    .unwrap();
                let servers = events
                    .iter()
                    .map(|e| &e.server_id)
                    .collect::<BTreeSet<_>>()
                    .len();
                let title = if events.len() == 1 && overflow == 0 {
                    format!(
                        "{} · {}",
                        if worst.severity == "critical" {
                            "Critical"
                        } else {
                            "Needs attention"
                        },
                        worst.server_name
                    )
                } else {
                    format!("New incidents: {}", events.len() + overflow as usize)
                };
                let mut body = if events.len() == 1 && overflow == 0 {
                    worst.title.clone()
                } else {
                    format!(
                        "New incidents: {}; server: {}. {}: {}",
                        events.len(),
                        servers,
                        worst.server_name,
                        worst.title
                    )
                };
                if overflow > 0 {
                    body.push_str(&format!(" More {overflow} events beyond the queue limit."));
                }
                let batch = Batch {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: text(&title, 240),
                    body: text(&body, 512),
                    count: events.len(),
                    servers,
                    overflow,
                };
                tx.execute(
                    "INSERT INTO notification_batches VALUES(?1,?2,?2,'pending',0,?3)",
                    params![batch.id, at, serde_json::to_string(&batch).map_err(err)?],
                )
                .map_err(err)?;
                tx.execute("UPDATE notification_events SET state='batched',batch_id=?1 WHERE state='pending' AND at<=?2",params![batch.id,first+WINDOW]).map_err(err)?;
                if overflow > 0 {
                    tx.execute("UPDATE notification_control SET overflow=0 WHERE id=1", [])
                        .map_err(err)?;
                }
            }
            deadline = None;
        }
        let (overflow, overflow_at): (i64, i64) = tx
            .query_row(
                "SELECT overflow,overflow_at FROM notification_control WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(err)?;
        if overflow > 0 {
            if overflow_at + WINDOW <= at {
                let batch=Batch{id:uuid::Uuid::new_v4().to_string(),title:format!("New incidents: {overflow}"),body:format!("{overflow} events beyond the queue limit. Details in the section “Incidents”."),count:0,servers:0,overflow};
                tx.execute(
                    "INSERT INTO notification_batches VALUES(?1,?2,?2,'pending',0,?3)",
                    params![batch.id, at, serde_json::to_string(&batch).map_err(err)?],
                )
                .map_err(err)?;
                tx.execute("UPDATE notification_control SET overflow=0 WHERE id=1", [])
                    .map_err(err)?;
            } else {
                deadline =
                    Some(deadline.map_or(overflow_at + WINDOW, |d| d.min(overflow_at + WINDOW)));
            }
        }
        let due:Option<(String,i64,String)>=tx.query_row("SELECT id,next_at,payload FROM notification_batches WHERE state='pending' ORDER BY next_at,at LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(err)?;
        let batch = if let Some((id, time, payload)) = due {
            if time <= at {
                tx.execute("UPDATE notification_batches SET state='sending',attempts=attempts+1 WHERE id=?1",[id]).map_err(err)?;
                Some(serde_json::from_str(&payload).map_err(err)?)
            } else {
                deadline = Some(deadline.map_or(time, |d| d.min(time)));
                None
            }
        } else {
            None
        };
        tx.commit().map_err(err)?;
        Ok((batch, deadline))
    }
    fn finish_notification(
        &self,
        id: &str,
        result: Result<()>,
        at: i64,
        suppressed: bool,
    ) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let attempts: i64 = tx
            .query_row(
                "SELECT attempts FROM notification_batches WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .map_err(err)?;
        let state = if suppressed {
            "suppressed"
        } else if result.is_ok() {
            "submitted"
        } else if attempts < 3 {
            "pending"
        } else {
            "failed"
        };
        tx.execute(
            "UPDATE notification_batches SET state=?2,next_at=?3 WHERE id=?1",
            params![id, state, at + attempts * 5],
        )
        .map_err(err)?;
        if state != "pending" {
            tx.execute(
                "UPDATE notification_events SET state=?2 WHERE batch_id=?1 AND state='batched'",
                params![id, state],
            )
            .map_err(err)?;
        }
        tx.execute(
            "UPDATE notification_control SET error=?1 WHERE id=1",
            [result.err().map(|s| text(&s, 240))],
        )
        .map_err(err)?;
        tx.commit().map_err(err)
    }
    pub(crate) fn notification_target(&self, id: &str) -> Result<Target> {
        if let Some(id) = id.strip_prefix("action:") {
            return Ok(Target {
                open: true,
                open_actions: true,
                action_request_id: uuid::Uuid::parse_str(id)
                    .ok()
                    .and_then(|_| self.action_request(id).ok())
                    .map(|r| r.id),
                ..Default::default()
            });
        }
        if uuid::Uuid::parse_str(id).is_err() {
            return Ok(Target {
                open: true,
                ..Default::default()
            });
        }
        let db = self.0.lock().map_err(err)?;
        let mut q=db.prepare("SELECT DISTINCT i.id FROM notification_events e JOIN incidents i ON i.id=e.incident_id WHERE e.batch_id=?1 AND json_extract(i.payload,'$.episode')=e.episode LIMIT 10000").map_err(err)?;
        let ids = q
            .query_map([id], |r| r.get(0))
            .map_err(err)?
            .collect::<std::result::Result<Vec<String>, _>>()
            .map_err(err)?;
        Ok(Target {
            open: true,
            incident_ids: ids,
            ..Default::default()
        })
    }
}
fn rebuild_unsent(db: &Connection) -> Result<()> {
    let (overflow,at):(i64,Option<i64>)=db.query_row("SELECT coalesce(sum(json_extract(payload,'$.overflow')),0),min(at) FROM notification_batches WHERE state='pending' AND id IN (SELECT batch_id FROM notification_events WHERE state='suppressed')",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(err)?;
    if overflow > 0 {
        db.execute("UPDATE notification_control SET overflow=overflow+?1,overflow_at=CASE WHEN overflow=0 THEN ?2 ELSE min(overflow_at,?2) END WHERE id=1",params![overflow,at]).map_err(err)?;
    }
    db.execute("UPDATE notification_batches SET state='suppressed' WHERE state='pending' AND id IN (SELECT batch_id FROM notification_events WHERE state='suppressed')",[]).map_err(err)?;
    db.execute("UPDATE notification_events SET state='pending',batch_id=NULL WHERE state='batched' AND batch_id IN (SELECT id FROM notification_batches WHERE state='suppressed')",[]).map_err(err)?;
    Ok(())
}
pub(crate) fn suppress_incident(db: &Connection, id: &str, episode: &str) -> Result<()> {
    // OS handoffs already in progress cannot be recalled; failed handoffs are rebuilt before retry.
    db.execute("UPDATE notification_events SET state='suppressed' WHERE incident_id=?1 AND episode=?2 AND state IN ('pending','batched')",params![id,episode]).map_err(err)?;
    rebuild_unsent(db)?;
    WAKE.notify_one();
    Ok(())
}
pub(crate) async fn status(store: &Store) -> Result<Status> {
    let mut s = store.notification_settings()?;
    s.permission = native::permission()
        .await
        .unwrap_or_else(|_| "unavailable".into());
    Ok(s)
}
pub(crate) async fn configure(store: &Store, enabled: bool) -> Result<Status> {
    store.configure_notifications(enabled)?;
    if enabled
        && native::permission().await.ok().as_deref() == Some("notDetermined")
        && store.notification_ask_once()?
    {
        native::request().await?;
    }
    status(store).await
}
pub(crate) async fn request_permission(store: &Store) -> Result<Status> {
    if !store.notification_settings()?.enabled {
        return Err("Notifications off".into());
    }
    let mut span = activity::begin("app", "notification_permission", None);
    let result = async {
        let _ = store.notification_ask_once()?;
        native::request().await?;
        status(store).await
    }
    .await;
    span.result(&result);
    result
}
pub(crate) fn open_settings() -> Result<()> {
    native::open_settings()
}
pub(crate) async fn test(store: &Store) -> Result<()> {
    if !store.notification_settings()?.enabled {
        return Err("Notifications off".into());
    }
    if native::permission().await? == "notDetermined" {
        let _ = store.notification_ask_once()?;
        native::request().await?;
    }
    if !matches!(
        native::permission().await?.as_str(),
        "authorized" | "provisional"
    ) {
        return Err("Allow Cyberbot notifications in macOS settings".into());
    }
    let mut span = activity::begin("app", "notification_test", None);
    let result = native::show(
        &uuid::Uuid::new_v4().to_string(),
        "Cyberbot",
        "New Incident Notifications Work.",
    )
    .await;
    span.result(&result);
    if result.is_ok() {
        store
            .0
            .lock()
            .map_err(err)?
            .execute("UPDATE notification_control SET error=NULL WHERE id=1", [])
            .map_err(err)?;
    }
    result
}
pub(crate) async fn action_approval(
    store: &Store,
    request: &crate::ai_actions::Request,
) -> Result<()> {
    if !store.notification_settings()?.enabled
        || !matches!(
            native::permission().await?.as_str(),
            "authorized" | "provisional"
        )
    {
        return Ok(());
    }
    if !store.mark_action_notified(&request.id)? {
        return Ok(());
    }
    let mut span = activity::begin_run(
        "app",
        "action_approval_notification",
        Some(request.server_id.clone()),
        Some(request.run_id.clone()),
    );
    let body = format!(
        "{} · open Cyberbot to check the action and make a decision.",
        text(&request.server_label, 140)
    );
    let mut result = Ok(());
    for attempt in 0..3 {
        result = native::show(
            &format!("action:{}", request.id),
            "AI asks for permission",
            &body,
        )
        .await;
        if result.is_ok() {
            break;
        }
        if attempt < 2 {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    span.result(&result);
    result
}
pub(crate) fn activate(app: &tauri::AppHandle, id: &str) {
    if let Some(request_id) = id.strip_prefix("action:") {
        let app = app.clone();
        let request_id = request_id.to_owned();
        tauri::async_runtime::spawn(async move {
            if crate::ai_actions::open_approval(&app, &request_id).is_err() {
                activate_main(&app, &format!("action:{request_id}"));
            }
        });
        return;
    }
    activate_main(app, id);
}
fn activate_main(app: &tauri::AppHandle, id: &str) {
    if let Ok(mut target) = TARGET.lock() {
        *target = Some(id.to_string());
    }
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
    let _ = app.emit_to("main", "notification-open", ());
}
pub(crate) fn take_target(store: &Store) -> Result<Target> {
    let id = TARGET.lock().map_err(err)?.take();
    id.map_or(Ok(Target::default()), |id| store.notification_target(&id))
}
pub(crate) fn start(app: tauri::AppHandle, state: Arc<AppState>) {
    if let Err(e) = native::install(app) {
        activity::info("app", "notification_unavailable", None);
        let _ = e;
        return;
    }
    tauri::async_runtime::spawn(async move {
        let _ = state.store.recover_notifications();
        loop {
            if state.stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let next = state.store.next_notification(now());
            let wait = match next {
                Ok((Some(batch), _)) => {
                    let mut span =
                        activity::begin("app", "notification_send", Some(batch.id.clone()));
                    let permission = native::permission().await;
                    let enabled = state.store.notification_settings().is_ok_and(|s| s.enabled);
                    let suppressed = !enabled
                        || permission
                            .as_ref()
                            .is_ok_and(|s| !matches!(s.as_str(), "authorized" | "provisional"));
                    let result = match permission {
                        Ok(_) if suppressed => {
                            Err("Notifications turned off or not allowed by macOS".into())
                        }
                        Ok(_) => native::show(&batch.id, &batch.title, &batch.body).await,
                        Err(e) => Err(e),
                    };
                    span.result(&result);
                    let _ = state
                        .store
                        .finish_notification(&batch.id, result, now(), suppressed);
                    continue;
                }
                Ok((None, Some(at))) => Duration::from_secs((at - now()).max(1) as u64),
                Ok((None, None)) => Duration::from_secs(3600),
                Err(_) => {
                    activity::info("app", "notification_queue_error", None);
                    Duration::from_secs(60)
                }
            };
            tokio::select! {_=WAKE.notified()=>(),_=tokio::time::sleep(wait)=>()}
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Store, String) {
        let db = Store::open(std::path::Path::new(":memory:")).unwrap();
        let source = crate::model::Source {
            id: "fixture".into(),
            name: "fixture".into(),
            kind: "manual".into(),
            location: "ops@node".into(),
            last_sync: None,
            error: None,
        };
        db.import(&source, crate::inventory::parse_manual("ops@node").unwrap())
            .unwrap();
        let id = db.snapshot().unwrap().servers[0].id.clone();
        (db, id)
    }
    fn event(db: &Store, id: &str, check: &str, bad: bool, at: i64) {
        let mut sql = db.0.lock().unwrap();
        let tx = sql.transaction().unwrap();
        Store::incident(
            &tx,
            id,
            check,
            bad.then(|| "password=never-in-notification".into()),
            "Problem",
            "critical",
            at,
        )
        .unwrap();
        tx.commit().unwrap();
    }
    fn count(db: &Store) -> i64 {
        db.0.lock()
            .unwrap()
            .query_row("SELECT count(*) FROM notification_events", [], |r| r.get(0))
            .unwrap()
    }
    #[test]
    fn manual_resolution_rebuilds_a_failed_batch_without_losing_other_events() {
        let (db, id) = fixture();
        event(&db, &id, "cpu", true, 100);
        event(&db, &id, "memory", true, 101);
        let batch = db.next_notification(105).unwrap().0.unwrap();
        let cpu = db
            .snapshot()
            .unwrap()
            .incidents
            .into_iter()
            .find(|i| i.check == "cpu")
            .unwrap();
        db.resolve_incident(&cpu.id, &cpu.episode, 106).unwrap();
        db.finish_notification(
            &batch.id,
            Err("OS temporarily unavailable".into()),
            106,
            false,
        )
        .unwrap();
        let rebuilt = db.next_notification(107).unwrap().0.unwrap();
        assert_eq!(rebuilt.count, 1);
        assert_ne!(rebuilt.id, batch.id);
        let target = db.notification_target(&rebuilt.id).unwrap();
        assert_eq!(target.incident_ids.len(), 1);
        assert_ne!(target.incident_ids[0], cpu.id);
        db.finish_notification(&rebuilt.id, Ok(()), 107, false)
            .unwrap();
        assert!(db.next_notification(120).unwrap().0.is_none());
    }
    #[test]
    fn episode_dedup_recovery_and_atomic_rollback() {
        let (db, id) = fixture();
        {
            let mut sql = db.0.lock().unwrap();
            let tx = sql.transaction().unwrap();
            Store::incident(
                &tx,
                &id,
                "cpu",
                Some("secret".into()),
                "CPU",
                "warning",
                100,
            )
            .unwrap();
        }
        assert_eq!(count(&db), 0);
        assert!(db.snapshot().unwrap().incidents.is_empty());
        for at in 100..110 {
            event(&db, &id, "cpu", true, at);
        }
        assert_eq!(count(&db), 1);
        event(&db, &id, "cpu", false, 111);
        event(&db, &id, "cpu", true, 112);
        assert_eq!(count(&db), 1);
        event(&db, &id, "cpu", false, 113);
        event(&db, &id, "cpu", false, 114);
        event(&db, &id, "cpu", true, 115);
        assert_eq!(count(&db), 2);
        let first = db.next_notification(105).unwrap().0.unwrap();
        assert_eq!(first.count, 1);
        assert!(!first.body.contains("password"));
        assert_eq!(
            db.notification_target(&first.id)
                .unwrap()
                .incident_ids
                .len(),
            0,
            "old episode must not point to a reopened incident"
        );
    }
    #[test]
    fn fixed_window_summary_and_three_attempt_limit() {
        let (db, id) = fixture();
        event(&db, &id, "cpu", true, 100);
        event(&db, &id, "memory", true, 103);
        event(&db, &id, "disk", true, 106);
        assert!(db.next_notification(104).unwrap().0.is_none());
        let batch = db.next_notification(105).unwrap().0.unwrap();
        assert_eq!(batch.count, 2);
        assert_eq!(batch.servers, 1);
        assert_eq!(
            db.notification_target(&batch.id)
                .unwrap()
                .incident_ids
                .len(),
            2
        );
        db.finish_notification(&batch.id, Err("OS failure".into()), 105, false)
            .unwrap();
        let second = db.next_notification(110).unwrap().0.unwrap();
        assert_eq!(second.id, batch.id);
        db.finish_notification(&batch.id, Err("OS failure".into()), 110, false)
            .unwrap();
        let later = db.next_notification(111).unwrap().0.unwrap();
        assert_eq!(later.count, 1);
        db.finish_notification(&later.id, Ok(()), 111, false)
            .unwrap();
        let third = db.next_notification(120).unwrap().0.unwrap();
        assert_eq!(third.id, batch.id);
        db.finish_notification(&batch.id, Err("OS failure".into()), 120, false)
            .unwrap();
        assert!(db.next_notification(1000).unwrap().0.is_none());
    }
    #[test]
    fn toggle_denial_and_restart_do_not_replay_old_incidents() {
        let (db, id) = fixture();
        db.configure_notifications(false).unwrap();
        event(&db, &id, "cpu", true, 100);
        assert_eq!(count(&db), 0);
        db.configure_notifications(true).unwrap();
        event(&db, &id, "cpu", true, 101);
        assert_eq!(count(&db), 0);
        event(&db, &id, "disk", true, 102);
        let batch = db.next_notification(107).unwrap().0.unwrap();
        db.recover_notifications().unwrap();
        assert!(db.next_notification(108).unwrap().0.is_none());
        assert!(db.notification_target(&batch.id).unwrap().open);
        event(&db, &id, "memory", true, 110);
        let batch = db.next_notification(115).unwrap().0.unwrap();
        db.finish_notification(&batch.id, Err("denied".into()), 115, true)
            .unwrap();
        assert!(db.next_notification(116).unwrap().0.is_none());
        event(&db, &id, "logs:oom", true, 120);
        db.configure_notifications(false).unwrap();
        db.configure_notifications(true).unwrap();
        assert!(db.next_notification(200).unwrap().0.is_none());
        assert_eq!(
            db.notification_target("../../anything")
                .unwrap()
                .incident_ids
                .len(),
            0
        );
    }
    #[test]
    fn capacity_overflow_is_reported_and_retention_is_bounded() {
        let (db, id) = fixture();
        let payload = serde_json::to_string(&Event {
            incident_id: "id".into(),
            episode: "e".into(),
            server_id: id.clone(),
            server_name: "node".into(),
            title: "CPU".into(),
            severity: "warning".into(),
        })
        .unwrap();
        db.0.lock().unwrap().execute("WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<10000) INSERT INTO notification_events SELECT printf('%05d',n),'id','e',?1,100,'pending',NULL,?2 FROM seq",params![id,payload]).unwrap();
        event(&db, &id, "overflow", true, 110);
        assert_eq!(count(&db), CAP);
        assert_eq!(db.notification_settings().unwrap().overflow, 1);
        let batch = db.next_notification(111).unwrap().0.unwrap();
        assert_eq!(batch.count, 10000);
        db.finish_notification(&batch.id, Ok(()), 111, false)
            .unwrap();
        let overflow = db.next_notification(115).unwrap().0.unwrap();
        assert_eq!(overflow.overflow, 1);
        db.finish_notification(&overflow.id, Ok(()), 115, false)
            .unwrap();
        db.configure_notifications(false).unwrap();
        db.next_notification(8 * 86400).unwrap();
        assert_eq!(count(&db), 0);
    }
    #[test]
    fn migration_does_not_enqueue_existing_incidents() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("state.sqlite");
        let db = Store::open(&file).unwrap();
        let source = crate::model::Source {
            id: "migration".into(),
            name: "migration".into(),
            kind: "manual".into(),
            location: "ops@old".into(),
            last_sync: None,
            error: None,
        };
        db.import(
            &source,
            crate::inventory::parse_manual(&source.location).unwrap(),
        )
        .unwrap();
        let id = db.snapshot().unwrap().servers[0].id.clone();
        event(&db, &id, "cpu", true, 100);
        db.0.lock().unwrap().execute_batch("DROP TABLE notification_events; DROP TABLE notification_batches; DROP TABLE notification_control; PRAGMA user_version=12;").unwrap();
        drop(db);
        let db = Store::open(&file).unwrap();
        assert_eq!(count(&db), 0);
        assert_eq!(db.snapshot().unwrap().incidents.len(), 1);
        event(&db, &id, "cpu", true, 101);
        assert_eq!(count(&db), 0);
        assert!(db.notification_settings().unwrap().enabled);
        assert!(db.notification_ask_once().unwrap());
        assert!(!db.notification_ask_once().unwrap());
    }
}

/// Explicit acceptance fixture: empty data directory, paused monitoring, fictional endpoints only.
pub(crate) fn seed_smoke(state: Arc<AppState>, app: tauri::AppHandle) -> Result<()> {
    let mut settings = state.store.settings()?;
    settings.paused = true;
    settings.mode = "manual".into();
    state.store.save_settings(&settings)?;
    let source = crate::model::Source {
        id: "notification-fixture".into(),
        name: "Notification fixture".into(),
        kind: "manual".into(),
        location: "fixture@notification.invalid".into(),
        last_sync: None,
        error: None,
    };
    state
        .store
        .import(&source, crate::inventory::parse_manual(&source.location)?)?;
    tauri::async_runtime::spawn(async move {
        for _ in 0..60 {
            if matches!(
                native::permission().await.ok().as_deref(),
                Some("authorized" | "provisional")
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let emit = |check: &str, title: &str| -> Result<()> {
            let mut db = state.store.0.lock().map_err(err)?;
            let tx = db.transaction().map_err(err)?;
            let id: String = tx
                .query_row("SELECT id FROM servers LIMIT 1", [], |r| r.get(0))
                .map_err(err)?;
            Store::incident(
                &tx,
                &id,
                check,
                Some("synthetic".into()),
                title,
                "critical",
                now(),
            )?;
            tx.commit().map_err(err)
        };
        let _ = emit(
            "fixture:foreground",
            "Verification of notifications: plug-in",
        );
        let _ = app.emit("state-changed", ());
        tokio::time::sleep(Duration::from_secs(9)).await;
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.hide();
        }
        let _ = emit(
            "fixture:hidden",
            "Verification of notifications: hidden-window",
        );
        let _ = emit("fixture:batch", "Verification of incident reports");
        tokio::time::sleep(Duration::from_secs(9)).await;
        let approval = match crate::ai_actions::approval_fixture(&state) {
            Ok(request) => {
                let submitted = action_approval(&state.store, &request).await.is_ok();
                let opened = crate::ai_actions::open_approval(&app, &request.id).is_ok();
                let _ = app.emit("state-changed", ());
                serde_json::json!({"id":request.id,"submitted":submitted,"windowOpened":opened,"state":request.state})
            }
            Err(error) => serde_json::json!({"error":error}),
        };
        let report = (|| -> Result<serde_json::Value> {
            let db = state.store.0.lock().map_err(err)?;
            let mut q = db
                .prepare("SELECT state,attempts,payload FROM notification_batches ORDER BY at")
                .map_err(err)?;
            let rows=q.query_map([],|r|Ok(serde_json::json!({"state":r.get::<_,String>(0)?,"attempts":r.get::<_,i64>(1)?,"batch":serde_json::from_str::<serde_json::Value>(&r.get::<_,String>(2)?).unwrap_or_default()}))).map_err(err)?.collect::<std::result::Result<Vec<_>,_>>().map_err(err)?;
            Ok(
                serde_json::json!({"batches":rows,"approval":approval,"paused":true,"realInfrastructure":false}),
            )
        })();
        if let Ok(report) = report {
            let _ = std::fs::write(
                state.root.join("notification-smoke.json"),
                report.to_string(),
            );
        }
    });
    Ok(())
}
