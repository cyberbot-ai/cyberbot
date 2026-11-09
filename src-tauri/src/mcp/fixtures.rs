//! Synthetic data for the opt-in CLI smoke test and local MCP tests.
use crate::{model::now, AppState};
use rusqlite::params;
use serde_json::json;

pub(crate) const CVE: &str = "CVE-2023-6879";
pub(crate) const TRACKER: &str = "https://security-tracker.debian.org/tracker/CVE-2023-6879";

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

pub(crate) fn seed_server_context(app: &AppState, id: &str, count: usize) -> Result<(), String> {
    let mut state = app.store.package_state(id)?;
    let metadata = crate::packages::Metadata {
        distro: "debian".into(),
        release: "bookworm".into(),
        version: "12".into(),
        architecture: "amd64".into(),
        kernel: "6.1".into(),
    };
    state.metadata = Some(metadata.clone());
    state.root = Some("fixture-root".into());
    state.last_success = Some(now());
    app.store.ensure_sources(&metadata)?;
    let db = app.store.0.lock().map_err(err)?;
    let tx = db.unchecked_transaction().map_err(err)?;
    tx.execute(
        "UPDATE package_state SET payload=?2 WHERE server_id=?1",
        params![id, serde_json::to_string(&state).map_err(err)?],
    )
    .map_err(err)?;
    tx.execute("UPDATE advisory_sources SET payload=json_set(payload,'$.file','/private/cache/file','$.previous','/private/cache/old')", []).map_err(err)?;
    tx.execute("INSERT INTO package_buckets VALUES(?1,'fixture-root',0,'hash',?2)",params![id,json!([
        {"name":"libaom3","arch":"amd64","version":"3.6.0-1+deb12u1","source":"aom","sourceVersion":"3.6.0-1+deb12u1","status":"installed"}
    ]).to_string()]).map_err(err)?;
    for i in 0..count {
        let incident = json!({"id":format!("inc-{i}"),"serverId":id,"check":"disk","title":"Test disk",
            "severity":"warning","status":if i == 0 {"resolved"} else {"open"},"openedAt":i,"updatedAt":i,"evidence":"Synthetic example"});
        tx.execute(
            "INSERT INTO incidents VALUES(?1,?2,?3)",
            params![format!("inc-{i}"), id, incident.to_string()],
        )
        .map_err(err)?;
        let cve = if i < 2 {
            CVE.into()
        } else {
            format!("CVE-2025-{:04}", 1000 + i)
        };
        let source = if i == 0 {
            "aom".into()
        } else {
            format!("fixture-source-{i}")
        };
        let hidden = (i == 1).then_some(now());
        let finding = json!({"source":source,"cve":cve,"state":"affected","severity":"critical","severitySource":"fixture",
            "packages":[{"name":"libaom3","version":"3.6.0-1+deb12u1","fixedVersion":null}],
            "description":"Synthetic CVE evidence","url":TRACKER,"reason":null,"fixPublished":false,"hiddenAt":hidden}).to_string();
        tx.execute(
            "INSERT INTO vulnerability_findings VALUES(?1,?2,?3,NULL,?4)",
            params![id, source, cve, finding],
        )
        .map_err(err)?;
        tx.execute("INSERT INTO vulnerability_groups(server_id,source,payload,hidden_at) VALUES(?1,?2,?3,?4)",
            params![id, source, finding, hidden]).map_err(err)?;
    }
    tx.commit().map_err(err)
}
