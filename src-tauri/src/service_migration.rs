//! SQLite compatibility for data created before the unified service store.
use rusqlite::{params, Connection, Transaction, TransactionBehavior};

type Result<T> = std::result::Result<T, String>;
fn err(error: rusqlite::Error) -> String {
    error.to_string()
}

pub(crate) fn initialize_legacy(db: &Connection, version: i64) -> Result<()> {
    let (pg_state_columns, pg_summary_columns) = if version < 10 {
        ("server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,payload TEXT NOT NULL", "")
    } else {
        ("server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,payload TEXT NOT NULL,instance_id TEXT NOT NULL DEFAULT 'default',PRIMARY KEY(server_id,instance_id)", ",instance_id TEXT NOT NULL DEFAULT 'default'")
    };
    db.execute_batch(&format!("          CREATE TABLE IF NOT EXISTS nginx_state(server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE, payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS nginx_summaries(id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE, at INTEGER NOT NULL, payload TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS nginx_summaries_server_at ON nginx_summaries(server_id,at);
          CREATE TABLE IF NOT EXISTS nginx_evidence(incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE, summary_id TEXT NOT NULL REFERENCES nginx_summaries(id) ON DELETE CASCADE, PRIMARY KEY(incident_id,summary_id));
          CREATE TABLE IF NOT EXISTS postgresql_state({pg_state_columns});
          CREATE TABLE IF NOT EXISTS postgresql_summaries(id TEXT PRIMARY KEY,server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,at INTEGER NOT NULL,payload TEXT NOT NULL{pg_summary_columns});
          CREATE INDEX IF NOT EXISTS postgresql_summaries_at ON postgresql_summaries(server_id,at);
          CREATE TABLE IF NOT EXISTS postgresql_evidence(incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,summary_id TEXT NOT NULL REFERENCES postgresql_summaries(id) ON DELETE CASCADE,PRIMARY KEY(incident_id,summary_id));
")).map_err(err)
}

pub(crate) fn upgrade_instances(db: &Connection) -> Result<()> {
    db.execute_batch("BEGIN IMMEDIATE;
             CREATE TABLE service_instances(server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,kind TEXT NOT NULL,id TEXT NOT NULL,name TEXT NOT NULL,PRIMARY KEY(server_id,kind,id));
             INSERT INTO service_instances SELECT server_id,kind,'default','Basic' FROM service_state;
             INSERT INTO service_instances SELECT server_id,'postgresql','default','Basic' FROM postgresql_state;
             CREATE TABLE service_state_v10(server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,kind TEXT NOT NULL,payload TEXT NOT NULL,instance_id TEXT NOT NULL DEFAULT 'default',PRIMARY KEY(server_id,kind,instance_id));
             INSERT INTO service_state_v10(server_id,kind,payload) SELECT server_id,kind,payload FROM service_state;
             DROP TABLE service_state; ALTER TABLE service_state_v10 RENAME TO service_state;
             CREATE TABLE postgresql_state_v10(server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,payload TEXT NOT NULL,instance_id TEXT NOT NULL DEFAULT 'default',PRIMARY KEY(server_id,instance_id));
             INSERT INTO postgresql_state_v10(server_id,payload) SELECT server_id,payload FROM postgresql_state;
             DROP TABLE postgresql_state; ALTER TABLE postgresql_state_v10 RENAME TO postgresql_state;
             ALTER TABLE service_summaries ADD COLUMN instance_id TEXT NOT NULL DEFAULT 'default';
             ALTER TABLE postgresql_summaries ADD COLUMN instance_id TEXT NOT NULL DEFAULT 'default';
             CREATE INDEX service_summaries_instance_at ON service_summaries(server_id,kind,instance_id,at);
             CREATE INDEX postgresql_summaries_instance_at ON postgresql_summaries(server_id,instance_id,at);
             PRAGMA user_version=10; COMMIT;").map_err(err)
}

pub(crate) fn legacy_profiles(
    db: &Connection,
) -> Result<Vec<(String, String, String, serde_json::Value)>> {
    let mut query = db
        .prepare(
            "SELECT server_id,kind,instance_id,payload FROM service_state
         UNION ALL SELECT server_id,'postgresql',instance_id,payload FROM postgresql_state",
        )
        .map_err(err)?;
    let rows = query
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(err)?;
    rows.map(|row| {
        let (server, kind, instance, raw) = row.map_err(err)?;
        let mut value: serde_json::Value =
            serde_json::from_str(&raw).map_err(|error| error.to_string())?;
        let config = &mut value["config"];
        if let Some(fields) = config.as_object_mut() {
            for (old, new) in [
                ("expectedStreaming", "expectedPeers"),
                ("expectReceiver", "expectReplica"),
            ] {
                if let Some(value) = fields.remove(old) {
                    fields.entry(new).or_insert(value);
                }
            }
        }
        Ok((server, kind, instance, config.take()))
    })
    .collect()
}

pub(crate) fn upgrade(db: &Connection) -> Result<()> {
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate).map_err(err)?;
    let version: u32 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(err)?;
    if version >= 18 {
        return Ok(());
    }
    // Historical rescheduling must run before moving legacy rows.
    tx.execute_batch("
        UPDATE service_state SET payload=json_set(payload,'$.nextCheck',min(json_extract(payload,'$.nextCheck'),unixepoch()+rowid%60)) WHERE NOT EXISTS(SELECT 1 FROM maintenance WHERE id=5);
        UPDATE postgresql_state SET payload=json_set(payload,'$.nextCheck',min(json_extract(payload,'$.nextCheck'),unixepoch()+rowid%60)) WHERE NOT EXISTS(SELECT 1 FROM maintenance WHERE id=5);
        INSERT OR IGNORE INTO maintenance VALUES(5,unixepoch());
        UPDATE service_state SET payload=json_set(payload,'$.nextCheck',min(json_extract(payload,'$.nextCheck'),unixepoch()+rowid%60)) WHERE kind IN ('cockroach','php-fpm') AND NOT EXISTS(SELECT 1 FROM maintenance WHERE id=6);
        UPDATE postgresql_state SET payload=json_set(payload,'$.nextCheck',min(json_extract(payload,'$.nextCheck'),unixepoch()+rowid%60)) WHERE NOT EXISTS(SELECT 1 FROM maintenance WHERE id=6);
        INSERT OR IGNORE INTO maintenance VALUES(6,unixepoch());
    ").map_err(err)?;
    for (kind, instance) in [("nginx", "'default'"), ("postgresql", "instance_id")] {
        move_rows(
            &tx,
            &format!("{kind}_state"),
            &format!(
                "INSERT INTO service_state(server_id,kind,instance_id,payload)
             SELECT server_id,?1,{instance},payload FROM {kind}_state"
            ),
            kind,
        )?;
        move_rows(
            &tx,
            &format!("{kind}_summaries"),
            &format!(
                "INSERT INTO service_summaries(id,server_id,kind,instance_id,at,payload)
             SELECT id,server_id,?1,{instance},at,payload FROM {kind}_summaries ORDER BY rowid"
            ),
            kind,
        )?;
        move_rows(
            &tx,
            &format!("{kind}_evidence"),
            &format!(
                "INSERT INTO service_evidence(incident_id,summary_id)
             SELECT incident_id,summary_id FROM {kind}_evidence WHERE ?1 IS NOT NULL"
            ),
            kind,
        )?;
        tx.execute(
            &format!(
                "INSERT OR IGNORE INTO service_instances(server_id,kind,id,name)
             SELECT server_id,?1,{instance},'' FROM {kind}_state"
            ),
            params![kind],
        )
        .map_err(err)?;
    }
    let broken: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check('service_evidence'))",
            [],
            |row| row.get(0),
        )
        .map_err(err)?;
    if broken {
        return Err("Damaged links to evidence of diagnosis".into());
    }
    tx.execute_batch("DROP TABLE nginx_evidence; DROP TABLE nginx_summaries; DROP TABLE nginx_state;
        DROP TABLE postgresql_evidence; DROP TABLE postgresql_summaries; DROP TABLE postgresql_state;")
        .map_err(err)?;
    tx.pragma_update(None, "user_version", 18).map_err(err)?;
    tx.commit().map_err(err)
}

fn move_rows(tx: &Transaction<'_>, table: &str, sql: &str, kind: &str) -> Result<()> {
    let expected: usize = tx
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .map_err(err)?;
    if tx.execute(sql, [kind]).map_err(err)? != expected {
        return Err(format!(
            "Incomplete transfer of diagnostic data from {table}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inventory, model::Source, store::Store};

    #[test]
    fn upgrade_is_atomic_and_preserves_specialized_history() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("services.sqlite");
        let store = Store::open(&path).unwrap();
        let source = Source {
            id: "fixture".into(),
            name: "Fixture".into(),
            kind: "manual".into(),
            location: "ops@fixture".into(),
            last_sync: None,
            error: None,
        };
        store
            .import(&source, inventory::parse_manual(&source.location).unwrap())
            .unwrap();
        let server = store.snapshot().unwrap().servers.remove(0);
        let db = store.0.lock().unwrap();
        initialize_legacy(&db, 17).unwrap();
        db.pragma_update(None, "user_version", 17).unwrap();
        db.execute(
            "INSERT INTO incidents VALUES('episode',?1,'{}')",
            [&server.id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO nginx_state VALUES(?1,'{\"cursor\":{\"offset\":12},\"nextCheck\":1234}')",
            [&server.id],
        )
        .unwrap();
        for instance in ["default", "123e4567-e89b-12d3-a456-426614174000"] {
            db.execute("INSERT INTO postgresql_state VALUES(?1,'{\"config\":{\"host\":\"/tmp\",\"port\":5432},\"nextCheck\":2345}',?2)", params![server.id, instance]).unwrap();
        }
        db.execute(
            "INSERT INTO nginx_summaries VALUES('web',?1,100,'{\"id\":\"web\"}')",
            [&server.id],
        )
        .unwrap();
        db.execute("INSERT INTO postgresql_summaries VALUES('database',?1,200,'{\"id\":\"database\"}','default')", [&server.id]).unwrap();
        db.execute_batch(
            "
            INSERT INTO nginx_evidence VALUES('episode','web');
            INSERT INTO postgresql_evidence VALUES('episode','database');
            CREATE TRIGGER fail_migration BEFORE INSERT ON service_state
                WHEN NEW.kind='postgresql' BEGIN SELECT RAISE(ABORT,'fixture'); END;
        ",
        )
        .unwrap();
        assert!(upgrade(&db).is_err());
        assert_eq!(
            db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            17
        );
        assert_eq!(count(&db, "nginx_state"), 1);
        assert_eq!(count(&db, "service_state"), 0);
        assert_eq!(count(&db, "service_summaries"), 0);
        db.execute_batch("DROP TRIGGER fail_migration").unwrap();
        drop(db);
        drop(store);
        for _ in 0..2 {
            let reopened = Store::open(&path).unwrap();
            let db = reopened.0.lock().unwrap();
            assert_eq!(
                db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                    .unwrap(),
                18
            );
            assert_eq!(count(&db, "service_state"), 3);
            assert_eq!(count(&db, "service_summaries"), 2);
            assert_eq!(count(&db, "service_evidence"), 2);
            assert_eq!(count(&db, "service_instances"), 3);
            assert_eq!(db.query_row(
                "SELECT json_extract(payload,'$.cursor.offset') FROM service_state WHERE kind='nginx'",
                [], |row| row.get::<_, i64>(0)
            ).unwrap(), 12);
            assert!(db.prepare("SELECT 1 FROM nginx_state").is_err());
        }
    }

    fn count(db: &Connection, table: &str) -> i64 {
        db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    }
}
