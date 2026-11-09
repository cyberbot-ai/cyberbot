use super::*;

impl Store {
    pub(crate) fn review_charged(&self, parent: &str) -> Result<u64> {
        let db = self.0.lock().map_err(err)?;
        review_charged(&db, parent)
    }
    pub(crate) fn admit_review(&self, request: &Request, at: i64) -> Result<(String, u64)> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(err)?;
        let current = read(&tx, &request.id)?;
        let run = context(&tx, &current, at)?;
        if current.state != "reviewing" || current.artifact_hash != request.artifact_hash {
            return Err("Review cancelled or artifact changed".into());
        }
        let active:i64=tx.query_row("SELECT count(*) FROM ai_children c JOIN ai_ledger l ON l.id=c.id WHERE l.state='running'",[],|r|r.get(0)).map_err(err)?;
        if active > 0 {
            return Err("A risk review is already in progress".into());
        }
        let (reserved, day, state): (u64, i64, String) = tx
            .query_row(
                "SELECT reserved,day,state FROM ai_ledger WHERE id=?1",
                [&run.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(err)?;
        if state != "running" {
            return Err("The AI run has ended".into());
        }
        let settings = Self::read_settings(&tx)?;
        let (runs, charged): (u64, u64) = tx
            .query_row(
                "SELECT count(*),CAST(total(charged) AS INTEGER) FROM ai_ledger WHERE day=?1",
                [day],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(err)?;
        let wanted = (serde_json::to_vec(&request.artifact).map_err(err)?.len() as u64 / 2 + 12288)
            .clamp(12288, 32000);
        let additional = if reserved == 0 { wanted } else { 0 };
        if settings
            .daily_runs_cap()
            .is_some_and(|n| runs >= u64::from(n))
            || settings
                .daily_tokens_cap()
                .is_some_and(|n| charged.saturating_add(additional) > n)
        {
            return Err("The daily budget does not cover another risk review".into());
        }
        let used = review_charged(&tx, &run.id)?;
        if reserved != 0 {
            let main = crate::automation::tokens(&run.agent, &run.usage).unwrap_or(0);
            let available = reserved.saturating_sub(used).saturating_sub(main);
            if available < wanted {
                return Err("This run has too few tokens left for risk review".into());
            }
            tx.execute(
                "UPDATE ai_ledger SET charged=?2 WHERE id=?1",
                params![run.id, reserved.saturating_sub(used).saturating_sub(wanted)],
            )
            .map_err(err)?;
        }
        let id = uuid::Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO ai_ledger VALUES(?1,?2,?3,NULL,?3,'running')",
            params![id, day, wanted],
        )
        .map_err(err)?;
        tx.execute(
            "INSERT INTO ai_children VALUES(?1,?2,?3)",
            params![id, run.id, request.id],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok((id, wanted))
    }
    pub(crate) fn settle_review(&self, id: &str, usage: Value, complete: bool) -> Result<u64> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(err)?;
        let (parent,request_id,reserved,state):(String,String,u64,String)=tx.query_row("SELECT c.parent_id,c.request_id,l.reserved,l.state FROM ai_children c JOIN ai_ledger l ON l.id=c.id WHERE c.id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(err)?;
        if state != "running" {
            let charged = tx
                .query_row("SELECT charged FROM ai_ledger WHERE id=?1", [id], |r| {
                    r.get(0)
                })
                .map_err(err)?;
            return Ok(charged);
        }
        let r = read(&tx, &request_id)?;
        let actual = crate::automation::tokens(&r.artifact.provider, &usage);
        let exact = complete && actual.is_some();
        let charged = if exact {
            actual.unwrap_or(0)
        } else {
            reserved.max(actual.unwrap_or(0))
        };
        if state == "running" {
            tx.execute(
                "UPDATE ai_ledger SET actual=?2,charged=?3,state=?4 WHERE id=?1",
                params![
                    id,
                    actual,
                    charged,
                    if exact { "settled" } else { "uncertain" }
                ],
            )
            .map_err(err)?;
            let used = review_charged(&tx, &parent)?;
            tx.execute(
                "UPDATE ai_ledger SET charged=max(coalesce(actual,0),reserved-?2) WHERE id=?1 AND state='running'",
                params![parent, used],
            )
            .map_err(err)?;
            if !exact || charged >= reserved {
                tx.execute("UPDATE ai_control SET reason='Risk review token usage needs confirmation. Automatic retries are paused.' WHERE id=1",[]).map_err(err)?;
            }
        }
        tx.commit().map_err(err)?;
        Ok(charged)
    }
}
pub(crate) fn review_charged(db: &Connection, parent: &str) -> Result<u64> {
    db.query_row("SELECT coalesce(sum(l.charged),0) FROM ai_children c JOIN ai_ledger l ON l.id=c.id WHERE c.parent_id=?1",[parent],|r|r.get(0)).map_err(err)
}
