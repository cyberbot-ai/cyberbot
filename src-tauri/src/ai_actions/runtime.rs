//! Executes one approved artifact; waiting never owns a remote admission slot.
use super::*;
use crate::{mcp::Scope, AppState};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
#[derive(Default)]
pub struct Runtime {
    pub reviewer: tokio::sync::Mutex<()>,
    sent: std::sync::atomic::AtomicU64,
    received: std::sync::atomic::AtomicU64,
    tasks: Mutex<HashMap<String, (String, CancellationToken)>>,
}
impl Runtime {
    pub fn traffic(&self) -> Value {
        json!({"sent":self.sent.load(std::sync::atomic::Ordering::Relaxed),"received":self.received.load(std::sync::atomic::Ordering::Relaxed)})
    }
    pub fn cancel(&self, id: &str) {
        if let Ok(tasks) = self.tasks.lock() {
            if let Some((_, token)) = tasks.get(id) {
                token.cancel();
            }
        }
    }
    pub fn cancel_run(&self, run: &str) {
        if let Ok(tasks) = self.tasks.lock() {
            for (parent, token) in tasks.values() {
                if parent == run {
                    token.cancel();
                }
            }
        }
    }
    pub fn cancel_all(&self) {
        if let Ok(tasks) = self.tasks.lock() {
            for (owner, token) in tasks.values() {
                if !owner.starts_with("user:") {
                    token.cancel();
                }
            }
        }
    }
}
#[derive(Default)]
pub struct WaitClock(Mutex<(Option<Instant>, Duration, usize)>);
impl WaitClock {
    pub fn elapsed(&self) -> Duration {
        self.0
            .lock()
            .map(|v| v.1 + v.0.map_or(Duration::ZERO, |start| start.elapsed()))
            .unwrap_or_default()
            .min(Duration::from_secs(WAIT_SECONDS as u64))
    }
    pub fn pause(&self) -> WaitGuard<'_> {
        if let Ok(mut v) = self.0.lock() {
            if v.2 == 0 {
                v.0 = Some(Instant::now());
            }
            v.2 += 1;
        }
        WaitGuard(self)
    }
}
pub struct WaitGuard<'a>(&'a WaitClock);
impl Drop for WaitGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut v) = self.0 .0.lock() {
            v.2 = v.2.saturating_sub(1);
            if v.2 == 0 {
                if let Some(start) = v.0.take() {
                    v.1 += start.elapsed();
                }
            }
        }
    }
}
struct Task {
    state: Arc<AppState>,
    id: String,
}
impl Drop for Task {
    fn drop(&mut self) {
        if let Ok(mut tasks) = self.state.actions.tasks.lock() {
            tasks.remove(&self.id);
        }
        if let Ok((_, true)) = self.state.store.interrupt_action(
            &self.id,
            "cancelled",
            "The request ended. Cyberbot will not retry it automatically.".into(),
            now(),
        ) {
            changed(&self.id);
        }
    }
}
struct ReviewLease {
    state: Arc<AppState>,
    id: String,
    settled: bool,
}
impl Drop for ReviewLease {
    fn drop(&mut self) {
        if !self.settled {
            let _ = self.state.store.settle_review(&self.id, json!({}), false);
        }
    }
}
fn output(r: &Request) -> Value {
    json!({"requestId":r.id,"artifactHash":r.artifact_hash,"state":r.state,"review":r.review.as_ref().map(|v|&v.verdict),"result":r.result,"error":r.error,"instructions":"This is the saved outcome. Never retry unknown effects. Approval is owned by the desktop user, not the model."})
}
fn inputs(state: &AppState, spec: &Spec) -> Result<Value> {
    let snapshot = state.store.snapshot()?;
    let server = snapshot
        .servers
        .iter()
        .find(|s| s.id == spec.server_id)
        .ok_or("The server is remote")?;
    let mut result = Vec::new();
    for input in &spec.inputs {
        let mut value = match input {
            Input::Metrics => {
                json!({"observation":server.observation,"lastError":server.last_error,"collectedAt":snapshot.collected_at})
            }
            Input::Logs => {
                serde_json::to_value(state.store.log_view(&spec.server_id)?).map_err(err)?
            }
            input => {
                let (kind, instance) = input.service_target().ok_or("Unknown source")?;
                crate::services::snapshot_for(&state.store, &spec.server_id, kind, instance)?
            }
        };
        if let Some(map) = value.as_object_mut() {
            map.remove("config");
        }
        result.push(json!({"source":input,"data":value}));
    }
    Ok(Value::Array(result))
}
async fn remote(
    state: Arc<AppState>,
    request: &Request,
    operation: &str,
    cancel: &CancellationToken,
) -> Result<Value> {
    let endpoint: crate::model::Endpoint =
        serde_json::from_str(&request.artifact.endpoint).map_err(err)?;
    let stamp = request
        .artifact
        .transport
        .as_ref()
        .ok_or("SSH context is not saved")?;
    let current = crate::ssh_authorization::capture(&endpoint).await?;
    if current.digest() != stamp.digest() {
        return Err("SSH settings or jump hosts changed after preparation".into());
    }
    let deadline = Instant::now();
    let guard = loop {
        if cancel.is_cancelled() {
            return Err("Request cancelled".into());
        }
        if deadline.elapsed() > Duration::from_secs(20) {
            return Err("SSH queue is busy".into());
        }
        let snapshot = state.store.snapshot()?;
        let server = snapshot
            .servers
            .iter()
            .find(|s| s.id == request.server_id)
            .ok_or("The server is remote")?;
        if serde_json::to_string(&server.endpoint).map_err(err)? != request.artifact.endpoint {
            return Err("Connection has changed".into());
        }
        if let Some(guard) = state
            .collectors
            .try_background(&request.server_id, snapshot.settings.concurrency)?
        {
            break guard;
        }
        tokio::select! {_=cancel.cancelled()=>return Err("Request cancelled".into()),_=tokio::time::sleep(Duration::from_millis(150))=>{}}
    };
    let endpoint: crate::model::Endpoint =
        serde_json::from_str(&request.artifact.endpoint).map_err(err)?;
    let payload = if operation == "prepare" {
        json!({"operation":"prepare","action":request.artifact.spec.action})
    } else if matches!(operation, "result" | "rollback") {
        json!({"operation":operation,"requestId":request.id,"artifactHash":request.artifact_hash,"action":request.artifact.spec.action,"prepared":request.artifact.prepared})
    } else {
        json!({"operation":operation,"requestId":request.id,"artifactHash":request.artifact_hash,"code":request.artifact.spec.code,"inputs":request.artifact.inputs,"action":request.artifact.spec.action,"prepared":request.artifact.prepared})
    };
    let data = json!({"kind":"action","state":payload});
    let shell_execute =
        operation == "execute" && matches!(request.artifact.spec.action, Action::Shell);
    let shell_sent = std::sync::atomic::AtomicBool::new(false);
    if serde_json::to_vec(&data).map_err(err)?.len() > 49152 {
        return Err("The action runner request exceeds 48 KiB".into());
    }
    let future = async {
        if matches!(operation, "prepare" | "execute") {
            state.store.action_context(&request.id, now())?;
        }
        tokio::select! {
            _ = cancel.cancelled() => return Err("The request was cancelled before the collector started".into()),
            result = crate::ssh::deploy(&endpoint, &state.collector) => result?,
        };
        if matches!(operation, "prepare" | "execute") {
            state.store.action_context(&request.id, now())?;
        }
        state.actions.sent.fetch_add(
            data.to_string().len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        let raw = if shell_execute {
            crate::ssh::run_shell_action(&endpoint, &data, cancel, &shell_sent).await?
        } else {
            crate::ssh::run_collector(&endpoint, &data, 32768).await?
        };
        state
            .actions
            .received
            .fetch_add(raw.len() as u64, std::sync::atomic::Ordering::Relaxed);
        serde_json::from_slice(&raw).map_err(|_| "Invalid response from the action runner".into())
    };
    let guarded = crate::ssh_authorization::guarded(stamp.clone(), future);
    let result = if shell_execute {
        guarded.await
    } else {
        tokio::select! {_=cancel.cancelled()=>Err("The remote action was interrupted. Its effects are unconfirmed.".into()),r=guarded=>r}
    };
    drop(guard);
    if shell_sent.load(std::sync::atomic::Ordering::Relaxed) {
        state.package_refresh_after_command(&request.server_id, &endpoint);
    }
    result
}
fn receipt(request: &Request, result: Value) -> Result<(String, Value)> {
    if result["state"] == "unknown" && result["hash"] == request.artifact_hash {
        return Ok(("unknown".into(), result));
    }
    if result["hash"] != request.artifact_hash
        || result["action"] != serde_json::to_value(&request.artifact.spec.action).map_err(err)?
        || result["prepared"] != request.artifact.prepared
    {
        return Err("The receipt does not match the approved action".into());
    }
    let state = result["state"]
        .as_str()
        .ok_or("The action receipt is missing its status")?;
    if !matches!(
        state,
        "succeeded"
            | "failed"
            | "unknown"
            | "rolledBack"
            | "rollbackUnknown"
            | "running"
            | "rollbackRunning"
    ) {
        return Err("The action receipt has an unknown status".into());
    }
    if matches!(request.artifact.spec.action, Action::Shell) {
        let code = result["result"]["exitCode"].as_i64();
        if !matches!(state, "succeeded" | "failed")
            || code.is_none()
            || (code == Some(0)) != (state == "succeeded")
        {
            return Err("The receipt does not confirm the script’s exit code".into());
        }
    } else if state == "succeeded" && result["effect"]["verified"] != true {
        return Err("The receipt does not verify the action’s effect".into());
    }
    Ok((
        if matches!(state, "running" | "rollbackRunning") {
            "unknown".into()
        } else {
            state.into()
        },
        result,
    ))
}
async fn wait(state: &AppState, id: &str, cancel: &CancellationToken) -> Result<Request> {
    loop {
        let r = state.store.action_request(id)?;
        if !active(&r.state) || r.state == "approved" {
            return Ok(r);
        }
        if r.expires_at <= now() {
            return state.store.action_result(
                id,
                "expired",
                None,
                Some("The approval request expired".into()),
                now(),
            );
        }
        if let Err(e) = state.store.action_context(id, now()) {
            return state
                .store
                .action_result(id, "cancelled", None, Some(e), now());
        }
        tokio::select! {_=cancel.cancelled()=>return state.store.action_result(id,"cancelled",None,Some("AI launch cancelled".into()),now()),_=tokio::time::sleep(Duration::from_millis(250))=>{}}
    }
}
pub(crate) async fn submit(scope: &Scope, spec: Spec) -> Result<Value> {
    if scope.cancel.is_cancelled() {
        return Err("AI launch cancelled".into());
    }
    spec.validate()?;
    let run_id = scope
        .run_id
        .as_ref()
        .ok_or("Actions are available only while an AI run is active")?;
    if scope.authoring.is_some() || !scope.targets.contains_key(&spec.server_id) {
        return Err("Action is outside this run’s scope".into());
    }
    if !scope
        .audit
        .lock()
        .map_err(err)?
        .iter()
        .any(|a| a["tool"] == "get_server" && a["serverId"] == spec.server_id && a["ok"] == true)
    {
        return Err("Call get_server for the selected server first".into());
    }
    let run = scope.app.investigator.get(run_id)?;
    let prepared_inputs = inputs(&scope.app, &spec)?;
    let frame = tokio::time::timeout(
        Duration::from_secs(45),
        scope
            .ssh_frame
            .get_or_try_init(|| crate::ssh_authorization::frame(&run.scope_endpoints)),
    )
    .await
    .map_err(|_| "Timed out while capturing SSH settings")??;
    if !frame.unchanged() {
        return Err("SSH settings changed. Start a new run.".into());
    }
    let transport = frame
        .targets
        .get(&spec.server_id)
        .ok_or("No server context")?
        .clone();
    let (mut request, new) = scope.app.store.action_propose(
        &run,
        spec,
        prepared_inputs,
        transport,
        frame.hash.clone(),
        now(),
    )?;
    changed(&request.id);
    if new {
        crate::activity::action(&request, "script_proposed");
    }
    if !new {
        let _pause = scope.wait_clock.pause();
        return wait(&scope.app, &request.id, &scope.cancel)
            .await
            .map(|r| output(&r));
    }
    let cancel = scope.cancel.child_token();
    scope
        .app
        .actions
        .tasks
        .lock()
        .map_err(err)?
        .insert(request.id.clone(), (run_id.clone(), cancel.clone()));
    let _task = Task {
        state: scope.app.clone(),
        id: request.id.clone(),
    };
    let mut span = crate::activity::begin_run(
        "ai",
        "script_request",
        Some(request.server_id.clone()),
        Some(run_id.clone()),
    );
    let outcome:Result<Value>=async{
  let prepared=remote(scope.app.clone(),&request,"prepare",&cancel).await?;
  if let Some(error)=prepared["error"].as_str(){let reason=crate::services::action_prepare_issue(error).unwrap_or_else(|| match error {"script_failed_or_isolation_unavailable"|"isolation_probe_failed"=>"Cyberbot could not verify Python isolation on the server and blocked execution",_=>"The action or secure access is unavailable on the server"});return Err(format!("{reason} ({})",error.chars().take(80).collect::<String>()));}
  if prepared["rules"]!=RULES{return Err("The action broker’s policy version does not match".into());}
  request=scope.app.store.action_freeze(&request.id,prepared["prepared"].clone(),prepared["isolation"].clone(),now())?;
  changed(&request.id);crate::activity::action(&request,"script_review_started");
  let review_lock=tokio::select!{_=cancel.cancelled()=>return Err("Review cancelled".into()),guard=scope.app.actions.reviewer.lock()=>guard};
  let (child,reservation)=scope.app.store.admit_review(&request,now())?;let mut lease=ReviewLease{state:scope.app.clone(),id:child.clone(),settled:false};
  let mut review=crate::agents::review_action(&scope.app.root,&request,cancel.child_token(),reservation).await;review.id=child;
  let charged=scope.app.store.settle_review(&review.id,review.usage.clone(),review.usage_complete)?;lease.settled=true;
  if !review.usage_complete||charged>=reservation{review.verdict.decision=Decision::Uncertain;review.verdict.explanation="Risk review token usage is unconfirmed or its budget ran out".into();}
  request=scope.app.store.action_reviewed(&request.id,review,now())?;changed(&request.id);crate::activity::action(&request,"script_review_completed");drop(review_lock);
  if request.state=="awaitingApproval" {
    crate::activity::action(&request,"script_awaiting_approval");
    // Present consent independently of OS notification permissions or clicks.
    if let Some(app)=EVENTS.get() {
      let mut window_span=crate::activity::begin_run("app","action_approval_window",Some(request.server_id.clone()),Some(run_id.clone()));
      window_span.result(&open_approval(app,&request.id));
    }
    let _=crate::notifications::action_approval(&scope.app.store,&request).await;
    let _pause=scope.wait_clock.pause();request=wait(&scope.app,&request.id,&cancel).await?;
  }
  if request.state!="approved"{return Ok(output(&request));}
  if !frame.unchanged(){return Err("SSH settings changed after approval".into());}
  scope.app.store.action_transition(&request.id,"approved","queued",now())?;
  request=scope.app.store.action_transition(&request.id,"queued","running",now())?;changed(&request.id);crate::activity::action(&request,"script_execution_started");
  let response=remote(scope.app.clone(),&request,"execute",&cancel).await?;
  let (status,result)=receipt(&request,response)?;
  request=scope.app.store.action_result(&request.id,&status,Some(result),None,now())?;
  Ok(output(&request))
 }.await;
    if let Err(e) = &outcome {
        let before_start = if cancel.is_cancelled() {
            "cancelled"
        } else {
            "denied"
        };
        let _ = scope
            .app
            .store
            .interrupt_action(&request.id, before_start, e.clone(), now());
    }
    changed(&request.id);
    if let Ok(saved) = scope.app.store.action_request(&request.id) {
        crate::activity::action(&saved, "script_result");
    }
    span.result(&outcome);
    outcome
}
pub(crate) fn cached(scope: &Scope, id: &str) -> Result<Value> {
    let request = scope.app.store.action_request(id)?;
    if Some(&request.run_id) != scope.run_id.as_ref()
        || scope.targets.get(&request.server_id) != Some(&request.artifact.endpoint)
    {
        return Err("This result belongs to a different AI run".into());
    }
    Ok(output(&request))
}
pub(crate) async fn reconcile(state: Arc<AppState>, id: &str) -> Result<Request> {
    let request = state.store.action_request(id)?;
    if !matches!(request.state.as_str(), "unknown" | "rollbackUnknown") {
        return Err("The result is already known".into());
    }
    let result = remote(state.clone(), &request, "result", &CancellationToken::new()).await?;
    let (status, result) = receipt(&request, result)?;
    state.store.action_reconciled(id, &status, result, now())
}
pub(crate) async fn rollback(state: Arc<AppState>, id: &str, hash: &str) -> Result<Request> {
    let request = state.store.begin_action_rollback(id, hash, now())?;
    crate::activity::action(&request, "script_rollback_started");
    let cancel = CancellationToken::new();
    state
        .actions
        .tasks
        .lock()
        .map_err(err)?
        .insert(id.into(), (format!("user:{id}"), cancel.clone()));
    let _task = Task {
        state: state.clone(),
        id: id.into(),
    };
    let result = remote(state.clone(), &request, "rollback", &cancel)
        .await
        .and_then(|v| receipt(&request, v));
    let saved = match result {
        Ok((status, result)) => state
            .store
            .action_result(id, &status, Some(result), None, now()),
        Err(e) => state
            .store
            .action_result(id, "rollbackUnknown", None, Some(e), now()),
    };
    if let Ok(request) = &saved {
        crate::activity::action(request, "script_rollback_result");
        changed(id);
    }
    saved
}

pub(crate) async fn fixture_remote(
    state: Arc<AppState>,
    request: &Request,
    operation: &str,
) -> Result<Value> {
    let endpoint: crate::model::Endpoint =
        serde_json::from_str(&request.artifact.endpoint).map_err(err)?;
    if endpoint.host != "127.0.0.1" || endpoint.port < 1024 {
        return Err("Smoke is only allowed on one-time localhost fixture".into());
    }
    remote(state, request, operation, &CancellationToken::new()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_wait_is_shared_bounded_and_stops_after_the_last_guard() {
        let clock = WaitClock::default();
        let first = clock.pause();
        let second = clock.pause();
        {
            let mut state = clock.0.lock().unwrap();
            state.0 = Some(Instant::now() - Duration::from_secs(20));
        }
        drop(first);
        assert_eq!(clock.0.lock().unwrap().2, 1);
        assert!(clock.elapsed() >= Duration::from_secs(20));
        drop(second);
        assert!(clock.0.lock().unwrap().0.is_none());
        assert!(clock.elapsed() < Duration::from_secs(21));
        clock.0.lock().unwrap().1 = Duration::from_secs(1000);
        assert_eq!(clock.elapsed(), Duration::from_secs(WAIT_SECONDS as u64));
    }

    #[test]
    fn finishing_a_run_does_not_cancel_a_user_requested_rollback() {
        let runtime = Runtime::default();
        let ai = CancellationToken::new();
        let user = CancellationToken::new();
        runtime.tasks.lock().unwrap().extend([
            ("ai".into(), ("run".into(), ai.clone())),
            ("rollback".into(), ("user:rollback".into(), user.clone())),
        ]);
        runtime.cancel_run("run");
        runtime.cancel_all();
        assert!(ai.is_cancelled());
        assert!(!user.is_cancelled());
        runtime.cancel("rollback");
        assert!(user.is_cancelled());
    }
}
