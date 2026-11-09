//! A focused native consent surface. Opening it never grants or executes anything.
use super::*;
use std::sync::Arc;
use tauri::Manager;

pub(crate) fn approval_label(id: &str) -> Result<String> {
    uuid::Uuid::parse_str(id).map_err(|_| "Incorrect query ID")?;
    Ok(format!("approval-{id}"))
}
pub(crate) fn open_approval(app: &tauri::AppHandle, id: &str) -> Result<()> {
    let label = approval_label(id)?;
    app.state::<Arc<crate::AppState>>()
        .store
        .action_request(id)?;
    if let Some(window) = app.get_webview_window(&label) {
        window.show().map_err(err)?;
        window.unminimize().map_err(err)?;
        return window.set_focus().map_err(err);
    }
    tauri::WebviewWindowBuilder::new(
        app,
        label,
        tauri::WebviewUrl::App(format!("index.html?approval={id}").into()),
    )
    .title("Cyberbot · Allowing AI")
    .inner_size(660.0, 600.0)
    .min_inner_size(540.0, 460.0)
    .center()
    .build()
    .map_err(err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn consent_windows_have_only_the_extra_permission_to_close_themselves() {
        let capability: Value =
            serde_json::from_str(include_str!("../../capabilities/approval.json")).unwrap();
        assert_eq!(capability["windows"], json!(["approval-*"]));
        assert_eq!(
            capability["permissions"],
            json!(["core:window:allow-close"])
        );
    }
    #[test]
    fn each_approval_is_bound_to_a_valid_request_id() {
        let id = uuid::Uuid::new_v4().to_string();
        assert_eq!(approval_label(&id).unwrap(), format!("approval-{id}"));
        for invalid in ["main", "../index.html", "server-id", "?approval=other"] {
            assert!(approval_label(invalid).is_err());
        }
    }
}
