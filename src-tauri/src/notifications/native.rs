//! Native macOS notifications. No WebView or shell helpers participate in delivery.
#[cfg(target_os = "macos")]
mod macos {
    use block2::{DynBlock, RcBlock};
    use objc2::{
        define_class, msg_send,
        rc::Retained,
        runtime::{Bool, ProtocolObject},
        AnyThread,
    };
    use objc2_app_kit::NSWorkspace;
    use objc2_foundation::NSURL;
    use objc2_foundation::{NSBundle, NSError, NSObject, NSObjectProtocol, NSString};
    use objc2_user_notifications::*;
    use std::{
        cell::RefCell,
        ptr::NonNull,
        sync::{Mutex, OnceLock},
        time::Duration,
    };
    static APP: OnceLock<tauri::AppHandle> = OnceLock::new();
    thread_local! { static DELEGATE: RefCell<Option<Retained<Delegate>>> = const { RefCell::new(None) }; }
    define_class!(
        #[unsafe(super = NSObject)]
        struct Delegate;
        unsafe impl NSObjectProtocol for Delegate {}
        unsafe impl UNUserNotificationCenterDelegate for Delegate {
            #[unsafe(method(userNotificationCenter:willPresentNotification:withCompletionHandler:))]
            fn present(
                &self,
                _: &UNUserNotificationCenter,
                _: &UNNotification,
                complete: &DynBlock<dyn Fn(UNNotificationPresentationOptions)>,
            ) {
                complete.call((UNNotificationPresentationOptions::Banner
                    | UNNotificationPresentationOptions::List
                    | UNNotificationPresentationOptions::Sound,));
            }
            #[unsafe(method(userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:))]
            fn clicked(
                &self,
                _: &UNUserNotificationCenter,
                response: &UNNotificationResponse,
                complete: &DynBlock<dyn Fn()>,
            ) {
                let id = response.notification().request().identifier().to_string();
                if let Some(app) = APP.get() {
                    super::super::activate(app, id.strip_prefix("cyberbot-").unwrap_or(""));
                }
                complete.call(());
            }
        }
    );
    fn center() -> Result<Retained<UNUserNotificationCenter>, String> {
        if NSBundle::mainBundle().bundleIdentifier().is_none() {
            return Err("Notifications are available in the collected app .app".into());
        }
        Ok(UNUserNotificationCenter::currentNotificationCenter())
    }
    pub fn install(app: tauri::AppHandle) -> Result<(), String> {
        let center = center()?;
        let _ = APP.set(app);
        let delegate: Retained<Delegate> = unsafe { msg_send![Delegate::alloc(), init] };
        center.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        DELEGATE.with(|slot| *slot.borrow_mut() = Some(delegate));
        Ok(())
    }
    pub fn open_settings() -> Result<(), String> {
        let url = NSURL::URLWithString(&NSString::from_str(
            "x-apple.systempreferences:com.apple.preference.notifications",
        ))
        .ok_or("System settings are not available")?;
        if NSWorkspace::sharedWorkspace().openURL(&url) {
            Ok(())
        } else {
            Err("Failed to open macOS notification settings".into())
        }
    }
    pub async fn permission() -> Result<String, String> {
        let rx = {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let tx = Mutex::new(Some(tx));
            let block = RcBlock::new(move |value: NonNull<UNNotificationSettings>| {
                let status = unsafe { value.as_ref() }.authorizationStatus();
                let name = if status == UNAuthorizationStatus::Authorized {
                    "authorized"
                } else if status == UNAuthorizationStatus::Provisional {
                    "provisional"
                } else if status == UNAuthorizationStatus::Denied {
                    "denied"
                } else {
                    "notDetermined"
                };
                if let Some(tx) = tx.lock().ok().and_then(|mut tx| tx.take()) {
                    let _ = tx.send(name.to_string());
                }
            });
            center()?.getNotificationSettingsWithCompletionHandler(&block);
            rx
        };
        tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .map_err(|_| "macOS did not respond to permission checks")?
            .map_err(|_| "Permit check interrupted".into())
    }
    pub async fn request() -> Result<(), String> {
        let rx = {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let tx = Mutex::new(Some(tx));
            let block = RcBlock::new(move |_: Bool, error: *mut NSError| {
                let result = if error.is_null() {
                    Ok(())
                } else {
                    Err("macOS failed to request permission for notifications".to_string())
                };
                if let Some(tx) = tx.lock().ok().and_then(|mut tx| tx.take()) {
                    let _ = tx.send(result);
                }
            });
            center()?.requestAuthorizationWithOptions_completionHandler(
                UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound,
                &block,
            );
            rx
        };
        tokio::time::timeout(Duration::from_secs(120), rx)
            .await
            .map_err(|_| "Waiting for macOS permission has expired")?
            .map_err(|_| "Request for permission terminated".to_string())?
    }
    pub async fn show(id: &str, title: &str, body: &str) -> Result<(), String> {
        let rx = {
            let content = UNMutableNotificationContent::new();
            content.setTitle(&NSString::from_str(title));
            content.setBody(&NSString::from_str(body));
            content.setSound(Some(&UNNotificationSound::defaultSound()));
            let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
                &NSString::from_str(&format!("cyberbot-{id}")),
                &content,
                None,
            );
            let (tx, rx) = tokio::sync::oneshot::channel();
            let tx = Mutex::new(Some(tx));
            let block = RcBlock::new(move |error: *mut NSError| {
                let result = if error.is_null() {
                    Ok(())
                } else {
                    Err("macOS rejects notification".to_string())
                };
                if let Some(tx) = tx.lock().ok().and_then(|mut tx| tx.take()) {
                    let _ = tx.send(result);
                }
            });
            center()?.addNotificationRequest_withCompletionHandler(&request, Some(&block));
            rx
        };
        tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .map_err(|_| "The result of the transmission of the notification macOS unknown")?
            .map_err(|_| "Transmission of notification interrupted".to_string())?
    }
}
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(not(target_os = "macos"))]
pub fn open_settings() -> Result<(), String> {
    Err("This OS is not yet supported".into())
}
#[cfg(not(target_os = "macos"))]
pub fn install(_: tauri::AppHandle) -> Result<(), String> {
    Ok(())
}
#[cfg(not(target_os = "macos"))]
pub async fn permission() -> Result<String, String> {
    Ok("unsupported".into())
}
#[cfg(not(target_os = "macos"))]
pub async fn request() -> Result<(), String> {
    Err("Notifications of this OS have not yet been supported".into())
}
#[cfg(not(target_os = "macos"))]
pub async fn show(_: &str, _: &str, _: &str) -> Result<(), String> {
    Err("Notifications of this OS have not yet been supported".into())
}
