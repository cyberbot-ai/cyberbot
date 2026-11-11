//! Native macOS notifications. No WebView or shell helpers participate in delivery.
#[cfg(target_os = "macos")]
mod macos {
    use block2::{DynBlock, RcBlock};
    use objc2::{
        define_class, msg_send,
        rc::Retained,
        runtime::{Bool, ProtocolObject},
        sel, AnyThread,
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
            return Err("Notifications are available in the installed macOS app".into());
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
        Ok(authorization().await?.0)
    }
    pub async fn authorization() -> Result<(String, bool), String> {
        let rx = {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let tx = Mutex::new(Some(tx));
            let block = RcBlock::new(move |value: NonNull<UNNotificationSettings>| {
                let settings = unsafe { value.as_ref() };
                let status = settings.authorizationStatus();
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
                    let _ = tx.send((
                        name.to_string(),
                        settings.badgeSetting() == UNNotificationSetting::Enabled,
                    ));
                }
            });
            center()?.getNotificationSettingsWithCompletionHandler(&block);
            rx
        };
        tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .map_err(|_| "macOS did not respond to the notification permission check")?
            .map_err(|_| "Notification permission check interrupted".into())
    }
    pub async fn request(alerts: bool, badge: bool) -> Result<(), String> {
        let mut options = UNAuthorizationOptions::empty();
        if alerts {
            options |= UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound;
        }
        if badge {
            options |= UNAuthorizationOptions::Badge;
        }
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
            center()?.requestAuthorizationWithOptions_completionHandler(options, &block);
            rx
        };
        tokio::time::timeout(Duration::from_secs(120), rx)
            .await
            .map_err(|_| "The macOS notification permission request timed out")?
            .map_err(|_| "Notification permission request interrupted".to_string())?
    }
    pub async fn set_dock_badge(window: &tauri::WebviewWindow, count: i64) -> Result<(), String> {
        if count != 0 && !authorization().await?.1 {
            return Err("macOS badge permission is required".into());
        }
        let rx = {
            let center = center()?;
            center
                .respondsToSelector(sel!(setBadgeCount:withCompletionHandler:))
                .then(|| {
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let tx = Mutex::new(Some(tx));
                    let block = RcBlock::new(move |error: *mut NSError| {
                        if let Some(tx) = tx.lock().ok().and_then(|mut tx| tx.take()) {
                            let _ = tx.send(error.is_null());
                        }
                    });
                    center.setBadgeCount_withCompletionHandler(count as isize, Some(&block));
                    rx
                })
        };
        let Some(rx) = rx else {
            // macOS 12 supports Dock tile labels but lacks the notification center setter.
            return window
                .set_badge_count((count > 0).then_some(count))
                .map_err(|error| error.to_string());
        };
        match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(true)) => Ok(()),
            _ => Err("macOS did not apply the Dock badge".into()),
        }
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
                    Err("macOS rejected the notification".to_string())
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
            .map_err(|_| "macOS did not confirm that it received the notification")?
            .map_err(|_| "Notification delivery interrupted".to_string())?
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
pub async fn authorization() -> Result<(String, bool), String> {
    Ok(("unsupported".into(), false))
}
#[cfg(not(target_os = "macos"))]
pub async fn request(_: bool, _: bool) -> Result<(), String> {
    Err("Notifications are unavailable on this OS".into())
}
#[cfg(not(target_os = "macos"))]
pub async fn show(_: &str, _: &str, _: &str) -> Result<(), String> {
    Err("Notifications are unavailable on this OS".into())
}
