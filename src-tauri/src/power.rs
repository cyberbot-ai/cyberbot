//! Native wake events invalidate process-local availability, not stored history.
#[cfg(target_os = "macos")]
pub(crate) fn install(app: tauri::AppHandle, state: std::sync::Arc<crate::AppState>) {
    use block2::RcBlock;
    use objc2::{rc::Retained, runtime::ProtocolObject};
    use objc2_app_kit::{NSWorkspace, NSWorkspaceDidWakeNotification};
    use objc2_foundation::{NSNotification, NSNotificationCenter, NSObjectProtocol};
    use std::{cell::RefCell, ptr::NonNull, sync::atomic::Ordering};
    use tauri::Emitter;
    struct Observer {
        center: Retained<NSNotificationCenter>,
        token: Retained<ProtocolObject<dyn NSObjectProtocol>>,
    }
    impl Drop for Observer {
        fn drop(&mut self) {
            unsafe {
                let observer: &objc2::runtime::AnyObject = (&*self.token).as_ref();
                self.center.removeObserver(observer);
            }
        }
    }
    thread_local! { static OBSERVER: RefCell<Option<Observer>> = const { RefCell::new(None) }; }
    let center = NSWorkspace::sharedWorkspace().notificationCenter();
    let callback = RcBlock::new(move |_: NonNull<NSNotification>| {
        let mut span = crate::activity::begin("app", "monitoring_wake", None);
        state.startup_cancel.cancel();
        let epoch = match state.store.suspend_metrics_checks() {
            Ok(epoch) => epoch,
            Err(error) => {
                span.result(&Err::<(), _>(error));
                return;
            }
        };
        state.wake_reset.store(true, Ordering::Release);
        let _ = app.emit("state-changed", ());
        let state = state.clone();
        let app = app.clone();
        tauri::async_runtime::spawn_blocking(move || {
            // Closing a bounded pool can wait on dead mux sockets; never block WebView.
            crate::ssh_pool::reset_global();
            let result = state.store.resume_metrics_checks(epoch);
            span.result(&result);
            let _ = app.emit("state-changed", ());
        });
    });
    let token = unsafe {
        center.addObserverForName_object_queue_usingBlock(
            Some(NSWorkspaceDidWakeNotification),
            None,
            None,
            &callback,
        )
    };
    OBSERVER.with(|slot| *slot.borrow_mut() = Some(Observer { center, token }));
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn install(_: tauri::AppHandle, _: std::sync::Arc<crate::AppState>) {}
