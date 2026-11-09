use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tauri::{AppHandle, Manager, WebviewWindow, WebviewWindowBuilder, Window};
use tokio::sync::watch;

const FILE_NAME: &str = "window-size.json";
const DEBOUNCE: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
struct Dimensions {
    width: f64,
    height: f64,
}

impl Dimensions {
    fn valid(self) -> bool {
        [self.width, self.height]
            .into_iter()
            .all(|value| (1.0..=32768.0).contains(&value))
    }

    fn fit(self, minimum: Self, available: Self) -> Self {
        Self {
            width: self
                .width
                .clamp(minimum.width, available.width.max(minimum.width)),
            height: self
                .height
                .clamp(minimum.height, available.height.max(minimum.height)),
        }
    }
}

fn read(path: &Path) -> Option<Dimensions> {
    let mut data = Vec::new();
    File::open(path)
        .ok()?
        .take(1025)
        .read_to_end(&mut data)
        .ok()?;
    if data.len() > 1024 {
        return None;
    }
    let size: Dimensions = serde_json::from_slice(&data).ok()?;
    size.valid().then_some(size)
}

fn write(path: &Path, size: Dimensions) -> io::Result<()> {
    let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    let result = serde_json::to_writer(&mut file, &size)
        .map_err(io::Error::other)
        .and_then(|_| file.sync_all());
    drop(file);
    let result = result.and_then(|_| fs::rename(&temp, path));
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

#[derive(Default)]
struct LastSize {
    // Start with the displayed size, even if the saved size had to be clamped.
    displayed: Option<Dimensions>,
    pending: Option<Dimensions>,
}

impl LastSize {
    fn observe(&mut self, size: Dimensions) -> bool {
        if !size.valid() || self.displayed == Some(size) {
            return false;
        }
        self.displayed = Some(size);
        self.pending = Some(size);
        true
    }

    fn save(&mut self, path: &Path) -> io::Result<()> {
        if let Some(size) = self.pending {
            write(path, size)?;
            self.pending = None;
        }
        Ok(())
    }
}

struct Persistence {
    path: PathBuf,
    size: Arc<Mutex<LastSize>>,
    changed: watch::Sender<()>,
}

impl Persistence {
    fn new(path: PathBuf, displayed: Option<Dimensions>) -> Self {
        let size = Arc::new(Mutex::new(LastSize {
            displayed,
            pending: None,
        }));
        let (changed, mut updates) = watch::channel(());
        let save_path = path.clone();
        let saved_size = size.clone();
        tauri::async_runtime::spawn(async move {
            while updates.changed().await.is_ok() {
                loop {
                    match tokio::time::timeout(DEBOUNCE, updates.changed()).await {
                        Ok(Ok(())) => continue,
                        Ok(Err(_)) => return,
                        Err(_) => break,
                    }
                }
                save(&saved_size, &save_path);
            }
        });
        Self {
            path,
            size,
            changed,
        }
    }

    fn observe(&self, window: &Window) {
        if !matches!(window.is_visible(), Ok(true))
            || !matches!(window.is_minimized(), Ok(false))
            || !matches!(window.is_maximized(), Ok(false))
            || !matches!(window.is_fullscreen(), Ok(false))
        {
            return;
        }
        if let Some(size) = dimensions(window) {
            if self.size.lock().unwrap().observe(size) {
                self.changed.send_replace(());
            }
        }
    }
}

fn save(size: &Mutex<LastSize>, path: &Path) {
    if let Err(error) = size.lock().unwrap().save(path) {
        eprintln!("The size of the Cyberbot window could not be maintained: {error}");
    }
}

fn dimensions(window: &Window) -> Option<Dimensions> {
    let scale = window.scale_factor().ok()?;
    let size = window.inner_size().ok()?.to_logical::<f64>(scale);
    let size = Dimensions {
        width: size.width,
        height: size.height,
    };
    size.valid().then_some(size)
}

#[cfg(target_os = "macos")]
fn available_size(_app: &AppHandle) -> Option<Dimensions> {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSScreen, NSWindow, NSWindowStyleMask};

    // The default macOS window is centered on the main screen. Convert the
    // usable frame into a content size, accounting for the native title bar.
    let main_thread = MainThreadMarker::new()?;
    let screen = NSScreen::mainScreen(main_thread)?;
    let style = NSWindowStyleMask::Titled
        | NSWindowStyleMask::Resizable
        | NSWindowStyleMask::Closable
        | NSWindowStyleMask::Miniaturizable;
    let area =
        NSWindow::contentRectForFrameRect_styleMask(screen.visibleFrame(), style, main_thread);
    Some(Dimensions {
        width: area.size.width,
        height: area.size.height,
    })
}

#[cfg(not(target_os = "macos"))]
fn available_size(app: &AppHandle) -> Option<Dimensions> {
    let monitor = app.primary_monitor().ok()??;
    let size = monitor
        .work_area()
        .size
        .to_logical::<f64>(monitor.scale_factor());
    Some(Dimensions {
        width: size.width,
        height: size.height,
    })
}

pub(crate) fn create_main(app: &AppHandle, root: &Path) -> tauri::Result<WebviewWindow> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|window| window.label == "main")
        .ok_or(tauri::Error::WindowNotFound)?;
    let path = root.join(FILE_NAME);
    let mut builder = WebviewWindowBuilder::from_config(app, config)?.visible(false);
    if let Some(stored) = read(&path) {
        let minimum = Dimensions {
            width: config.min_width.unwrap_or(1.0),
            height: config.min_height.unwrap_or(1.0),
        };
        let size = stored.fit(minimum, available_size(app).unwrap_or(stored));
        builder = builder.inner_size(size.width, size.height);
    }
    let window = builder.build()?;
    app.manage(Persistence::new(
        path,
        dimensions(&window.as_ref().window()),
    ));
    Ok(window)
}

pub(crate) fn resized(window: &Window) {
    if let Some(state) = window.try_state::<Persistence>() {
        state.observe(window);
    }
}

pub(crate) fn flush(app: &AppHandle) {
    if let Some(state) = app.try_state::<Persistence>() {
        if let Some(window) = app.get_webview_window("main") {
            state.observe(&window.as_ref().window());
        }
        save(&state.size, &state.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_and_corrupt_files_fall_back() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(FILE_NAME);
        assert_eq!(read(&path), None);
        for data in [b"{}".as_slice(), b"broken", br#"{"width":0,"height":720}"#] {
            fs::write(&path, data).unwrap();
            assert_eq!(read(&path), None);
        }
    }

    #[test]
    fn clamping_for_a_smaller_display_preserves_the_preference_until_resize() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(FILE_NAME);
        let stored = Dimensions {
            width: 2000.0,
            height: 1200.0,
        };
        write(&path, stored).unwrap();
        let minimum = Dimensions {
            width: 900.0,
            height: 640.0,
        };
        let available = Dimensions {
            width: 1200.0,
            height: 700.0,
        };
        let restored = stored.fit(minimum, available);
        assert_eq!(restored, available);
        let mut tracker = LastSize {
            displayed: Some(restored),
            pending: None,
        };
        assert!(!tracker.observe(restored));
        tracker.save(&path).unwrap();
        assert_eq!(read(&path), Some(stored));

        let resized = Dimensions {
            width: 1000.0,
            height: 650.5,
        };
        assert!(tracker.observe(resized));
        tracker.save(&path).unwrap();
        assert_eq!(read(&path), Some(resized));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
}
