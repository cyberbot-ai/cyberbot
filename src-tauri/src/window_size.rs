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
#[serde(deny_unknown_fields)]
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

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

impl Frame {
    fn size(self) -> Dimensions {
        Dimensions {
            width: self.width,
            height: self.height,
        }
    }

    #[cfg(any(target_os = "macos", test))]
    fn overlap(self, other: Self) -> f64 {
        let width = (self.x + self.width).min(other.x + other.width) - self.x.max(other.x);
        let height = (self.y + self.height).min(other.y + other.height) - self.y.max(other.y);
        width.max(0.0) * height.max(0.0)
    }

    #[cfg(any(target_os = "macos", test))]
    fn place(
        size: Dimensions,
        origin: Option<(f64, f64)>,
        work_area: Self,
        minimum: Dimensions,
    ) -> Self {
        let size = size.fit(minimum, work_area.size());
        let spare_width = work_area.width - size.width;
        let spare_height = work_area.height - size.height;
        let (x, y) = origin.unwrap_or((
            work_area.x + spare_width / 2.0,
            work_area.y + spare_height / 2.0,
        ));
        // If the minimum size exceeds the work area, keep the top left accessible.
        Self {
            x: x.clamp(work_area.x, work_area.x + spare_width.max(0.0)),
            y: y.clamp(
                work_area.y + spare_height.min(0.0),
                work_area.y + spare_height,
            ),
            width: size.width,
            height: size.height,
        }
    }

    #[cfg(any(target_os = "macos", test))]
    fn restore(
        self,
        primary_work_area: Self,
        displays: impl Iterator<Item = (Self, Self)>,
        minimum: Dimensions,
    ) -> Self {
        let work_area = displays
            .filter_map(|(bounds, work_area)| {
                let overlap = self.overlap(bounds);
                (overlap > 0.0).then_some((overlap, work_area))
            })
            .max_by(|(left, _), (right, _)| left.total_cmp(right))
            .map(|(_, work_area)| work_area);
        Self::place(
            self.size(),
            work_area.map(|_| (self.x, self.y)),
            work_area.unwrap_or(primary_work_area),
            minimum,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
enum Geometry {
    Frame(Frame),
    Size(Dimensions),
}

impl Geometry {
    fn valid(self) -> bool {
        match self {
            Self::Frame(frame) => {
                frame.x.is_finite() && frame.y.is_finite() && frame.size().valid()
            }
            Self::Size(size) => size.valid(),
        }
    }
}

fn read(path: &Path) -> Option<Geometry> {
    let mut data = Vec::new();
    File::open(path)
        .ok()?
        .take(1025)
        .read_to_end(&mut data)
        .ok()?;
    if data.len() > 1024 {
        return None;
    }
    let geometry: Geometry = serde_json::from_slice(&data).ok()?;
    geometry.valid().then_some(geometry)
}

fn write(path: &Path, geometry: Geometry) -> io::Result<()> {
    let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    let result = serde_json::to_writer(&mut file, &geometry)
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
struct LastGeometry {
    // Start with the displayed geometry, even if the saved frame had to be fitted.
    displayed: Option<Geometry>,
    pending: Option<Geometry>,
}

impl LastGeometry {
    fn observe(&mut self, geometry: Geometry) -> bool {
        if !geometry.valid() || self.displayed == Some(geometry) {
            return false;
        }
        self.displayed = Some(geometry);
        self.pending = Some(geometry);
        true
    }

    fn save(&mut self, path: &Path) -> io::Result<()> {
        if let Some(geometry) = self.pending {
            write(path, geometry)?;
            self.pending = None;
        }
        Ok(())
    }
}

struct Persistence {
    path: PathBuf,
    geometry: Arc<Mutex<LastGeometry>>,
    changed: watch::Sender<()>,
}

impl Persistence {
    fn new(path: PathBuf, displayed: Option<Geometry>) -> Self {
        let geometry = Arc::new(Mutex::new(LastGeometry {
            displayed,
            pending: None,
        }));
        let (changed, mut updates) = watch::channel(());
        let save_path = path.clone();
        let saved_geometry = geometry.clone();
        tauri::async_runtime::spawn(async move {
            while updates.changed().await.is_ok() {
                loop {
                    match tokio::time::timeout(DEBOUNCE, updates.changed()).await {
                        Ok(Ok(())) => continue,
                        Ok(Err(_)) => return,
                        Err(_) => break,
                    }
                }
                save(&saved_geometry, &save_path);
            }
        });
        Self {
            path,
            geometry,
            changed,
        }
    }

    fn observe(&self, window: &Window) {
        if !matches!(window.is_visible(), Ok(true))
            || !matches!(window.is_minimized(), Ok(false))
            || !matches!(window.is_fullscreen(), Ok(false))
        {
            return;
        }
        #[cfg(not(target_os = "macos"))]
        if !matches!(window.is_maximized(), Ok(false)) {
            return;
        }
        if let Some(geometry) = current_geometry(window) {
            if self.geometry.lock().unwrap().observe(geometry) {
                self.changed.send_replace(());
            }
        }
    }
}

fn save(geometry: &Mutex<LastGeometry>, path: &Path) {
    if let Err(error) = geometry.lock().unwrap().save(path) {
        eprintln!("The Cyberbot window geometry could not be saved: {error}");
    }
}

#[cfg(not(target_os = "macos"))]
fn current_geometry(window: &Window) -> Option<Geometry> {
    let scale = window.scale_factor().ok()?;
    let size = window.inner_size().ok()?.to_logical::<f64>(scale);
    let size = Dimensions {
        width: size.width,
        height: size.height,
    };
    size.valid().then_some(Geometry::Size(size))
}

#[cfg(target_os = "macos")]
use macos::current_geometry;

#[cfg(target_os = "macos")]
mod macos {
    use super::{Dimensions, Frame, Geometry};
    use objc2::rc::Retained;
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSScreen, NSWindow};
    use objc2_foundation::{NSPoint, NSRect, NSSize};
    use tauri::Window;

    impl From<NSRect> for Frame {
        fn from(rect: NSRect) -> Self {
            Self {
                x: rect.origin.x,
                y: rect.origin.y,
                width: rect.size.width,
                height: rect.size.height,
            }
        }
    }

    fn native_window(
        window: &Window,
        _main_thread: MainThreadMarker,
    ) -> Option<Retained<NSWindow>> {
        // Tauri returns an autoreleased NSWindow pointer on the main thread.
        unsafe { Retained::retain(window.ns_window().ok()?.cast()) }
    }

    pub(super) fn current_geometry(window: &Window) -> Option<Geometry> {
        let window = native_window(window, MainThreadMarker::new()?)?;
        let geometry = Geometry::Frame(window.frame().into());
        geometry.valid().then_some(geometry)
    }

    pub(super) fn restore(window: &Window, stored: Geometry) -> Option<()> {
        let main_thread = MainThreadMarker::new()?;
        let window = native_window(window, main_thread)?;
        let screens = NSScreen::screens(main_thread);
        let primary_work_area = screens.firstObject()?.visibleFrame().into();
        let min_size = window.minSize();
        let minimum = Dimensions {
            width: min_size.width,
            height: min_size.height,
        };
        let frame = match stored {
            Geometry::Frame(frame) => frame.restore(
                primary_work_area,
                screens
                    .iter()
                    .map(|screen| (screen.frame().into(), screen.visibleFrame().into())),
                minimum,
            ),
            Geometry::Size(size) => {
                let content = NSRect::new(NSPoint::ZERO, NSSize::new(size.width, size.height));
                let outer = Frame::from(window.frameRectForContentRect(content));
                Frame::place(outer.size(), None, primary_work_area, minimum)
            }
        };
        window.setFrame_display(
            NSRect::new(
                NSPoint::new(frame.x, frame.y),
                NSSize::new(frame.width, frame.height),
            ),
            false,
        );
        Some(())
    }
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
    let stored = read(&root.join(FILE_NAME));
    let builder = WebviewWindowBuilder::from_config(app, config)?.visible(false);
    #[cfg(not(target_os = "macos"))]
    let builder = if let Some(Geometry::Size(stored)) = stored {
        let minimum = Dimensions {
            width: config.min_width.unwrap_or(1.0),
            height: config.min_height.unwrap_or(1.0),
        };
        let size = stored.fit(minimum, available_size(app).unwrap_or(stored));
        builder.inner_size(size.width, size.height)
    } else {
        builder
    };
    let window = builder.build()?;
    #[cfg(target_os = "macos")]
    if let Some(stored) = stored {
        macos::restore(&window.as_ref().window(), stored);
    }
    Ok(window)
}

pub(crate) fn track(window: &WebviewWindow, root: &Path) {
    window.app_handle().manage(Persistence::new(
        root.join(FILE_NAME),
        current_geometry(&window.as_ref().window()),
    ));
}

pub(crate) fn geometry_changed(window: &Window) {
    if let Some(state) = window.try_state::<Persistence>() {
        state.observe(window);
    }
}

pub(crate) fn flush(app: &AppHandle) {
    if let Some(state) = app.try_state::<Persistence>() {
        if let Some(window) = app.get_webview_window("main") {
            state.observe(&window.as_ref().window());
        }
        save(&state.geometry, &state.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMUM: Dimensions = Dimensions {
        width: 900.0,
        height: 668.0,
    };
    const PRIMARY: Frame = Frame {
        x: 0.0,
        y: 44.0,
        width: 1512.0,
        height: 900.0,
    };
    const EXTERNAL: Frame = Frame {
        x: -2560.0,
        y: 0.0,
        width: 2560.0,
        height: 1415.0,
    };

    #[test]
    fn missing_and_corrupt_files_fall_back() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(FILE_NAME);
        assert_eq!(read(&path), None);
        for data in [
            b"{}".as_slice(),
            b"broken",
            br#"{"width":0,"height":720}"#,
            br#"{"x":10,"width":1280,"height":840}"#,
            br#"{"x":"invalid","y":10,"width":1280,"height":840}"#,
        ] {
            fs::write(&path, data).unwrap();
            assert_eq!(read(&path), None);
        }
    }

    #[test]
    fn reads_legacy_size_and_round_trips_frame() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(FILE_NAME);
        fs::write(&path, br#"{"width":1280,"height":840}"#).unwrap();
        assert_eq!(
            read(&path),
            Some(Geometry::Size(Dimensions {
                width: 1280.0,
                height: 840.0,
            }))
        );

        let frame = Geometry::Frame(Frame {
            x: -1920.5,
            y: 80.5,
            width: 1280.5,
            height: 840.0,
        });
        write(&path, frame).unwrap();
        assert_eq!(read(&path), Some(frame));
    }

    #[test]
    fn restores_full_work_area_and_fractional_position_exactly() {
        let moved = Frame {
            x: -1850.5,
            y: 25.5,
            width: 1280.5,
            height: 840.5,
        };
        for frame in [PRIMARY, EXTERNAL, moved] {
            assert_eq!(
                frame.restore(
                    PRIMARY,
                    [(PRIMARY, PRIMARY), (EXTERNAL, EXTERNAL)].into_iter(),
                    MINIMUM,
                ),
                frame
            );
        }
    }

    #[test]
    fn fits_to_changed_work_area_and_keeps_title_bar_visible_on_small_displays() {
        let smaller = Frame {
            y: 110.0,
            height: 600.0,
            ..PRIMARY
        };
        assert_eq!(
            PRIMARY.restore(smaller, [(PRIMARY, smaller)].into_iter(), MINIMUM),
            Frame {
                y: 42.0,
                height: 668.0,
                ..smaller
            }
        );
    }

    #[test]
    fn missing_display_preserves_preference_until_window_moves() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(FILE_NAME);
        let stored = Frame {
            width: 1000.0,
            height: 750.0,
            ..EXTERNAL
        };
        write(&path, Geometry::Frame(stored)).unwrap();
        let restored = stored.restore(PRIMARY, [(PRIMARY, PRIMARY)].into_iter(), MINIMUM);
        assert_eq!(
            restored,
            Frame {
                x: 256.0,
                y: 119.0,
                ..stored
            }
        );
        let mut tracker = LastGeometry {
            displayed: Some(Geometry::Frame(restored)),
            pending: None,
        };
        assert!(!tracker.observe(Geometry::Frame(restored)));
        tracker.save(&path).unwrap();
        assert_eq!(read(&path), Some(Geometry::Frame(stored)));

        let moved = Geometry::Frame(Frame {
            x: 350.0,
            ..restored
        });
        assert!(tracker.observe(moved));
        tracker.save(&path).unwrap();
        assert_eq!(read(&path), Some(moved));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
}
