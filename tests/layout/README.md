# Layout fixture

From the repository root, run `npx vite --config tests/layout/vite.config.ts` and open `http://127.0.0.1:1435`. The fixture uses production Vue components with local fictional data. It runs without SSH, Tauri, or model calls.

Exercise the fleet ribbon, server detail, dependencies, logs, and service panels. Use the controls to switch theme and container width, select long names and paths, or try extreme numbers. Resize the browser viewport separately to check media queries.

Check that metric values keep their alignment, the container and its visible children fit horizontally, and abbreviations remain readable. Where content is truncated, confirm that the exact value or full label is available through its tooltip or accessible label.
