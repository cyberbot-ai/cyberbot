# Cyberbot interface guidelines

Cyberbot is built for scanning a fleet and opening evidence quickly. Use compact controls, one accent color, and consistent layouts. Show operational problems and missing data where the operator can see them. Put methods and coverage details behind disclosures.

- The **Servers** page opens on the virtualized fleet ribbon. Keep resource metrics and detected services visible on each row. Distinguish warnings, critical results, stale data, unavailable readings, and pending checks. Keep full values available to the keyboard and assistive technology.
- Keep search, filters, and the view switch close to the fleet. Preserve focus and the visible server when background updates change metrics. The polling control belongs at the bottom of the navigation.
- Start server tabs with a short status summary and key values, followed by findings and data coverage. Keep routine navigation and the monitoring library consistent across services.
- Settings that save automatically stay editable. Show errors next to their fields and keep the existing valid value until the replacement has been accepted.
- Use Vue scoped styles. Define shared CSS custom properties on the app container and inherit them in scoped components. Use local selectors, visible keyboard focus, reduced-motion support, and system fonts.
- Keep layouts usable with narrow windows, long names, large metrics, and both themes. See the [layout fixture](tests/layout/README.md).
- The radar artwork lives in `src/assets/radar.svg`. Run `make icons` to regenerate native and frontend icons. Its attribution is in [third-party notices](THIRD_PARTY_NOTICES.md).
