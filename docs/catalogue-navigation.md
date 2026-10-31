# Catalogue navigation and eligible choices

Controller lists use the server's bounded `data` array and opaque `next_cursor`.
The UI requests 25 rows initially and offers 25, 50 and 100 rows. Previous moves
back one page through the same server snapshot; Next follows the returned
cursor. The screen displays the server's snapshot revision when supplied.
Refresh, retry after an expired cursor, page-size changes and saved mutations
start at the first page. A collection error remains an error. An empty page
with another cursor invites continuing rather than declaring the collection
empty. Server snapshots and current authorization checks remain authoritative.

Asset, service and target selectors request `eligible=true`. Load next registry
page accumulates eligible choices without silently truncating the list or
clearing selections. The number of loaded choices is visible. Refresh choices
starts a new eligible snapshot and rechecks selections. A selected ID that has
not been loaded or is no longer eligible stays visible as unavailable; it blocks
submission until the operator loads its page, chooses another item or explicitly
removes it. Current target validity and revocation are checked by the server on
submission; the UI does not invent heartbeat thresholds. Quarantined targets are
also excluded defensively from the picker.

The target table uses actual `enforcement_backend` and `observed_at` fields.
Missing observation time is shown as Not observed. Catalogue state and a backend
name do not certify native enforcement. Overview counts describe the loaded
page and show `+` when the server reports more results. Navigating back to the
same registry section exits its creation form and restores list navigation.

English remains the default. All new labels have Korean, Japanese, Spanish,
German, French, Simplified Chinese and Traditional Chinese counterparts, with
key and placeholder parity checks. Human language and assistive-technology
review remain unverified.

Reproduce from the repository root after the catalogue backend is built:

```sh
cd web
npm test -- --run --maxWorkers=2 --testTimeout=30000
npm run check
npm run build
cd ..
python scripts/smoke_catalogue_navigation.py \
  --controller-binary target/debug/fw_control
```

The browser script starts a real disposable controller on localhost:18983 and
uses the shipped UI. It creates 65 manual asset records, reaches all three
pages without duplicates, goes back to the second page, selects 50 rows,
refreshes, saves a new asset, and loads and refreshes picker choices while
preserving selection. It requires Chromium/Playwright as documented in the
[passkey guide](passkey-login.md). Generated reports remain local at
`reports/catalogue-browser.json`. This checks catalogue and browser integration;
it does not enroll a native target or change a host firewall.
