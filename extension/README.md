# WebFilter Proxy browser extension

One Manifest V3 extension for Chrome/Chromium (>= 121) and Firefox (>= 128), loaded unpacked and never published
(spec: `docs/SPEC_EXT_OPS.md` O9). It shows the proxy's mode and counters, the last 10 blocked requests, a badge
with the number of blocks since the extension started, and a toggle that routes the browser through the proxy.

It talks **only** to the proxy's loopback admin API (`http://127.0.0.1`, `localhost` or `[::1]`) and only with
**GET** requests using a **read-only** token. It has no content scripts, no `<all_urls>` access and no remote code.

## 1. Create a read-only token

1. Pick a long random token and hash it: `webfilter-proxy hash-password` (reads the secret from stdin, one line, and prints an
   argon2id PHC hash).
2. Put the hash in the proxy config and restart or reload the proxy:

   ```toml
   [admin]
   enabled = true
   readonly_token_hash = "$argon2id$v=19$..."
   ```

   The read-only token may only GET/HEAD; any state change answers 403 and is audited with actor `readonly`.
   Do not use the full admin token (`token_hash`) in the extension.

## 2. Load the extension

- **Chrome / Chromium**: open `chrome://extensions`, enable **Developer mode**, click **Load unpacked** and select
  this `extension/` folder.
- **Firefox**: open `about:debugging`, choose **This Firefox**, click **Load Temporary Add-on...** and select
  `extension/manifest.json`. Temporary add-ons are removed when Firefox closes.

## 3. Configure

Open the extension's options (from the popup, or the extensions page) and set:

- **Admin URL**: `http://127.0.0.1:9090` (http, loopback host, explicit port; anything else is refused).
- **Read-only token**: the secret from step 1. After saving it is never shown again.
- **Proxy**: `host:port` of the proxy listener, loopback only (default `127.0.0.1:8080`).

## Proxy toggle

- Chrome: fixed HTTP proxy for all traffic, bypassing `<local>`. Off restores the system settings.
- Firefox: manual proxy for HTTP and HTTPS. Firefox only lets an extension change proxy settings if it is allowed
  in private windows: on `about:addons`, open the extension and set **Run in Private Windows** to **Allow**.
  Off restores the system settings.

HTTPS interception still needs the lab CA installed manually in the browser (see the main README); the extension
never installs certificates.

## Request access

"Request access" opens a blocked `http`/`https` URL in a new tab; the proxy then shows its block page with the
access-request form. Other schemes are never opened.

## Lint

`just ext-lint` (or `python3 scripts/ext_lint.py`) checks the manifest permissions and that no script uses HTML
injection, `eval`, non-GET requests or non-loopback URLs.
