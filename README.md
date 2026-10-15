# aidoku-cf-relay

English | [繁體中文](README.zh-TW.md)

A small self-hosted relay that lets [Aidoku](https://aidoku.app) sources reach sites behind a Cloudflare challenge without the app showing a verification sheet.

Some sites put every page behind Cloudflare's managed challenge, and the app often has to pass it several times before a page opens. With this relay, a source sends its requests to the relay instead. The relay passes the challenge once in a real browser ([TRAWL](https://github.com/germondai/trawl)), keeps the resulting clearance, and forwards every request with it. Pages then load at normal speed and the app never sees the challenge.

It only helps sources that support it. See [For source developers](#for-source-developers) for how to add support.

## For readers

### What you need

- A computer or NAS that stays on, with [Docker](https://docs.docker.com/get-docker/).
- About 1 GB of memory.
- A source that supports the relay.

### Setup

1. Create a folder and download the two files into it:

   ```bash
   curl -o docker-compose.yml https://raw.githubusercontent.com/0BlueYan0/aidoku-cf-relay/main/docker-compose.yml
   curl -o .env https://raw.githubusercontent.com/0BlueYan0/aidoku-cf-relay/main/.env.example
   ```

   On Windows PowerShell, use `curl.exe` instead of `curl`.
2. Open `.env` in a text editor and set `RELAY_TOKEN` to your own password (ASCII letters, digits and symbols). The relay does not start with the example value.
3. In the same folder, run:

   ```bash
   docker compose up -d
   ```

Open `http://<this computer's IP>:8191/health` in a browser. `ok` means it is running. The first page of each site takes about 15 seconds while the relay passes the challenge. It remembers the sites it got a clearance for and, after a restart, passes their challenge again in the background, about 15 seconds per site; requests made meanwhile wait for it.

### In Aidoku

In the settings of each source that supports the relay, enter:

| Field | Value |
|---|---|
| Relay URL | `http://<this computer's IP>:8191` |
| Relay password | `RELAY_TOKEN` from `.env` |

Leave them empty to connect the usual way. The relay must be reachable at the root of its address (`http://host:port`), not under a path such as `https://nas.example/relay`.

### Using it away from home

Your phone must be able to reach the computer. Away from your home network, install [Tailscale](https://tailscale.com/) on both and use the computer's Tailscale IP as the relay URL.

Do not open port 8191 on your router. The relay speaks plain http, so site passwords would cross the internet unencrypted. Tailscale connections are encrypted. If you open the port anyway, use a long password.

### Troubleshooting

- **The first page of a site is slow**: the relay is passing the challenge for that host, about 15 seconds. Later pages are fast. It happens again when the site asks for a new check.
- **The source shows an error**: check that `/health` shows `ok`, that the password matches `.env`, that the host is allowed by `ALLOWED_HOSTS` if you set it, and that the computer's firewall allows port 8191.
- **Finding out why**: run `docker compose logs relay` in the folder. It shows each request and its result, and why the relay did not start.
- **Whether a site passes** depends on Cloudflare and on how the computer's IP is rated. Speed depends on the connection between the relay and the site.
- **Update**: run `docker compose pull`, then `docker compose up -d`.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_TOKEN` | (required) | Password sent by sources in `X-Relay-Token` |
| `ALLOWED_HOSTS` | `*` | Hosts the relay forwards to, comma separated. `*` matches any characters: `*.example.com` covers the subdomains (not `example.com` itself). Hosts on your local network (IP addresses, `localhost`, names without a dot, `.local`, `.lan`, `.home.arpa` and the like, names that do not resolve, and names that resolve to an address that is not public) are always refused |
| `SEEN_HOSTS_FILE` | `/data/hosts.txt` | Where the relay remembers the sites it got a clearance for (up to 50, most recently solved first), to pass their challenge again after a restart. Compose keeps it in the `relay-data` volume |
| `TRAWL_URL` | `http://trawl:8191` | Where TRAWL runs |
| `PORT` | `8080` | Port inside the container |
| `WARM_UP` | `1` | `0` skips getting clearances at start-up |

`PORT` only matters when you run `relay.py` yourself. With compose, change the left side of `"8191:8080"` instead.

## For source developers

The relay changes only where a request goes. A source keeps its parsing, login and logout code.

### 1. Settings

Add two text settings. `refreshes` reloads the source when the reader finishes typing.

```json
{
	"type": "group",
	"title": "Cloudflare relay",
	"footer": "See github.com/0BlueYan0/aidoku-cf-relay. Leave empty to connect the usual way.",
	"items": [
		{
			"type": "text",
			"key": "relayUrl",
			"title": "Relay URL",
			"placeholder": "http://192.168.0.10:8191",
			"keyboardType": 3,
			"autocapitalizationType": 0,
			"autocorrectionDisabled": true,
			"refreshes": ["content", "listings"]
		},
		{
			"type": "text",
			"key": "relayToken",
			"title": "Relay password",
			"secure": true,
			"autocapitalizationType": 0,
			"autocorrectionDisabled": true,
			"refreshes": ["content", "listings"]
		}
	]
}
```

### 2. Requests

When `relayUrl` is set, send `https://<host><path>?<query>` to `<relayUrl>/r/<host><path>?<query>` with the header `X-Relay-Token: <relayToken>`.

- Lowercase the host and put at least `/` after it. The relay files cookies under `/r/<lowercase host>/`.
- The relay always connects to the site over https.
- Hosts must be plain DNS names. Send internationalized names as punycode (`xn--…`).
- Do not set `User-Agent` and do not send your own `cf_clearance`. The relay replaces both with the ones its clearance was issued for.
- A relay on the reader's network is usually plain `http://`. Default to `http://` when the reader leaves out the scheme.

```rust
use aidoku::{alloc::String, imports::{defaults::defaults_get, html::Html, net::Request}, prelude::*, Result};

fn relay_base() -> Option<String> {
	let value = defaults_get::<String>("relayUrl")?;
	let value = value.trim().trim_end_matches('/');
	match value {
		"" => None,
		v if v.starts_with("http://") || v.starts_with("https://") => Some(String::from(v)),
		v => Some(format!("http://{v}")),
	}
}

/// `https://Example.com/a?b=1` -> `<base>/r/example.com/a?b=1`
fn relay_target(base: &str, url: &str) -> String {
	let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
	let (host, path) = rest.find(['/', '?']).map_or((rest, ""), |at| rest.split_at(at));
	// At least `/` after the host: the relay files cookies under `/r/<host>/`.
	let slash = if path.starts_with('/') { "" } else { "/" };
	format!("{base}/r/{}{slash}{path}", host.to_lowercase())
}

fn site_get(url: &str) -> Result<Request> {
	match relay_base() {
		Some(base) => {
			let token = defaults_get::<String>("relayToken").unwrap_or_default();
			Ok(Request::get(relay_target(&base, url))?.header("X-Relay-Token", token.trim()))
		}
		None => Ok(Request::get(url)?),
	}
}
```

Do the same for form posts (`Request::post`) and any other method.

What the relay passes on:

- **Methods**: GET, POST, HEAD, PUT, PATCH, DELETE, OPTIONS.
- **Request headers**: all of them, except connection-level ones, `User-Agent` (replaced), `Accept-Encoding` (the site answers uncompressed) and `X-Relay-Token`. Your own cookies go along, with `cf_clearance` replaced.
- **Request body**: up to 1 MB, with a `Content-Length`. Chunked bodies are refused.
- **Response headers**: all of them, except connection-level ones, `Strict-Transport-Security`, `Alt-Svc`, `Content-Length` (recomputed), and `Date` and `Server` (the relay sends its own). `Set-Cookie` and `Location` are rewritten (see 4).

### 3. Responses

- **Parse against the site's URL**, not the response's. The response URL is the relay's, so `get_html()` would resolve every link to the relay. Read the text and call `Html::parse_with_url(&text, original_url)`.
- **Treat any status outside 200 to 399 as an error.** The relay answers `401` for a wrong password, `403` for a host it refuses (the body says why), `502` when it could not get a clearance, and passes the site's own errors through. Parsed as pages they look empty, and a library refresh would take them for works with no chapters.

```rust
let response = site_get(url)?.send()?;
let status = response.status_code();
if !(200..400).contains(&status) {
	bail!("relay answered {status} for {url}");
}
let html = Html::parse_with_url(&response.get_string()?, url)?;
```

### 4. Sign-in and cookies

Nothing to do. The relay rewrites the site's `Set-Cookie` to the relay host under `Path=/r/<host>/…`, and the app's cookie jar sends it back on later requests to the same host. A login form posted through the relay signs in, and the logout link signs out. A redirect to an allowed https host comes back as `/r/<host>/…`, so the app follows it through the relay. A redirect anywhere else comes back as an absolute URL and the app goes there directly.

### 5. Images

The app fetches covers and page images itself. If they are behind the challenge too, implement `ImageRequestProvider` and return the relayed request (`site_get(&url)`) for those hosts. Images on hosts without the challenge can stay direct.

### 6. Hosts

By default the relay forwards to any public host, so readers do not need a list. List the hosts your source requests through the relay, mirrors included, for readers who restrict `ALLOWED_HOSTS`. Only hosts behind the challenge gain anything. A host without it also works (requests go with TRAWL's user agent and no clearance), but it is faster to leave it direct.

A complete example: `zh.bakamh` and `zh.18mh` in [aidoku-new-zh-sources](https://github.com/0BlueYan0/aidoku-new-zh-sources), files `sources/zh.bakamh/src/helper.rs` and `sources/zh.18mh/src/helper.rs`.

## How it works

```text
source ──> relay ──(clearance + its user agent)──> site
             └─ no clearance yet, or the site refuses it ──> TRAWL solves once (~15 s)
```

- One clearance per host, kept in memory. A refused clearance is renewed once per request. When a renewal fails, or a fresh clearance is refused too, the host is paused for 60 seconds. When TRAWL does not answer, a solve waits up to 90 seconds for it; after one such wait times out, solves fail at once (`TRAWL is not answering`) until TRAWL answers again or 60 seconds pass.
- Only hosts `ALLOWED_HOSTS` allows are forwarded (every public host by default), and never hosts on a local network. Every request needs the password, except `/health`.
- The sites it got a clearance for are listed in `SEEN_HOSTS_FILE`, so a restart can pass their challenge again before the reader asks.
- The log records each request's URL (including search terms), never cookies or passwords.
- The relay itself never connects to a local network. TRAWL's browser opens the sites it is sent to, following their scripts and redirects, so keep the password private.
- TRAWL is a separate project (AGPL-3.0) running in its own container. This relay only calls it over HTTP.

## License

MIT
