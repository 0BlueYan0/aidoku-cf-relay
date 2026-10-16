# aidoku-cf-relay

[English](README.md) | 繁體中文

自架的小型轉發伺服器，讓 [Aidoku](https://aidoku.app) 的圖源連得上有 Cloudflare 驗證的網站，App 不會再跳出驗證視窗。

有些網站整站都在 Cloudflare 的驗證後面，App 常常要驗證好幾次才打得開一頁。用了這個轉發伺服器，圖源改把請求送給它。它用真正的瀏覽器（[TRAWL](https://github.com/germondai/trawl)）通過一次驗證、保留驗證結果，之後的每個請求都帶著這個結果轉送給網站。頁面以平常的速度載入，App 完全碰不到驗證。

只有支援它的圖源才能用。圖源要怎麼支援，見[給圖源開發者](#給圖源開發者)。

## 給讀者

### 需要什麼

- 一台一直開著、裝了 [Docker](https://docs.docker.com/get-docker/) 的電腦或 NAS。
- 約 1 GB 記憶體。
- 支援轉發伺服器的圖源。

### 架設

1. 建一個資料夾，在裡面執行下面的指令，下載兩個設定檔：

   ```bash
   curl -o docker-compose.yml https://raw.githubusercontent.com/0BlueYan0/aidoku-cf-relay/main/docker-compose.yml
   curl -o .env https://raw.githubusercontent.com/0BlueYan0/aidoku-cf-relay/main/.env.example
   ```

   Windows 的 PowerShell 把 `curl` 改成 `curl.exe`。
2. 用文字編輯器打開 `.env`，把 `RELAY_TOKEN` 換成你自己的密碼，只能用英文字母、數字與符號。沿用範例值不會啟動。
3. 在同一個資料夾執行：

   ```bash
   docker compose up -d
   ```

用瀏覽器開 `http://<這台電腦的 IP>:8191/health`，看到 `ok` 就是在執行了。每個網站的第一頁要等約 15 秒，讓轉發伺服器通過驗證。它會記住取得過驗證結果的網站，重新啟動後在背景替這些網站再通過一次驗證，每個約 15 秒，這段時間的請求會排隊等候。

### App 裡的設定

在每個支援轉發伺服器的圖源設定頁填：

| 欄位 | 填什麼 |
|---|---|
| 轉發網址 | `http://<這台電腦的 IP>:8191` |
| 轉發密碼 | `.env` 裡的 `RELAY_TOKEN` |

留空就照原本的方式連線。轉發伺服器要放在網址的根目錄（`http://主機:埠`），不能放在 `https://nas.example/relay` 這種子路徑底下。

### 在家裡以外的地方使用

手機要連得到這台電腦才能用。在家用網路以外，建議電腦與手機都裝 [Tailscale](https://tailscale.com/)，轉發網址改填電腦的 Tailscale IP。

不要在路由器開放 8191 埠。轉發伺服器用的是沒有加密的 http，網站的登入密碼會以明文經過網路。Tailscale 的連線本身有加密。真的要開放的話，密碼一定要設得夠長。

### 常見問題

- **某個網站的第一頁比較慢**：轉發伺服器正在替這個網域通過驗證，約 15 秒，之後就快了。最近 7 天用過的網站，轉發伺服器會學網站隔多久要求重新驗證，之後在那之前先換好，見[背景檢查與提前換新](#背景檢查與提前換新)。還沒學到之前，閱讀中偶爾還是會慢一次。
- **圖源顯示錯誤**：確認 `/health` 是 `ok`、密碼與 `.env` 相同、有設 `ALLOWED_HOSTS` 的話網域符合它、電腦的防火牆沒有擋 8191 埠。
- **查原因**：在資料夾執行 `docker compose logs relay`，可以看到每個請求的結果，以及轉發伺服器沒有啟動的原因。
- **能不能通過驗證**取決於 Cloudflare 與這台電腦 IP 的評分，速度則看轉發伺服器和網站之間的連線。
- **更新**：執行 `docker compose pull`，再執行 `docker compose up -d`。

### 設定值

| 變數 | 預設 | 意思 |
|---|---|---|
| `RELAY_TOKEN` | （必填） | 圖源在 `X-Relay-Token` 送來的密碼 |
| `ALLOWED_HOSTS` | `*` | 允許轉發的網域，以逗號分隔。`*` 代表任意字元，`*.example.com` 涵蓋它的子網域（不含 `example.com` 本身）。家裡區網的位址（IP 位址、`localhost`、沒有點的名稱、`.local`、`.lan`、`.home.arpa` 等，解析不到的網域，以及解析到非公開位址的網域）一律拒絕 |
| `SEEN_HOSTS_FILE` | `/data/hosts.txt` | 轉發伺服器記住取得過驗證結果的網站（最多 50 個，最近取得驗證結果的優先）的檔案，重新啟動後替它們再通過一次驗證。每個網站多久要重新驗證、最近用過的時間，記在同一個資料夾的 `clearances.json`。compose 把它們放在 `relay-data` volume |
| `TRAWL_URL` | `http://trawl:8191` | TRAWL 的位址 |
| `PORT` | `8080` | 容器內的埠 |
| `WARM_UP` | `1` | 設 `0` 就不在啟動時先通過驗證 |
| `KEEP_WARM_DAYS` | `7` | 網站每隔一段時間會要求重新驗證。最近這幾天用過的網站，轉發伺服器會在那之前先在背景取得新的驗證結果，閱讀中不用等約 15 秒。設大一點，隔比較久才回來看的網站也不用等，代價是每個網站每隔一段時間就要開一次瀏覽器。設 `0` 關閉。運作方式見[背景檢查與提前換新](#背景檢查與提前換新) |
| `CHECK_MINUTES` | `30` | 每隔幾分鐘用現有的驗證結果打開一次網站首頁，確認還能用，不能用就先換新的。這是一般的請求，不開瀏覽器。設小一點，驗證結果被作廢後比較快換好，送給網站的請求也比較多。最少 `1` |

`PORT` 只在自己執行 `relay.py` 時有用。用 compose 的話，改 `"8191:8080"` 左邊的數字。

## 給圖源開發者

轉發伺服器只改變請求送去哪裡。圖源的解析、登入、登出程式都不用改。

### 1. 設定頁

加兩個文字欄位。`refreshes` 讓讀者輸入完之後重新載入圖源。

```json
{
	"type": "group",
	"title": "轉發伺服器",
	"footer": "架設方法見 github.com/0BlueYan0/aidoku-cf-relay。留空就照原本的方式連線。",
	"items": [
		{
			"type": "text",
			"key": "relayUrl",
			"title": "轉發網址",
			"placeholder": "http://192.168.0.10:8191",
			"keyboardType": 3,
			"autocapitalizationType": 0,
			"autocorrectionDisabled": true,
			"refreshes": ["content", "listings"]
		},
		{
			"type": "text",
			"key": "relayToken",
			"title": "轉發密碼",
			"secure": true,
			"autocapitalizationType": 0,
			"autocorrectionDisabled": true,
			"refreshes": ["content", "listings"]
		}
	]
}
```

### 2. 送出請求

有填 `relayUrl` 時，`https://<host><path>?<query>` 改送到 `<relayUrl>/r/<host><path>?<query>`，並帶 header `X-Relay-Token: <relayToken>`。

- 網域轉成小寫，後面至少接一個 `/`。轉發伺服器把 cookie 存在 `/r/<小寫網域>/` 底下。
- 轉發伺服器一律用 https 連到網站。
- 網域必須是一般的 DNS 名稱，中文等國際化網域請用 punycode（`xn--…`）。
- 不要設 `User-Agent`，也不要自己送 `cf_clearance`。轉發伺服器會換成驗證結果對應的那一組。
- 讀者家裡的轉發伺服器通常是 `http://`。讀者沒寫通訊協定時預設補 `http://`。

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

表單 POST（`Request::post`）與其他方法照同樣方式處理。

轉發伺服器會轉送：

- **方法**：GET、POST、HEAD、PUT、PATCH、DELETE、OPTIONS。
- **請求 header**：全部轉送，除了連線層的 header、`User-Agent`（會被換掉）、`Accept-Encoding`（網站會回未壓縮的內容）與 `X-Relay-Token`。圖源自己的 cookie 會一起送出，`cf_clearance` 會被換掉。
- **請求本體**：最多 1 MB，要帶 `Content-Length`。chunked 本體會被拒絕。
- **回應 header**：全部傳回，除了連線層的 header、`Strict-Transport-Security`、`Alt-Svc`、`Content-Length`（重新計算），以及 `Date` 與 `Server`（轉發伺服器送自己的）。`Set-Cookie` 與 `Location` 會改寫（見第 4 點）。

### 3. 處理回應

- **用網站的網址解析**，不要用回應的網址。回應的網址是轉發伺服器的，`get_html()` 會把每個連結解析到轉發伺服器。讀出文字後用 `Html::parse_with_url(&text, 原網址)`。
- **狀態碼不在 200～399 一律當成錯誤。** 密碼錯回 `401`、拒絕的網域回 `403`（內容會寫原因）、拿不到驗證結果回 `502`，網站自己的錯誤也會原樣傳回。這些若當成頁面解析會變成空白，書庫更新還會以為作品沒有章節。

```rust
let response = site_get(url)?.send()?;
let status = response.status_code();
if !(200..400).contains(&status) {
	bail!("relay answered {status} for {url}");
}
let html = Html::parse_with_url(&response.get_string()?, url)?;
```

### 4. 登入與 cookie

不用做任何事。轉發伺服器把網站的 `Set-Cookie` 改寫到轉發主機的 `Path=/r/<host>/…` 底下，App 的 cookie jar 之後會在同一個網域的請求帶回去。經轉發送出的登入表單會登入，登出連結會登出。轉址到白名單內的 https 網域時會改寫成 `/r/<host>/…`，App 會經轉發跟過去。轉址到其他地方則傳回完整網址，App 會直接連過去。

### 5. 圖片

封面與頁面圖是 App 自己下載的。如果它們也在驗證後面，實作 `ImageRequestProvider`，對那些網域回傳經轉發的請求（`site_get(&url)`）。沒有驗證的圖片網域可以照舊直連。

### 6. 網域

轉發伺服器預設轉送所有公開網域，讀者不必列清單。仍請在說明裡列出圖源會經轉發送出的網域（包含鏡像），給想限制 `ALLOWED_HOSTS` 的讀者參考。只有在驗證後面的網域才有好處。沒有驗證的網域也能經轉發（只帶 TRAWL 的 `User-Agent`，不帶驗證結果），但直連比較快。

完整範例：[aidoku-new-zh-sources](https://github.com/0BlueYan0/aidoku-new-zh-sources) 的 `zh.bakamh` 與 `zh.18mh`，檔案是 `sources/zh.bakamh/src/helper.rs` 與 `sources/zh.18mh/src/helper.rs`。

## 運作方式

```text
圖源 ──> 轉發伺服器 ──（驗證結果＋對應的 User-Agent）──> 網站
              └─ 還沒有驗證結果，或網站不接受 ──> TRAWL 通過一次驗證（約 15 秒）
```

- 每個網域一份驗證結果，存在記憶體。網站不接受時，該請求會換一次新的。換失敗，或新的也被拒絕時，這個網域暫停 60 秒。TRAWL 沒回應時，解題會等它最多 90 秒。等過一次還是沒回應，之後的解題會直接失敗（`TRAWL is not answering`），直到 TRAWL 恢復或過了 60 秒。
- 只轉發 `ALLOWED_HOSTS` 允許的網域（預設是所有公開網域），區網內的位址一律不轉發。除了 `/health`，每個請求都要密碼。
- 取得過驗證結果的網站記在 `SEEN_HOSTS_FILE`，重新啟動後可以在讀者使用前先通過驗證。
- 紀錄會記下每個請求的網址（包含搜尋關鍵字），不記錄 cookie 與密碼。
- 轉發伺服器本身絕不連到區網。TRAWL 的瀏覽器會打開送給它的網站，也會照網站的 script 與轉址走，所以密碼請保密。
- TRAWL 是另一個專案（AGPL-3.0），在自己的容器裡執行。本專案只透過 HTTP 呼叫它。

### 背景檢查與提前換新

網站接受同一份驗證結果多久，由網站自己的 Cloudflare 設定決定，常見的是 30 分鐘。驗證結果本身標示的期限一律是一年，跟網站實際接受多久無關，所以轉發伺服器靠觀察學出每個網站的時間，在網站拒絕之前先換好，讀者讀到一半就不用等約 15 秒。

1. **檢查**：最近 `KEEP_WARM_DAYS` 天用過的網站，每 `CHECK_MINUTES` 分鐘用現有的驗證結果載入一次首頁。這只是一般的請求，不開瀏覽器，約 1 秒。被拒就馬上換新的。
2. **學習**：網站拒絕一份驗證結果時（不論是檢查發現的，還是讀者的請求遇到的），轉發伺服器記下那份用了多久。取最近 3 次裡最短的當作這個網站的時間，最少 10 分鐘，一次提早作廢不會讓它變成每幾分鐘開一次瀏覽器。
3. **提前換新**：知道時間之後，驗證結果用到這個時間的 80% 就在背景換新的。換新期間讀者的請求照用舊的那份。
4. **重新學習**：網站可能改成接受得更久。每 5 次提前換新有 1 次會把舊的驗證結果留著，讀者照樣用新的。舊的那份每過學到的時間的十分之一檢查一次，直到網站拒絕，最多檢查一天。超過學到的時間還通過就把時間往上調，被拒就記下實際的時間。

其他行為：

- 還沒學到時間的網站只做第 1 步。讀者在兩次檢查之間遇到作廢，那一頁會慢一次，同時記下時間。
- 學到的時間與每個網站最近用過的時間存在 `SEEN_HOSTS_FILE` 同一個資料夾的 `clearances.json`，重新啟動後沿用。
- 重新啟動後背景不會替網站取得驗證結果，那是啟動時先通過驗證（`WARM_UP`）與讀者第一次請求的工作。設 `WARM_UP=0` 時，啟動後就不會開瀏覽器。
- 背景換新失敗時，這個網站隔 `CHECK_MINUTES` 分鐘再試，讀者的請求不受影響。
- 超過 `KEEP_WARM_DAYS` 天沒用的網站不再檢查，下次打開時第一頁會慢一次。

在 `docker compose logs relay` 裡看得到這些動作：

| 紀錄 | 意思 |
|---|---|
| `still takes its clearance, N min old` | 檢查通過，驗證結果用了 N 分鐘 |
| `refused a clearance N min old, renewing it at M min from now on` | 網站拒絕了用了 N 分鐘的驗證結果，之後用到 M 分鐘就換 |
| `renewing the clearance for … before the site stops taking it` | 提前換新 |
| `keeping the old clearance for … to see if it lasts past N min now` | 這次提前換新後舊的留著，看網站是不是接受得更久 |
| `refused the clearance kept aside at N min, renewing at M min from now on` | 網站在 N 分鐘拒絕了留著的那份，之後用到 M 分鐘就換 |
| `stopped checking the clearance kept aside for …, it lasted past 24 h` | 留著的那份過了一天網站還接受，不再檢查 |
| `still took a clearance N min old, dropping the shorter ages noted before` | 網站接受得比學到的久，時間往上調 |

## 授權

MIT
