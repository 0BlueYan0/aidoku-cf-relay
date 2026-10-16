"""Cloudflare relay for Aidoku sources.

Forwards requests to sites behind a Cloudflare challenge, carrying a clearance that TRAWL
(https://github.com/germondai/trawl) earned once. The phone never meets the challenge, and
TRAWL opens a browser only when there is no clearance yet, the site refuses it, or a host the
reader uses is about to reach the age at which its site refused one before.

    GET POST HEAD PUT PATCH DELETE OPTIONS /r/<host>/<path>?<query>  ->  https://<host>/<path>?<query>

The hosts it forwards to are set by whoever runs it (`ALLOWED_HOSTS`, wildcards allowed, `*` by
default). Every request needs the relay's password, and hosts on the local network are always
refused, so even with `*` the relay itself never connects to the reader's router or NAS. TRAWL's
browser does open the sites it is sent to, scripts and redirects included, so the password is what
keeps strangers from using it.

Measured on 2026-10-15 against two sites behind a managed challenge: a clearance from TRAWL plus
its user agent was accepted for every page of the site from the same public IP, 0.5 to 1.9 s a
page, against 8 to 15 s for loading every page in TRAWL's browser.
"""

import hmac
import http.server
import ipaddress
import json
import math
import os
import re
import socket
import socketserver
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# Request headers not passed on to the site: connection-level ones, the relay's own password,
# and the user agent, which is replaced by the one the clearance was issued for. Accept-Encoding
# is dropped so the site answers uncompressed and lengths stay simple. Everything else goes.
DROPPED_REQUEST_HEADERS = {
    "host", "user-agent", "x-relay-token", "accept-encoding", "content-length", "connection",
    "keep-alive", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding",
    "upgrade",
}
# Response headers not passed back: connection-level ones, the length (recomputed), the two
# that are rewritten (Set-Cookie, Location), and ones that would make the client treat the
# relay's own host differently (HSTS forcing https, Alt-Svc offering another protocol).
# `Date` and `Server` are written by the relay itself; passing the site's too would send each twice.
DROPPED_RESPONSE_HEADERS = {
    "connection", "keep-alive", "transfer-encoding", "content-length", "set-cookie", "location",
    "strict-transport-security", "alt-svc", "upgrade", "trailer", "proxy-authenticate",
    "date", "server",
}
MAX_BODY = 1 << 20
PLACEHOLDER_TOKEN = "change-me-to-a-long-password"
SITE_TIMEOUT = 60
TRAWL_TIMEOUT = 120
TRAWL_START_WAIT = 90


def log(message):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), message, flush=True)


# Names that only exist on a local network. Always refused, whatever ALLOWED_HOSTS says.
INTERNAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".intranet", ".localhost", ".home.arpa")

# A plain DNS name: letters, digits and hyphens in dot-separated labels, at least two labels, no
# trailing dot. Anything else (`a@127.0.0.1`, `localhost.`, `%`, `_`) is refused before any lookup:
# a browser reads such a name differently from the relay's own resolver. IDN hosts arrive as punycode.
HOST_NAME = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")


def resolve(host):
    """The addresses `host` resolves to, empty when it does not resolve."""
    try:
        return {info[4][0] for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)}
    except OSError:
        return set()


def is_public_address(address):
    """Whether an address is on the public internet, looking through the IPv6 forms that carry an
    IPv4 address inside (mapped, 6to4, Teredo, NAT64 `64:ff9b::/96`)."""
    ip = ipaddress.ip_address(address.split("%")[0])
    if not ip.is_global or ip.is_multicast:
        return False
    # Site-local and local-use NAT64: global to some Python versions, local in practice.
    if ip.version == 6 and any(ip in ipaddress.ip_network(net) for net in ("fec0::/10", "64:ff9b:1::/48", "::/96", "::ffff:0:0:0/96")):
        return False
    if ip.version == 6:
        inner = [ip.ipv4_mapped, ip.sixtofour]
        if ip.teredo:
            inner.extend(ip.teredo)
        if ip in ipaddress.ip_network("64:ff9b::/96"):
            inner.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if any(v4 is not None and not v4.is_global for v4 in inner):
            return False
    return True


def is_internal(host, resolver=resolve):
    """Whether `host` must not be forwarded to: anything but a plain DNS name (IP literals, ports,
    userinfo, a trailing dot), a name without a dot, a local-only suffix, a name that does not
    resolve here, or one that resolves to any address that is not public (private, loopback,
    link-local, carrier-grade NAT and the like, which also covers a public name made to point at
    the LAN). Fails closed: a name this relay cannot resolve is refused."""
    if not HOST_NAME.fullmatch(host) or host.endswith(INTERNAL_SUFFIXES):
        return True
    # `1.2.3` or `127.1`: resolvers and browsers read a name ending in digits as an IPv4 address.
    if host.rsplit(".", 1)[-1].isdigit():
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    addresses = resolver(host)
    if not addresses:
        return True
    return not all(is_public_address(address) for address in addresses)


class HostRules:
    """`ALLOWED_HOSTS`: comma-separated host patterns where `*` matches any run of characters and
    every other character matches itself. `*` alone allows every public host; `*.example.com`
    allows its subdomains but not `example.com` itself, which needs its own entry."""

    # How long a host's local-network verdict is reused. Each page would otherwise pay a DNS lookup
    # (the slim image has no resolver cache). The certificate check in `send` still stops a name
    # that changes address within this window.
    CACHE_SECONDS = 60

    def __init__(self, patterns, resolver=resolve, clock=time.time):
        self.cache = {}
        self.clock = clock
        self.patterns = [p.strip().lower() for p in patterns if p.strip()]
        self.compiled = [re.compile(".*".join(re.escape(part) for part in p.split("*"))) for p in self.patterns]
        self.resolver = resolver

    @classmethod
    def parse(cls, value, resolver=resolve):
        return cls(value.split(","), resolver)

    def allows(self, host):
        return self.refusal(host) is None

    def refusal(self, host):
        """Why `host` is refused, or None when it is allowed."""
        host = host.lower()
        if not any(pattern.fullmatch(host) for pattern in self.compiled):
            return "host not allowed by ALLOWED_HOSTS"
        cached = self.cache.get(host)
        if cached and self.clock() - cached[1] < self.CACHE_SECONDS:
            internal = cached[0]
        else:
            internal = is_internal(host, self.resolver)
            now = self.clock()
            if len(self.cache) > 1000:
                self.cache = {h: v for h, v in self.cache.items() if now - v[1] < self.CACHE_SECONDS}
            self.cache[host] = (internal, now)
        if internal:
            return "host is on a local network, not a plain DNS name, or does not resolve"
        return None

    def exact(self):
        """The patterns that name one host, for the start-up warm-up."""
        return {p for p in self.patterns if "*" not in p}

    def __str__(self):
        return ", ".join(self.patterns)


class SeenHosts:
    """Hosts a clearance was obtained for, kept in a file so a restart can warm them up again.
    With `ALLOWED_HOSTS=*` there is no list of hosts to warm up otherwise. Keeps the `LIMIT` most
    recently solved; only plain DNS names are kept, so a hand-edited file cannot feed TRAWL junk."""

    LIMIT = 50

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.hosts = []
        try:
            with open(path, encoding="utf-8-sig", errors="replace") as file:
                self.hosts = [h for h in (line.strip().lower() for line in file) if HOST_NAME.fullmatch(h)][-self.LIMIT:]
        except OSError:
            pass

    def add(self, host):
        if not HOST_NAME.fullmatch(host):
            return
        with self.lock:
            if self.hosts and self.hosts[-1] == host:
                return
            self.hosts = ([h for h in self.hosts if h != host] + [host])[-self.LIMIT:]
            # Written beside the file and moved over it, so a crash never leaves half a list.
            temporary = self.path + ".tmp"
            try:
                with open(temporary, "w", encoding="utf-8") as file:
                    file.write("\n".join(self.hosts) + "\n")
                os.replace(temporary, self.path)
            except OSError as error:
                log(f"cannot remember hosts in {self.path}: {error}")


def is_challenge(status, headers):
    return status in (403, 503) and (headers.get("cf-mitigated") or "").lower() == "challenge"


def rewrite_location(location, url, rules):
    """A redirect target as a relay path, so the app follows it through the relay.

    `location` may be absolute, protocol-relative (`//host/x`), root-relative (`/x`) or
    relative (`x`); it is resolved against the request's `url` first. Only https targets on
    an allowed host are rewritten. Any other target is passed on as an absolute URL, so the
    app goes there directly instead of meeting the relay's 403 or a wrong scheme.
    """
    resolved = urllib.parse.urljoin(url, location)
    target = urllib.parse.urlsplit(resolved)
    if target.scheme != "https" or not rules.allows(target.netloc):
        return resolved
    rest = target.path or "/"
    if target.query:
        rest += "?" + target.query
    return f"/r/{target.netloc.lower()}{rest}"


def rewrite_cookie(cookie, host):
    """Moves a site cookie under `/r/<host>/` on the relay's own host.

    `Domain` would not match the relay, and `Secure` would keep the cookie off a plain-http
    relay, so both go. The app's cookie jar then sends the cookie back with later requests
    for that host only, which is how a sign-in survives.

    Known limit: a `__Host-` or `__Secure-` cookie is no longer valid once `Secure` is gone
    and its path changes, and the jar drops it.
    """
    parts = [p.strip() for p in cookie.split(";") if p.strip()]
    kept = [parts[0]]
    path = "/"
    for part in parts[1:]:
        name = part.split("=", 1)[0].strip().lower()
        if name in ("domain", "secure", "samesite"):
            continue
        if name == "path":
            path = part.split("=", 1)[1].strip() if "=" in part else "/"
            continue
        kept.append(part)
    if not path.startswith("/"):
        path = "/" + path
    kept.append(f"Path=/r/{host}{path}")
    return "; ".join(kept)


class TrawlDown(RuntimeError):
    """TRAWL did not accept connections in time."""


class Clearances:
    """One clearance per host, renewed through TRAWL one host at a time.

    Kept per host rather than per registrable domain: `www.example.com` and `example.com` then
    solve once each, but no list of public suffixes is needed to tell `example.co.uk` apart.

    After a failed renewal, or a fresh clearance the site still refused, the host is left
    alone for `PAUSE` seconds: each try opens a browser for ~15 s, and a hung TRAWL would
    otherwise hold every waiting request for `TRAWL_TIMEOUT` in turn.
    """

    PAUSE = 60

    def __init__(self, trawl_url, fetch_clearance=None, clock=time.time, on_new=None, trawl_ready=None):
        self.trawl_url = trawl_url.rstrip("/")
        self.trawl_ready = trawl_ready or self._trawl_ready
        self.keys = {}
        self.obtained_at = {}
        self.locks = {}
        self.failed_at = {}
        self.guard = threading.Lock()
        # One solve at a time: TRAWL's browser pool is small, and a second solve sent while one
        # runs could be refused (429) and pause that site for the reader.
        self.solving = threading.Lock()
        self.fetch_clearance = fetch_clearance or self._from_trawl
        self.clock = clock
        self.on_new = on_new
        self.trawl_down_until = 0

    def get(self, site):
        return self.keys.get(site)

    def failed(self, site):
        self.failed_at[site] = self.clock()

    def renew(self, site, seen, pause_on_failure=True):
        """Gets a new clearance unless another request already replaced `seen`."""
        with self.guard:
            lock = self.locks.setdefault(site, threading.Lock())
        with lock:
            if self.keys.get(site) is not seen:
                return
            if pause_on_failure and self.clock() - self.failed_at.get(site, -self.PAUSE) < self.PAUSE:
                raise RuntimeError(f"clearance for {site} failed recently, try again in a minute")
            started = time.time()
            try:
                if self.fetch_clearance == self._from_trawl or self.trawl_ready != self._trawl_ready:
                    self._wait_for_trawl()
                with self.solving:
                    self.keys[site] = self.fetch_clearance(site)
            except TrawlDown:
                # Not this host's fault: `_wait_for_trawl` already holds every solve back for a while.
                raise
            except Exception:
                if pause_on_failure:
                    self.failed(site)
                raise
            self.failed_at.pop(site, None)
            self.obtained_at[site] = self.clock()
            if self.keys[site][0]:
                log(f"new clearance for {site} in {time.time() - started:.1f} s")
            if self.on_new and self.keys[site][0]:
                self.on_new(site)

    def warm_up(self, sites, trawl_ready=None, wait=180, allows=None):
        """Gets a clearance for every host in turn, so the first page of each, and a mirror the
        reader switches to, does not wait ~15 s for a solve. On 2026-10-15 switching a source to a
        mirror took 17 s before its home page showed, and it looked as if nothing reloaded.

        Waits for TRAWL first: a solve sent while it is still starting would fail. A site that
        fails here is not paused; the reader's first request for it tries again.

        A list is taken in its order (most recently solved first); a set alphabetically. `allows`
        filters hosts here, after TRAWL is up, so DNS lookups never delay the relay's start.
        After start-up, `Upkeep` renews the hosts the reader keeps using.
        """
        ready = trawl_ready or self.trawl_ready
        deadline = self.clock() + wait
        while not ready():
            if self.clock() > deadline:
                log("TRAWL did not come up, skipping the warm-up")
                return
            time.sleep(3)
        ordered = list(dict.fromkeys(sites)) if isinstance(sites, list) else sorted(sites)
        for site in ordered:
            if allows and not allows(site):
                continue
            try:
                self.renew(site, None, pause_on_failure=False)
            except Exception as error:  # noqa: BLE001 - a site that fails now is solved on demand later
                log(f"warm-up for {site} failed: {error}")

    def _trawl_ready(self):
        try:
            urllib.request.urlopen(f"{self.trawl_url}/health", timeout=5)
            return True
        except Exception:  # noqa: BLE001
            return False

    def _wait_for_trawl(self):
        """Right after `docker compose up` TRAWL takes a while to accept connections. A reader who
        opens a source then would otherwise get a 502 and a paused host, so this waits for it,
        outside the solving lock. Once a wait has timed out, later ones fail at once for `PAUSE`
        seconds instead of each waiting again."""
        if self.clock() < self.trawl_down_until:
            if not self.trawl_ready():
                raise TrawlDown("TRAWL is not answering")
            self.trawl_down_until = 0
        deadline = time.time() + TRAWL_START_WAIT
        while not self.trawl_ready():
            if time.time() > deadline:
                self.trawl_down_until = self.clock() + self.PAUSE
                raise TrawlDown("TRAWL is not answering")
            time.sleep(2)

    def _from_trawl(self, site):
        body = json.dumps({"url": f"https://{site}/", "maxTimeout": 60000}).encode()
        request = urllib.request.Request(
            f"{self.trawl_url}/scrape", body, {"Content-Type": "application/json"}
        )
        data = json.loads(urllib.request.urlopen(request, timeout=TRAWL_TIMEOUT).read().decode("utf-8"))
        key = next(
            (c.get("value") for c in data.get("cookies") or [] if c.get("name") == "cf_clearance"),
            None,
        )
        agent = data.get("userAgent")
        if not agent:
            raise RuntimeError(f"TRAWL gave no answer for {site}")
        if not key:
            # The host showed no challenge this time (not behind Cloudflare, or a challenge that
            # only fires sometimes). Requests go with TRAWL's user agent alone, and a challenge
            # that shows up later renews as usual.
            log(f"{site} showed no challenge, forwarding without a clearance")
        return key, agent


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def with_clearance(headers, clearance):
    """The client's headers with our clearance and its user agent in place of theirs."""
    out = dict(headers)
    if clearance:
        key, agent = clearance
        cookies = [
            c.strip()
            for c in out.get("cookie", "").split(";")
            if c.strip() and not c.strip().startswith("cf_clearance=")
        ]
        if key:
            cookies.append(f"cf_clearance={key}")
        if cookies:
            out["cookie"] = "; ".join(cookies)
        else:
            out.pop("cookie", None)
        out["user-agent"] = agent
    return out


def send(method, url, headers, body):
    # Always https with the certificate checked: that is what stops DNS rebinding (a public name
    # that resolves to a LAN address after `is_internal` looked), since a local service has no
    # valid certificate for the attacker's name. Do not add an http fallback or turn the check off.
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        response = OPENER.open(request, timeout=SITE_TIMEOUT)
        return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()


class Upkeep:
    """Renews the clearances of hosts a reader used in the last `keep_days` before the site stops
    taking them, so a reader in the middle of a chapter does not wait ~15 s for a solve.

    The `cf_clearance` cookie says it lasts a year (TRAWL's answer for bakamh.com and baka1.cfd on
    2026-10-15), but a site set to Cloudflare's default refuses it after 30 minutes. How long it
    really lasts is therefore learned: each refusal notes the clearance's age, and from then on
    the host is renewed at `RENEW_AT` of the shortest of the last `KEEP` ages, never sooner than
    `RENEW_AT` of `MIN_LIFETIME`, so one early refusal (the IP's score dropping) does not open a
    browser every few minutes.

    Every `check_minutes` each host is also loaded once with its clearance (one page, no browser).
    That finds a refusal before the reader meets it, including the first one of a host whose
    lifetime is not known yet. An age found that way can be up to `check_minutes` too long; if
    the reader is then refused before the renewal, that shorter age wins.

    Renewing early means the site never refuses again, so the estimate could only shrink. At
    every `TRIAL_EVERY`th early renewal the old clearance is therefore kept aside: the reader
    gets the new one as usual, and the old one is checked every tenth of the estimate until the
    site refuses it, which notes its real age, or it is `TRIAL_LIMIT` old. A check it passes past
    the estimate drops the shorter ages. A new clearance does not stop the old one working
    (baka2.cfd, 2026-10-16). Before that the clearance the reader used was the one left to run,
    and on 2026-10-16 the reader met its refusal and waited 17.5 s for a page.
    """

    KEEP = 3
    TRIAL_EVERY = 5
    TRIAL_LIMIT = 86400
    MIN_LIFETIME = 600
    RENEW_AT = 0.8
    # The time a host was last used goes to the file at most this often, not on every page.
    SAVE_EVERY = 3600

    def __init__(self, path, clearances, keep_days, check_minutes, allows=None, sender=send, clock=time.time):
        self.path = path
        self.clearances = clearances
        self.keep = keep_days * 86400
        self.check = check_minutes * 60
        self.allows = allows or (lambda host: True)
        self.sender = sender
        self.clock = clock
        self.lock = threading.Lock()
        self.lifetimes = {}
        self.last_used = {}
        self.saved_used = {}
        self.checked_at = {}
        self.next_try = {}
        self.early = {}
        self.trials = {}
        self.noted = {}
        self._load()

    def _load(self):
        """A missing or broken file starts from nothing: it only makes the first renewals later."""
        try:
            with open(self.path, encoding="utf-8") as file:
                data = json.load(file)
            lifetimes, used = data.get("lifetimes") or {}, data.get("last_used") or {}
            for host, ages in lifetimes.items():
                ages = [a for a in ages if isinstance(a, (int, float)) and 0 < a < float("inf")]
                if HOST_NAME.fullmatch(host) and ages:
                    self.lifetimes[host] = ages[-self.KEEP:]
            for host, at in used.items():
                if HOST_NAME.fullmatch(host) and isinstance(at, (int, float)) and math.isfinite(at):
                    self.last_used[host] = at
        except (OSError, ValueError, AttributeError, TypeError) as error:
            if not isinstance(error, FileNotFoundError):
                log(f"cannot read {self.path}, starting without it: {error}")
        self.saved_used = dict(self.last_used)

    def _save(self):
        now = self.clock()
        with self.lock:
            self.last_used = {h: t for h, t in self.last_used.items() if now - t <= self.keep}
            self.lifetimes = {h: a for h, a in self.lifetimes.items() if h in self.last_used}
            self.saved_used = dict(self.last_used)
            temporary = self.path + ".tmp"
            try:
                with open(temporary, "w", encoding="utf-8") as file:
                    json.dump({"lifetimes": self.lifetimes, "last_used": self.last_used}, file)
                os.replace(temporary, self.path)
            except OSError as error:
                log(f"cannot save {self.path}: {error}")

    def lifetime(self, site):
        """How long a clearance for `site` lasts, as far as is known, or None."""
        ages = self.lifetimes.get(site)
        return max(min(ages), self.MIN_LIFETIME) if ages else None

    def used(self, site):
        now = self.clock()
        with self.lock:
            self.last_used[site] = now
            due = now - self.saved_used.get(site, now - self.SAVE_EVERY) >= self.SAVE_EVERY
        if due:
            self._save()

    def refused(self, site, seen):
        """Notes how old `seen` was when the site refused it, unless it was already replaced,
        carried no clearance, or was noted already: the pages and images loading at that moment
        are all refused while the renewal runs, and would otherwise fill every slot with one age."""
        obtained = self.clearances.obtained_at.get(site)
        if not seen or not seen[0] or obtained is None or self.clearances.get(site) is not seen:
            return
        age = self.clock() - obtained
        if age <= 0:
            return  # the clock was set back
        with self.lock:
            if self.noted.get(site) is seen:
                return
            self.noted[site] = seen
            renew_at = self._note(site, age)
        log(f"{site} refused a clearance {age / 60:.0f} min old, renewing it at {renew_at / 60:.0f} min from now on")
        self._save()

    def _note(self, site, age):
        """Adds a refusal at `age` and gives the age renewals happen at from now on. Called
        holding `self.lock`."""
        self.lifetimes[site] = (self.lifetimes.get(site, []) + [age])[-self.KEEP:]
        return self.RENEW_AT * self.lifetime(site)

    def tick(self):
        now = self.clock()
        with self.lock:
            hosts = [h for h, t in self.last_used.items() if now - t <= self.keep]
        # Here rather than in `_save`, which a reader's request also runs: `trials` is only
        # touched by this thread. A host no longer visited would otherwise keep its trial.
        for site in [h for h in self.trials if h not in hosts]:
            del self.trials[site]
        for site in hosts:
            if not self.allows(site):
                continue
            if now >= self.next_try.get(site, 0):
                try:
                    self._keep_warm(site, now)
                except Exception as error:  # noqa: BLE001 - one host failing must not stop the others
                    # Not retried every minute: each try may open a browser.
                    self.next_try[site] = now + self.check
                    log(f"keeping {site} ready failed: {error}")
            # Apart from the renewals: a check that fails does not hold the next renewal back, and
            # a renewal that fails does not stop the checks, or the age noted could be off by a
            # whole `check`.
            try:
                self._check_trial(site, now)
            except Exception as error:  # noqa: BLE001 - the check must not stop the renewals
                log(f"checking the clearance kept aside for {site} failed: {error}")

    def _keep_warm(self, site, now):
        current = self.clearances.get(site)
        # No clearance yet (just restarted, or the warm-up failed): left to the warm-up and the
        # reader's next page, so `WARM_UP=0` still means no browser at start-up.
        if current is None:
            return
        obtained = self.clearances.obtained_at.get(site, now)
        lifetime = self.lifetime(site)
        if current[0] and lifetime and now - obtained >= self.RENEW_AT * lifetime:
            # Counted once the renewal is done, so failed tries do not bring the trial forward.
            count = self.early.get(site, 0) + 1
            log(f"renewing the clearance for {site} before the site stops taking it")
            self.clearances.renew(site, current, pause_on_failure=False)
            self.early[site] = count
            # A reader refused with `current` may have renewed it first; its age is noted already.
            if not count % self.TRIAL_EVERY and site not in self.trials and self.noted.get(site) is not current:
                self.trials[site] = {"clearance": current, "obtained": obtained, "checked": now}
                log(f"keeping the old clearance for {site} to see if it lasts past {lifetime / 60:.0f} min now")
            return
        if now - max(self.checked_at.get(site, 0), obtained) < self.check:
            return
        self.checked_at[site] = now
        status, headers, _ = self.sender("GET", f"https://{site}/", with_clearance({}, current), None)
        if is_challenge(status, headers):
            log(f"{site} no longer takes its clearance, renewing it before the reader's next page")
            self.refused(site, current)
            self.clearances.renew(site, current, pause_on_failure=False)
        else:
            log(f"{site} still takes its clearance, {(now - obtained) / 60:.0f} min old")
            if current[0]:
                self.survived(site, now - obtained)

    def _check_trial(self, site, now):
        """Loads the home page with the clearance kept aside at a trial, every tenth of the
        estimate, so the age noted when the site refuses it is off by that much at most."""
        trial = self.trials.get(site)
        if trial is None:
            return
        age = now - trial["obtained"]
        if age > self.TRIAL_LIMIT:
            # A site that never refuses would otherwise be loaded every few minutes for as long
            # as the cookie says it lasts (a year).
            del self.trials[site]
            log(f"stopped checking the clearance kept aside for {site}, it lasted past {self.TRIAL_LIMIT / 3600:.0f} h")
            return
        if now - trial["checked"] < max(60, (self.lifetime(site) or self.MIN_LIFETIME) / 10):
            return
        trial["checked"] = now
        status, headers, _ = self.sender("GET", f"https://{site}/", with_clearance({}, trial["clearance"]), None)
        if not is_challenge(status, headers):
            self.survived(site, age)
            return
        del self.trials[site]
        with self.lock:
            renew_at = self._note(site, age)
        log(f"{site} refused the clearance kept aside at {age / 60:.0f} min, renewing at {renew_at / 60:.0f} min from now on")
        self._save()

    def survived(self, site, age):
        """The site still took a clearance `age` old, so any shorter age noted before was not how
        long it lasts (an early refusal, or the site now keeps them longer). With none left,
        `age` itself stands in, so a clearance kept past the estimate is still checked every
        tenth of it and the age noted at its refusal stays that close."""
        with self.lock:
            ages = self.lifetimes.get(site)
            if not ages or age <= min(ages):
                return
            self.lifetimes[site] = [a for a in ages if a > age] or [age]
        log(f"{site} still took a clearance {age / 60:.0f} min old, dropping the shorter ages noted before")
        self._save()

    def run(self):
        while True:
            time.sleep(60)
            try:
                self.tick()
            except Exception as error:  # noqa: BLE001 - the loop must outlive any one failure
                log(f"keeping hosts ready failed: {error}")


def make_handler(token, rules, clearances, sender=send, upkeep=None):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "aidoku-cf-relay"

        def version_string(self):
            # Without the Python version, for a relay a reader may expose.
            return self.server_version
        # A client that stops halfway through its headers would otherwise hold a thread forever.
        timeout = 60

        def log_message(self, *args):
            pass

        def refuse(self, status, message):
            """An answer sent before the request body was read: the connection is closed, so
            an unread body is never taken for the next request on it."""
            self.close_connection = True
            self.reply(status, {"Content-Type": "text/plain", "Connection": "close"}, message)

        def handle_request(self):
            started = time.time()
            if self.headers.get("Transfer-Encoding"):
                return self.refuse(411, b"send a Content-Length, not a chunked body")
            if len(self.headers.get_all("Content-Length") or []) > 1:
                return self.refuse(400, b"more than one Content-Length")
            raw_length = (self.headers.get("Content-Length") or "0").strip()
            if not (raw_length.isascii() and raw_length.isdigit()):
                return self.refuse(400, b"bad Content-Length")
            length = int(raw_length)
            if self.path == "/health":
                return self.refuse(200, b"ok") if length else self.reply(200, {"Content-Type": "text/plain"}, b"ok")
            given = self.headers.get("X-Relay-Token") or ""
            if not hmac.compare_digest(given.encode(), token.encode()):
                return self.refuse(401, b"wrong token")
            match = re.match(r"^/r/([^/?#]+)(/[^?#]*)?(\?[^#]*)?$", self.path)
            if not match:
                return self.refuse(404, b"use /r/<host>/<path>")
            host, path, query = match.group(1).lower(), match.group(2) or "/", match.group(3) or ""
            refusal = rules.refusal(host)
            if refusal:
                return self.refuse(403, refusal.encode())
            if length > MAX_BODY:
                return self.refuse(413, b"body too large")
            body = self.rfile.read(length) if length else None
            headers = {k.lower(): v for k, v in self.headers.items() if k.lower() not in DROPPED_REQUEST_HEADERS}
            url = f"https://{host}{path}{query}"
            site = host
            try:
                if clearances.get(site) is None:
                    clearances.renew(site, None)
                used = clearances.get(site)
                status, site_headers, data = sender(self.command, url, with_clearance(headers, used), body)
                if is_challenge(status, site_headers):
                    log(f"challenged on {url}, renewing the clearance")
                    if upkeep:
                        upkeep.refused(site, used)
                    clearances.renew(site, used)
                    status, site_headers, data = sender(
                        self.command, url, with_clearance(headers, clearances.get(site)), body
                    )
                    if is_challenge(status, site_headers):
                        log(f"a fresh clearance for {site} was refused too")
                        clearances.failed(site)
            except Exception as error:  # noqa: BLE001 - any failure is a 502 for the app
                log(f"{self.command} {url} failed: {error}")
                # The detail is only logged: echoed back it would tell a token holder how a host
                # failed (refused, certificate, timeout), a way to probe what answers behind a name.
                return self.reply(502, {"Content-Type": "text/plain"}, b"relay error, see the relay's log")
            if upkeep:
                upkeep.used(site)
            # A list of pairs, so a header the site sends more than once (Vary, Link) keeps every value.
            out = [(k, v) for k, v in site_headers.items() if k.lower() not in DROPPED_RESPONSE_HEADERS]
            if site_headers.get("Location"):
                out.append(("Location", rewrite_location(site_headers.get("Location"), url, rules)))
            if self.command == "HEAD" and site_headers.get("Content-Length"):
                out.append(("Content-Length", site_headers.get("Content-Length")))
            cookies = [rewrite_cookie(c, host) for c in site_headers.get_all("Set-Cookie") or []]
            log(f"{self.command} {url} -> {status} {len(data)} B {time.time() - started:.1f} s")
            self.reply(status, out, data, cookies)

        do_GET = do_POST = do_HEAD = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = handle_request

        def reply(self, status, headers, body, cookies=()):
            """`headers` is a dict or a list of (name, value) pairs."""
            pairs = list(headers.items()) if isinstance(headers, dict) else list(headers)
            self.send_response(status)
            for name, value in pairs:
                self.send_header(name, value)
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
            # A HEAD reply carries the site's length when it sent one, and none otherwise.
            has_length = any(name.lower() == "content-length" for name, _ in pairs)
            if not has_length and self.command != "HEAD":
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

    return Handler


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def start_upkeep(seen_file, clearances, keep_days, check_minutes, allows):
    """The background renewals, kept beside `seen_file`, or None when `keep_days` turns them off."""
    if not keep_days > 0:
        return None
    upkeep = Upkeep(os.path.join(os.path.dirname(seen_file), "clearances.json"), clearances,
                    keep_days, check_minutes, allows=allows)
    threading.Thread(target=upkeep.run, daemon=True).start()
    return upkeep


def main():
    token = os.environ.get("RELAY_TOKEN", "").strip()
    if not token or token == PLACEHOLDER_TOKEN:
        sys.exit("RELAY_TOKEN is not set. Put your own password in .env (see .env.example).")
    if not token.isascii():
        sys.exit("RELAY_TOKEN must be ASCII letters, digits and symbols.")
    port = int(os.environ.get("PORT", "8080"))
    trawl = os.environ.get("TRAWL_URL", "http://trawl:8191")
    rules = HostRules.parse(os.environ.get("ALLOWED_HOSTS", "*"))
    if not rules.patterns:
        sys.exit("ALLOWED_HOSTS is empty. Leave it out to allow every public host, or list patterns.")
    try:
        keep_days = float(os.environ.get("KEEP_WARM_DAYS", "7"))
        check_minutes = float(os.environ.get("CHECK_MINUTES", "30"))
    except ValueError:
        sys.exit("KEEP_WARM_DAYS and CHECK_MINUTES must be numbers.")
    if not check_minutes >= 1:
        sys.exit("CHECK_MINUTES must be at least 1.")
    seen_file = os.environ.get("SEEN_HOSTS_FILE", "/data/hosts.txt")
    seen = SeenHosts(seen_file)
    clearances = Clearances(trawl, on_new=seen.add)
    upkeep = start_upkeep(seen_file, clearances, keep_days, check_minutes, rules.allows)
    handler = make_handler(token, rules, clearances, upkeep=upkeep)
    log(f"listening on :{port}, TRAWL at {trawl}, hosts {rules}")
    if os.environ.get("WARM_UP", "1") != "0":
        hosts = list(reversed(seen.hosts)) + sorted(rules.exact())
        threading.Thread(
            target=clearances.warm_up, args=(hosts,), kwargs={"allows": rules.allows}, daemon=True
        ).start()
    Server(("0.0.0.0", port), handler).serve_forever()


if __name__ == "__main__":
    main()
