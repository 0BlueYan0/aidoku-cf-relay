import email.message
import sys
import threading
import unittest
import urllib.error
import urllib.request

import relay


def headers(**values):
    message = email.message.Message()
    for name, value in values.items():
        name = name.replace("_", "-")
        for item in value if isinstance(value, list) else [value]:
            message[name] = item
    return message


def rules(*patterns, addresses=None):
    """HostRules without DNS: `addresses` maps a host to what it should resolve to; any other host
    resolves to a public address."""
    table = addresses or {}
    return relay.HostRules(patterns, resolver=lambda host: table.get(host, {"104.16.0.1"}))


class Site:
    """A fake site: challenges requests without the expected clearance."""

    def __init__(self):
        self.valid = "key-1"
        self.calls = []

    def __call__(self, method, url, sent, body):
        self.calls.append((method, url, dict(sent), body))
        if f"cf_clearance={self.valid}" not in sent.get("cookie", ""):
            return 403, headers(cf_mitigated="challenge", content_type="text/html"), b"challenge"
        if url.endswith("/login"):
            return 302, headers(
                location="https://bakamh.com/home",
                set_cookie=["wordpress_logged_in_x=abc; path=/; domain=.bakamh.com; secure; HttpOnly"],
            ), b""
        return 200, headers(content_type="text/html"), b"<html>page</html>"


class RelayTest(unittest.TestCase):
    def setUp(self):
        self.site = Site()
        self.solves = []

        def fetch_clearance(site):
            self.solves.append(site)
            return self.site.valid, "Firefox/152"

        self.clearances = relay.Clearances("http://trawl", fetch_clearance)
        handler = relay.make_handler("secret", rules("bakamh.com", "18mh.org"), self.clearances, self.site)
        self.server = relay.Server(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def get(self, path, token="secret", data=None, extra=None):
        request = urllib.request.Request(self.base + path, data=data, headers={"X-Relay-Token": token, **(extra or {})})
        opener = urllib.request.build_opener(relay.NoRedirect)
        try:
            response = opener.open(request, timeout=10)
            return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read()

    def test_forwards_with_one_clearance(self):
        for _ in range(3):
            status, _, body = self.get("/r/bakamh.com/manga/x/?a=1")
            self.assertEqual((status, body), (200, b"<html>page</html>"))
        self.assertEqual(self.solves, ["bakamh.com"])
        method, url, sent, _ = self.site.calls[0]
        self.assertEqual(url, "https://bakamh.com/manga/x/?a=1")
        self.assertEqual(sent["user-agent"], "Firefox/152")

    def test_renews_once_when_refused(self):
        self.get("/r/bakamh.com/")
        self.site.valid = "key-2"
        status, _, _ = self.get("/r/bakamh.com/")
        self.assertEqual(status, 200)
        self.assertEqual(self.solves, ["bakamh.com", "bakamh.com"])

    def test_does_not_renew_a_clearance_already_replaced(self):
        self.clearances.renew("bakamh.com", None)
        seen = self.clearances.get("bakamh.com")
        self.clearances.renew("bakamh.com", seen)
        self.clearances.renew("bakamh.com", seen)
        self.assertEqual(len(self.solves), 2)

    def test_needs_the_token(self):
        self.assertEqual(self.get("/r/bakamh.com/", token="wrong")[0], 401)
        self.assertEqual(self.get("/health", token="")[0], 200)

    def test_refuses_other_hosts(self):
        self.assertEqual(self.get("/r/example.com/")[0], 403)
        self.assertEqual(self.site.calls, [])

    def test_rewrites_cookies_and_redirects(self):
        status, response, _ = self.get("/r/bakamh.com/login", data=b"a=1", extra={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 302)
        self.assertEqual(response["Location"], "/r/bakamh.com/home")
        self.assertEqual(
            response["Set-Cookie"], "wordpress_logged_in_x=abc; HttpOnly; Path=/r/bakamh.com/"
        )
        _, _, sent, body = self.site.calls[-1]
        self.assertEqual(body, b"a=1")
        self.assertEqual(sent["content-type"], "application/x-www-form-urlencoded")

    def test_keeps_client_cookies_and_replaces_its_clearance(self):
        self.get("/r/bakamh.com/", extra={"Cookie": "cf_clearance=old; wordpress_logged_in_x=abc"})
        sent = self.site.calls[-1][2]
        self.assertEqual(sent["cookie"], "wordpress_logged_in_x=abc; cf_clearance=key-1")

    def test_closes_the_connection_when_refusing_before_the_body(self):
        import socket

        port = self.server.server_address[1]
        smuggled = b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n"
        raw = (
            b"POST /r/bakamh.com/x HTTP/1.1\r\nHost: x\r\nX-Relay-Token: wrong\r\n"
            + f"Content-Length: {len(smuggled)}\r\n\r\n".encode()
            + smuggled
        )
        with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
            conn.sendall(raw)
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        self.assertEqual(data.count(b"HTTP/1.1 "), 1)
        self.assertIn(b"401", data.split(b"\r\n", 1)[0])

    def test_rejects_bad_lengths_and_chunked_bodies(self):
        import http.client

        port = self.server.server_address[1]
        for name, value, expected in [("Content-Length", "-1", 400), ("Content-Length", "abc", 400), ("Transfer-Encoding", "chunked", 411)]:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.putrequest("POST", "/r/bakamh.com/x", skip_accept_encoding=True)
            conn.putheader("X-Relay-Token", "secret")
            conn.putheader(name, value)
            conn.endheaders()
            self.assertEqual(conn.getresponse().status, expected, (name, value))
            conn.close()

    def test_rewrites_every_location_form(self):
        url = "https://bakamh.com/a/b?q=1"
        allowed = rules("bakamh.com", "baka1.cfd")
        self.assertEqual(relay.rewrite_location("https://bakamh.com/x?y=1", url, allowed), "/r/bakamh.com/x?y=1")
        self.assertEqual(relay.rewrite_location("//baka1.cfd/x", url, allowed), "/r/baka1.cfd/x")
        self.assertEqual(relay.rewrite_location("/x", url, allowed), "/r/bakamh.com/x")
        self.assertEqual(relay.rewrite_location("c", url, allowed), "/r/bakamh.com/a/c")
        self.assertEqual(relay.rewrite_location("https://BakaMH.com", url, allowed), "/r/bakamh.com/")
        # Off the allow-list, or not https: passed on as an absolute URL for the app to follow directly.
        self.assertEqual(relay.rewrite_location("https://example.com/x", url, allowed), "https://example.com/x")
        self.assertEqual(relay.rewrite_location("http://bakamh.com/x", url, allowed), "http://bakamh.com/x")

    def test_forwards_other_headers_and_methods(self):
        status, response, _ = self.get(
            "/r/bakamh.com/api", extra={"Authorization": "Bearer t", "Origin": "https://bakamh.com", "User-Agent": "client"}
        )
        self.assertEqual(status, 200)
        sent = self.site.calls[-1][2]
        self.assertEqual(sent["authorization"], "Bearer t")
        self.assertEqual(sent["origin"], "https://bakamh.com")
        self.assertEqual(sent["user-agent"], "Firefox/152")
        self.assertNotIn("x-relay-token", sent)
        request = urllib.request.Request(self.base + "/r/bakamh.com/x", data=b"{}", method="PUT", headers={"X-Relay-Token": "secret"})
        self.assertEqual(urllib.request.urlopen(request, timeout=5).status, 200)
        self.assertEqual(self.site.calls[-1][0], "PUT")

    def test_passes_response_headers_but_not_hsts(self):
        def site(method, url, sent, body):
            return 200, headers(content_type="application/json", x_custom="1", strict_transport_security="max-age=1", alt_svc='h3=":443"'), b"{}"

        handler = relay.make_handler("secret", rules("bakamh.com"), self.clearances, site)
        server = relay.Server(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            request = urllib.request.Request(f"http://127.0.0.1:{server.server_address[1]}/r/bakamh.com/", headers={"X-Relay-Token": "secret"})
            response = urllib.request.urlopen(request, timeout=5)
            self.assertEqual(response.headers["X-Custom"], "1")
            self.assertIsNone(response.headers["Strict-Transport-Security"])
            self.assertIsNone(response.headers["Alt-Svc"])
        finally:
            server.shutdown()
            server.server_close()

    def test_keeps_repeated_headers_and_sends_one_date(self):
        def site(method, url, sent, body):
            return 200, headers(vary=["Accept", "Cookie"], date="Thu, 01 Jan 1970 00:00:00 GMT", server="cloudflare"), b"ok"

        handler = relay.make_handler("secret", rules("bakamh.com"), self.clearances, site)
        server = relay.Server(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            request = urllib.request.Request(f"http://127.0.0.1:{server.server_address[1]}/r/bakamh.com/", headers={"X-Relay-Token": "secret"})
            response = urllib.request.urlopen(request, timeout=5)
            self.assertEqual(response.headers.get_all("Vary"), ["Accept", "Cookie"])
            self.assertEqual(len(response.headers.get_all("Date")), 1)
            self.assertEqual(response.headers.get_all("Server"), ["aidoku-cf-relay"])
        finally:
            server.shutdown()
            server.server_close()

    def test_keeps_separate_clearances_under_a_public_suffix(self):
        solved = []
        clearances = relay.Clearances("http://trawl", lambda site: (solved.append(site), ("k", "UA"))[1])
        clearances.renew("a.example.co.uk", None)
        clearances.renew("b.example.co.uk", None)
        self.assertEqual(solved, ["a.example.co.uk", "b.example.co.uk"])

    def test_matches_wildcards(self):
        r = rules("*.example.com", "exact.org")
        self.assertTrue(r.allows("a.example.com"))
        self.assertTrue(r.allows("A.B.Example.com"))
        self.assertFalse(r.allows("example.com"))
        self.assertTrue(r.allows("exact.org"))
        self.assertFalse(r.allows("other.org"))
        self.assertTrue(rules("*").allows("anything.example"))
        self.assertEqual(r.exact(), {"exact.org"})

    def test_always_refuses_the_local_network(self):
        everything = rules("*", addresses={"nas.example.com": {"192.168.0.10"}, "site.example.com": {"104.16.0.1"}})
        for host in ["127.0.0.1", "192.168.0.10", "[::1]", "localhost", "trawl", "nas.local", "router.lan",
                     "box.home.arpa", "printer.internal", "example.com:8443", "nas.example.com"]:
            self.assertFalse(everything.allows(host), host)
        self.assertTrue(everything.allows("site.example.com"))

    def test_refuses_names_a_browser_reads_differently(self):
        everything = rules("*", addresses={"nowhere.example": set(), "v6.example.com": {"64:ff9b::a00:1"},
                                           "six.example.com": {"2002:7f00:1::1"}, "mixed.example.com": {"104.16.0.1", "10.0.0.1"}})
        for host in ["a@127.0.0.1", "x@trawl.", "localhost.", "127.0.0.1.", "example.com.", "a_b.example.com",
                     "a%2e.example.com", "nowhere.example", "v6.example.com", "six.example.com", "mixed.example.com"]:
            self.assertFalse(everything.allows(host), host)

    def test_refuses_numeric_last_labels_and_local_ipv6(self):
        everything = rules("*", addresses={"site.example.com": {"fec0::1"}, "nat.example.com": {"64:ff9b:1::1"}})
        for host in ["1.2.3", "127.1", "1.1", "site.example.com", "nat.example.com"]:
            self.assertFalse(everything.allows(host), host)
        self.assertTrue(everything.allows("a1.example.com"))

    def test_survives_a_hosts_file_that_is_not_utf8(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "hosts.txt")
            with open(path, "wb") as file:
                file.write(b"ok.example.com" + bytes([10, 0xFF, 0xFE, 0]) + b"junk" + bytes([10]))
            self.assertEqual(relay.SeenHosts(path).hosts, ["ok.example.com"])

    def test_does_not_remember_hosts_without_a_challenge(self):
        remembered = []
        clearances = relay.Clearances("http://trawl", lambda site: (None, "UA"), on_new=remembered.append)
        clearances.renew("plain.example.com", None)
        self.assertEqual(remembered, [])

    def test_warm_up_goes_most_recent_first_and_filters_late(self):
        solved = []
        clearances = relay.Clearances("http://trawl", lambda site: (solved.append(site), ("k", "UA"))[1])
        clearances.warm_up(["z.example.com", "a.example.com", "bad.example.com"], trawl_ready=lambda: True,
                           allows=lambda host: host != "bad.example.com")
        self.assertEqual(solved, ["z.example.com", "a.example.com"])

    def test_waits_for_trawl_then_fails_fast_until_it_answers(self):
        now = [0.0]
        answers = iter([False] * 100)
        state = {"up": False}

        def ready():
            return state["up"] or next(answers)

        clearances = relay.Clearances("http://trawl", lambda site: ("k", "UA"), clock=lambda: now[0], trawl_ready=ready)
        real_sleep, real_time = relay.time.sleep, relay.time.time
        fake = [0.0]
        relay.time.sleep = lambda seconds: fake.__setitem__(0, fake[0] + seconds)
        relay.time.time = lambda: fake[0]
        try:
            with self.assertRaises(relay.TrawlDown):
                clearances.renew("a.example.com", None)
            self.assertNotIn("a.example.com", clearances.failed_at)
            with self.assertRaises(relay.TrawlDown):
                clearances.renew("a.example.com", None)
            state["up"] = True
            clearances.renew("a.example.com", None)
        finally:
            relay.time.sleep, relay.time.time = real_sleep, real_time
        self.assertEqual(clearances.get("a.example.com"), ("k", "UA"))

    def test_caches_the_local_network_check(self):
        lookups = []
        now = [0.0]

        def resolver(host):
            lookups.append(host)
            return {"104.16.0.1"}

        r = relay.HostRules(["*"], resolver=resolver, clock=lambda: now[0])
        for _ in range(3):
            self.assertTrue(r.allows("site.example.com"))
        self.assertEqual(len(lookups), 1)
        now[0] += relay.HostRules.CACHE_SECONDS
        r.allows("site.example.com")
        self.assertEqual(len(lookups), 2)
        self.assertFalse(rules("*", addresses={"m.example.com": {"224.0.0.1"}}).allows("m.example.com"))

    def test_matches_only_star_as_a_wildcard(self):
        r = rules("a?c.example.com", "b[x].example.com")
        self.assertFalse(r.allows("abc.example.com"))
        self.assertTrue(r.allows("a?c.example.com") is False)
        self.assertEqual(r.exact(), {"a?c.example.com", "b[x].example.com"})

    def test_keeps_the_most_recently_used_hosts_and_skips_junk(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "hosts.txt")
            with open(path, "w", encoding="utf-8") as file:
                file.write("".join(line + chr(10) for line in ["a@127.0.0.1", "example.com.", "ok.example.com"]))
            seen = relay.SeenHosts(path)
            self.assertEqual(seen.hosts, ["ok.example.com"])
            seen.add("x@trawl.")
            for i in range(relay.SeenHosts.LIMIT):
                seen.add(f"h{i}.example.com")
                seen.add("ok.example.com")
            self.assertIn("ok.example.com", relay.SeenHosts(path).hosts)
            self.assertNotIn("x@trawl.", relay.SeenHosts(path).hosts)

    def test_refuses_a_local_host_through_the_relay(self):
        handler = relay.make_handler("secret", rules("*"), self.clearances, self.site)
        server = relay.Server(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            for host in ("192.168.0.1", "trawl", "localhost"):
                request = urllib.request.Request(f"http://127.0.0.1:{server.server_address[1]}/r/{host}/", headers={"X-Relay-Token": "secret"})
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(request, timeout=5)
                self.assertEqual(caught.exception.code, 403, host)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(self.site.calls, [])

    def test_remembers_hosts_for_the_next_start(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "hosts.txt")
            seen = relay.SeenHosts(path)
            clearances = relay.Clearances("http://trawl", lambda site: ("k", "UA"), on_new=seen.add)
            clearances.renew("a.example.com", None)
            clearances.renew("b.example.com", None)
            clearances.renew("a.example.com", clearances.get("a.example.com"))
            # a.example.com was renewed last, so it moves to the end (most recently used).
            self.assertEqual(relay.SeenHosts(path).hosts, ["b.example.com", "a.example.com"])
            for i in range(relay.SeenHosts.LIMIT + 5):
                seen.add(f"h{i}.example.com")
            self.assertEqual(len(relay.SeenHosts(path).hosts), relay.SeenHosts.LIMIT)

    def test_forwards_without_a_clearance_when_none_was_issued(self):
        sent = relay.with_clearance({"cookie": "a=1"}, (None, "UA"))
        self.assertEqual(sent, {"cookie": "a=1", "user-agent": "UA"})
        sent = relay.with_clearance({"cookie": "cf_clearance=old"}, (None, "UA"))
        self.assertEqual(sent, {"user-agent": "UA"})

    def test_pauses_after_a_failed_renewal(self):
        now = [1000.0]
        calls = []

        def broken(site):
            calls.append(site)
            raise RuntimeError("TRAWL down")

        clearances = relay.Clearances("http://trawl", broken, clock=lambda: now[0])
        for _ in range(3):
            with self.assertRaises(RuntimeError):
                clearances.renew("bakamh.com", None)
        self.assertEqual(len(calls), 1)
        now[0] += relay.Clearances.PAUSE
        with self.assertRaises(RuntimeError):
            clearances.renew("bakamh.com", None)
        self.assertEqual(len(calls), 2)

    def test_warm_up_waits_for_trawl_and_survives_failures(self):
        solved = []
        ready = iter([False, False, True])

        def fetch(site):
            solved.append(site)
            if site == "baka1.cfd":
                raise RuntimeError("no clearance")
            return "k", "UA"

        clearances = relay.Clearances("http://trawl", fetch)
        real_sleep = relay.time.sleep
        relay.time.sleep = lambda seconds: None
        try:
            clearances.warm_up({"bakamh.com", "baka1.cfd", "18mh.org"}, trawl_ready=lambda: next(ready))
        finally:
            relay.time.sleep = real_sleep
        self.assertEqual(solved, ["18mh.org", "baka1.cfd", "bakamh.com"])
        self.assertIsNotNone(clearances.get("bakamh.com"))
        # A site that failed during the warm-up is not paused for the reader.
        self.assertNotIn("baka1.cfd", clearances.failed_at)

    def test_warm_up_solves_a_host_a_reader_request_failed_on(self):
        attempts = []

        def fetch(site):
            attempts.append(site)
            if len(attempts) == 1:
                raise RuntimeError("TRAWL still starting")
            return "k", "UA"

        clearances = relay.Clearances("http://trawl", fetch)
        with self.assertRaises(RuntimeError):
            clearances.renew("a.com", None)
        clearances.warm_up({"a.com"}, trawl_ready=lambda: True)
        self.assertEqual(clearances.get("a.com"), ("k", "UA"))

    def test_splits_client_cookies_without_spaces(self):
        sent = relay.with_clearance({"cookie": "cf_clearance=old;a=1"}, ("new", "UA"))
        self.assertEqual(sent["cookie"], "a=1; cf_clearance=new")

    def test_rewrites_cookie_attributes(self):
        self.assertEqual(
            relay.rewrite_cookie("a=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0", "bakamh.com"),
            "a=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/r/bakamh.com/",
        )
        self.assertEqual(relay.rewrite_cookie("a=1", "18mh.org"), "a=1; Path=/r/18mh.org/")
        self.assertEqual(relay.rewrite_cookie("a=1; path=wp", "bakamh.com"), "a=1; Path=/r/bakamh.com/wp")

    def test_passes_every_set_cookie(self):
        def site(method, url, sent, body):
            return 200, headers(set_cookie=["a=1; path=/", "b=2; path=/x"]), b"ok"

        handler = relay.make_handler("secret", rules("bakamh.com"), self.clearances, site)
        server = relay.Server(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            request = urllib.request.Request(f"http://127.0.0.1:{server.server_address[1]}/r/bakamh.com/", headers={"X-Relay-Token": "secret"})
            response = urllib.request.urlopen(request, timeout=5)
            self.assertEqual(response.headers.get_all("Set-Cookie"), ["a=1; Path=/r/bakamh.com/", "b=2; Path=/r/bakamh.com/x"])
        finally:
            server.shutdown()
            server.server_close()

    def test_rejects_non_ascii_and_repeated_lengths(self):
        import socket

        port = self.server.server_address[1]
        crlf = b"\r\n"
        for extra in [b"Content-Length: \xb2" + crlf, b"Content-Length: 1" + crlf + b"Content-Length: 1" + crlf]:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
                head = b"POST /r/bakamh.com/ HTTP/1.1" + crlf + b"Host: x" + crlf + b"X-Relay-Token: secret" + crlf
                conn.sendall(head + extra + crlf + b"x")
                self.assertIn(b" 400 ", conn.recv(4096).split(crlf, 1)[0])

    def test_keeps_one_clearance_per_host(self):
        handler = relay.make_handler("secret", rules("bakamh.com", "www.bakamh.com"), self.clearances, self.site)
        server = relay.Server(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            for host in ("bakamh.com", "www.bakamh.com", "bakamh.com"):
                request = urllib.request.Request(
                    f"http://127.0.0.1:{server.server_address[1]}/r/{host}/", headers={"X-Relay-Token": "secret"}
                )
                urllib.request.urlopen(request, timeout=5)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(self.solves, ["bakamh.com", "www.bakamh.com"])

    def test_refuses_to_start_without_a_host_list_or_token(self):
        import os
        import subprocess

        base = {k: v for k, v in os.environ.items() if k not in ("RELAY_TOKEN", "ALLOWED_HOSTS")}
        for extra, message in [
            ({"ALLOWED_HOSTS": "example.com"}, "RELAY_TOKEN"),
            ({"RELAY_TOKEN": relay.PLACEHOLDER_TOKEN, "ALLOWED_HOSTS": "example.com"}, "RELAY_TOKEN"),
            ({"RELAY_TOKEN": "secret", "ALLOWED_HOSTS": " , "}, "ALLOWED_HOSTS"),
            ({"RELAY_TOKEN": "secret", "CHECK_MINUTES": "0"}, "CHECK_MINUTES"),
            ({"RELAY_TOKEN": "secret", "KEEP_WARM_DAYS": "a week"}, "KEEP_WARM_DAYS"),
        ]:
            result = subprocess.run(
                [sys.executable, relay.__file__], env={**base, **extra, "PORT": "0"},
                capture_output=True, text=True, timeout=20,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(message, result.stderr)


class UpkeepTest(unittest.TestCase):
    """Clearances and Upkeep on one fake clock, against the fake Site."""

    def setUp(self):
        import os
        import tempfile

        self.folder = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.folder.name, "clearances.json")
        self.now = [1000.0]
        self.site = Site()
        self.solves = []
        self.clearances = relay.Clearances("http://trawl", self.fetch, clock=self.clock)
        self.upkeep = self.make()

    def tearDown(self):
        self.folder.cleanup()

    def clock(self):
        return self.now[0]

    def fetch(self, site):
        self.solves.append(site)
        return self.site.valid, "Firefox/152"

    def make(self, keep_days=7, check_minutes=30):
        return relay.Upkeep(self.path, self.clearances, keep_days, check_minutes, sender=self.site, clock=self.clock)

    def start(self, site="bakamh.com"):
        """A clearance obtained now for a host the reader used now."""
        self.clearances.renew(site, None)
        self.upkeep.used(site)

    def test_learns_the_lifetime_when_the_reader_is_refused(self):
        handler = relay.make_handler("secret", rules("bakamh.com"), self.clearances, self.site, upkeep=self.upkeep)
        server = relay.Server(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/r/bakamh.com/"
            fetch = lambda: urllib.request.urlopen(urllib.request.Request(url, headers={"X-Relay-Token": "secret"}), timeout=5)
            fetch()
            self.assertEqual(self.upkeep.last_used, {"bakamh.com": 1000.0})
            self.now[0] += 1800
            self.site.valid = "key-2"
            self.assertEqual(fetch().status, 200)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(self.upkeep.lifetimes, {"bakamh.com": [1800.0]})
        self.assertEqual(self.solves, ["bakamh.com", "bakamh.com"])

    def test_keeps_the_shortest_of_the_last_ages_above_a_floor(self):
        self.start()
        for age in (3000, 2000, 2500, 2600):
            self.clearances.renew("bakamh.com", self.clearances.get("bakamh.com"))
            self.clearances.obtained_at["bakamh.com"] = self.now[0] - age
            self.upkeep.refused("bakamh.com", self.clearances.get("bakamh.com"))
        # 3000 dropped out, so the shortest of the last three is 2000.
        self.assertEqual(self.upkeep.lifetime("bakamh.com"), 2000)
        self.clearances.renew("bakamh.com", self.clearances.get("bakamh.com"))
        self.clearances.obtained_at["bakamh.com"] = self.now[0] - 60
        self.upkeep.refused("bakamh.com", self.clearances.get("bakamh.com"))
        self.assertEqual(self.upkeep.lifetime("bakamh.com"), relay.Upkeep.MIN_LIFETIME)

    def test_does_not_learn_from_a_replaced_or_missing_clearance(self):
        self.start()
        old = self.clearances.get("bakamh.com")
        self.clearances.renew("bakamh.com", old)
        self.upkeep.refused("bakamh.com", old)
        self.upkeep.refused("bakamh.com", (None, "UA"))
        self.assertEqual(self.upkeep.lifetimes, {})

    def test_renews_before_the_learned_lifetime(self):
        self.upkeep.lifetimes["bakamh.com"] = [1800]
        self.start()
        self.now[0] += 1439
        self.upkeep.tick()
        self.assertEqual(self.solves, ["bakamh.com"])
        self.now[0] += 1
        self.upkeep.tick()
        self.assertEqual(self.solves, ["bakamh.com", "bakamh.com"])
        # Renewed without loading a page first.
        self.assertEqual(self.site.calls, [])

    def test_checks_a_host_without_a_known_lifetime(self):
        self.start()
        self.now[0] += 1799
        self.upkeep.tick()
        self.assertEqual(self.site.calls, [])
        self.now[0] += 1
        self.upkeep.tick()
        self.assertEqual(len(self.site.calls), 1)
        method, url, sent, _ = self.site.calls[0]
        self.assertEqual((method, url, sent["cookie"]), ("GET", "https://bakamh.com/", "cf_clearance=key-1"))
        self.assertEqual(self.solves, ["bakamh.com"])
        self.site.valid = "key-2"
        self.now[0] += 1800
        self.upkeep.tick()
        self.assertEqual(self.solves, ["bakamh.com", "bakamh.com"])
        self.assertEqual(self.upkeep.lifetimes, {"bakamh.com": [3600.0]})

    def test_leaves_hosts_alone_after_the_window(self):
        self.upkeep.lifetimes["bakamh.com"] = [1800]
        self.start()
        self.now[0] += 7 * 86400 + 1
        self.upkeep.tick()
        self.assertEqual((self.solves, self.site.calls), (["bakamh.com"], []))

    def test_backs_off_a_host_that_fails_and_goes_on(self):
        for site in ("bakamh.com", "18mh.org"):
            self.upkeep.lifetimes[site] = [1800]
            self.start(site)
        self.solves.clear()

        def broken(site):
            self.solves.append(site)
            raise RuntimeError("TRAWL down")

        self.clearances.fetch_clearance = broken
        self.now[0] += 1440
        self.upkeep.tick()
        self.assertEqual(sorted(self.solves), ["18mh.org", "bakamh.com"])
        self.now[0] += 60
        self.upkeep.tick()
        self.assertEqual(len(self.solves), 2)
        # The reader is not paused by a failure in the background.
        self.assertEqual(self.clearances.failed_at, {})

    def test_lets_every_fifth_clearance_run_to_learn_a_longer_lifetime(self):
        self.upkeep.lifetimes["bakamh.com"] = [1000]
        self.start()
        for _ in range(relay.Upkeep.TRIAL_EVERY - 1):
            self.now[0] += 800
            self.upkeep.tick()
        self.assertEqual(len(self.solves), relay.Upkeep.TRIAL_EVERY)
        self.now[0] += 800
        self.upkeep.tick()
        self.now[0] += 1000
        self.upkeep.tick()
        # Not renewed early; the check at 1800 s passed, so that is the estimate now.
        self.assertEqual(len(self.solves), relay.Upkeep.TRIAL_EVERY)
        self.assertEqual(len(self.site.calls), 1)
        self.assertEqual(self.upkeep.lifetimes, {"bakamh.com": [1800.0]})

    def test_keeps_checking_often_after_a_kept_clearance_passes(self):
        self.upkeep.lifetimes["bakamh.com"] = [1000]
        self.start()
        self.upkeep.early["bakamh.com"] = relay.Upkeep.TRIAL_EVERY - 1
        self.now[0] += 1000
        self.upkeep.tick()
        self.assertEqual(len(self.site.calls), 1)
        self.now[0] += 500
        self.upkeep.tick()
        self.assertEqual(self.upkeep.lifetimes, {"bakamh.com": [1500.0]})
        # Still checked every tenth of the estimate, not every 30 min.
        self.now[0] += 150
        self.upkeep.tick()
        self.assertEqual(len(self.site.calls), 3)
        self.site.valid = "key-2"
        self.now[0] += 165
        self.upkeep.tick()
        self.assertEqual(self.upkeep.lifetimes, {"bakamh.com": [1650.0, 1815.0]})

    def test_a_failed_renewal_does_not_count_toward_the_trial(self):
        self.upkeep.lifetimes["bakamh.com"] = [1000]
        self.start()
        self.clearances.fetch_clearance = lambda site: (_ for _ in ()).throw(RuntimeError("TRAWL down"))
        self.now[0] += 800
        self.upkeep.tick()
        self.assertEqual(self.upkeep.early, {})

    def test_notes_one_refused_clearance_once(self):
        self.start()
        self.upkeep.lifetimes["bakamh.com"] = [900, 1200]
        self.now[0] += 1800
        seen = self.clearances.get("bakamh.com")
        threads = [threading.Thread(target=self.upkeep.refused, args=("bakamh.com", seen)) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(self.upkeep.lifetimes, {"bakamh.com": [900, 1200, 1800.0]})

    def test_skips_hosts_no_longer_allowed(self):
        self.upkeep.allows = lambda host: False
        self.start()
        self.now[0] += 3600
        self.upkeep.tick()
        self.assertEqual(self.site.calls, [])

    def test_checks_a_kept_clearance_more_often_past_the_estimate(self):
        self.upkeep.lifetimes["bakamh.com"] = [1000]
        self.start()
        self.upkeep.early["bakamh.com"] = relay.Upkeep.TRIAL_EVERY - 1
        self.now[0] += 800
        self.upkeep.tick()
        self.assertEqual(len(self.solves), 1)
        self.now[0] += 200
        self.upkeep.tick()
        # Past the estimate: checked every 100 s, not every 30 min.
        self.assertEqual(len(self.site.calls), 1)
        self.now[0] += 99
        self.upkeep.tick()
        self.assertEqual(len(self.site.calls), 1)
        self.now[0] += 1
        self.upkeep.tick()
        self.assertEqual(len(self.site.calls), 2)

    def test_a_passed_check_drops_only_shorter_ages(self):
        self.start()
        self.upkeep.lifetimes["bakamh.com"] = [700, 2400, 3000]
        self.upkeep.survived("bakamh.com", 1800)
        self.assertEqual(self.upkeep.lifetimes, {"bakamh.com": [2400, 3000]})

    def test_leaves_a_host_without_a_clearance_to_the_warm_up(self):
        # Just restarted: used last week, no clearance in memory yet.
        self.upkeep.used("bakamh.com")
        self.upkeep.lifetimes["bakamh.com"] = [1800]
        self.now[0] += 3600
        self.upkeep.tick()
        self.assertEqual((self.solves, self.site.calls), ([], []))

    def test_ignores_an_age_from_a_clock_set_back(self):
        self.start()
        self.now[0] -= 100
        self.upkeep.refused("bakamh.com", self.clearances.get("bakamh.com"))
        self.assertEqual(self.upkeep.lifetimes, {})

    def test_keep_warm_days_zero_turns_it_off(self):
        import os

        seen_file = os.path.join(self.folder.name, "hosts.txt")
        self.assertIsNone(relay.start_upkeep(seen_file, self.clearances, 0, 30, lambda host: True))
        upkeep = relay.start_upkeep(seen_file, self.clearances, 7, 30, lambda host: True)
        self.assertEqual(upkeep.path, self.path)

    def test_remembers_lifetimes_and_use_across_a_restart(self):
        self.start()
        self.clearances.obtained_at["bakamh.com"] = self.now[0] - 1800
        self.upkeep.refused("bakamh.com", self.clearances.get("bakamh.com"))
        again = self.make()
        self.assertEqual(again.lifetimes, {"bakamh.com": [1800.0]})
        self.assertEqual(again.last_used, {"bakamh.com": 1000.0})

    def test_starts_from_nothing_with_a_broken_file(self):
        for content in ("not json", "[1, 2]", '{"lifetimes": {"a@b": [1], "ok.com": ["x", -1]}, "last_used": {"ok.com": "x"}}'):
            with open(self.path, "w", encoding="utf-8") as file:
                file.write(content)
            upkeep = self.make()
            self.assertEqual((upkeep.lifetimes, upkeep.last_used), ({}, {}), content)


if __name__ == "__main__":
    unittest.main()
