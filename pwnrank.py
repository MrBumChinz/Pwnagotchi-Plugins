import logging
import math
import os
import json
import threading

import pwnagotchi
import pwnagotchi.plugins as plugins
import pwnagotchi.ui.fonts as fonts
from pwnagotchi.ui.components import Text
from pwnagotchi.ui.view import BLACK


class PwnRank(plugins.Plugin):
    __author__ = 'Handshakemon'
    __version__ = '1.0.0'
    __license__ = 'MIT'
    __description__ = 'RPG levelling + Pwn Elo competitive ranking for pwnagotchi'

    # Title tiers — checked highest first
    TITLES = [
        (1000, 'Legend'),
        (501,  'Wraith'),
        (251,  'Renegade'),
        (151,  'Shadow'),
        (101,  'Ghost'),
        (76,   'Phantom'),
        (41,   'Specter'),
        (21,   'Scout'),
        (11,   'Wanderer'),
        (6,    'Hatchling'),
        (1,    'Newborn'),
    ]

    DATA_PATH  = '/root/pwnrank.json'

    def __init__(self):
        self.epochs = 0
        self.handshakes = 0
        self.aps_seen = 0
        self._seen_bssids = set()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load(self):
        if os.path.exists(self.DATA_PATH):
            try:
                with open(self.DATA_PATH, 'r') as f:
                    d = json.load(f)
                self.epochs         = d.get('epochs',     0)
                self.handshakes     = d.get('handshakes', 0)
                self.aps_seen       = d.get('aps_seen',   0)
                self._seen_bssids   = set(d.get('seen_bssids', []))
            except Exception as e:
                logging.error(f'[PwnRank] Load failed: {e}')

    def _save(self):
        try:
            with open(self.DATA_PATH, 'w') as f:
                json.dump({
                    'epochs':      self.epochs,
                    'handshakes':  self.handshakes,
                    'aps_seen':    self.aps_seen,
                    'seen_bssids': list(self._seen_bssids),
                }, f)
        except Exception as e:
            logging.error(f'[PwnRank] Save failed: {e}')

    # ------------------------------------------------------------------
    # Core calculations
    # ------------------------------------------------------------------
    def _level(self):
        score = self.epochs + self.handshakes * 10
        lvl = int(20 * math.log(score / 5000.0 + 1)) + 1
        return min(lvl, 1000)

    def _title(self):
        lvl = self._level()
        for threshold, name in self.TITLES:
            if lvl >= threshold:
                return name
        return 'Newborn'

    def _success_rate(self):
        if self.aps_seen == 0:
            return '--'
        return f'{min(100, int(self.handshakes * 100 / self.aps_seen))}%'

    def _xp_bar(self, width=8):
        lvl = self._level()
        if lvl >= 1000:
            return '[' + '#' * width + ']'
        score = self.epochs + self.handshakes * 10
        score_start = 5000 * (math.exp((lvl - 1) / 20.0) - 1)
        score_end   = 5000 * (math.exp(lvl       / 20.0) - 1)
        if score_end <= score_start:
            progress = 1.0
        else:
            progress = max(0.0, min(1.0, (score - score_start) / (score_end - score_start)))
        filled = int(progress * width)
        return '[' + '#' * filled + '-' * (width - filled) + ']'

    def _display_text(self):
        return f'S Rate:{self._success_rate()} {self._xp_bar()}\nLvl:{self._level()} {self._title()}'

    # ------------------------------------------------------------------
    # Plugin lifecycle
    # ------------------------------------------------------------------
    def on_loaded(self):
        self._load()
        logging.info(f'[PwnRank] Loaded — {self._display_text()}')

    def on_epoch(self, agent, epoch, epoch_data):
        with self._lock:
            self.epochs += 1
            if self.epochs % 10 == 0:
                self._save()

    def on_handshake(self, agent, filename, access_point, client_station):
        with self._lock:
            self.handshakes += 1
            self._save()

    def on_unfiltered_ap_list(self, agent, aps):
        with self._lock:
            for ap in aps:
                bssid = ap.get('mac', '')
                if bssid and bssid not in self._seen_bssids:
                    self._seen_bssids.add(bssid)
                    self.aps_seen += 1

    def on_ui_setup(self, ui):
        x = int(self.options.get('x', 0))
        y = int(self.options.get('y', 113))
        ui.add_element('pwnrank', Text(
            color=BLACK,
            value=self._display_text(),
            position=(x, y),
            font=fonts.Small,
        ))

    def on_ui_update(self, ui):
        ui.set('pwnrank', self._display_text())

    def on_unload(self, ui):
        with self._lock:
            self._save()
        with ui._lock:
            ui.remove_element('pwnrank')
        logging.info('[PwnRank] Unloaded and saved.')
