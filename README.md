# Pwnagotchi Plugins by MrBumChinz

A collection of custom plugins for [Pwnagotchi](https://pwnagotchi.ai/).  
All plugins are available via [PwnStore](https://wpa-2.github.io/pwnagotchi-store/).

---

## Plugins

### 🏆 pwnrank

RPG levelling system — tracks your handshake success rate and assigns a rank title as you level up.

- Tracks lifetime unique APs seen and handshakes captured
- Displays **success rate** (handshakes / unique APs seen)
- RPG-style level progression with rank titles (Newborn → Legend)
- Persistent stats saved to `/root/pwnrank.json`
- Two-line e-ink display with configurable position

```
Rate: 42%
Lvl: 3 Specter
```

**Install:**
```bash
sudo pwnstore install pwnrank
```

**Config:**
```toml
[main.plugins.pwnrank]
enabled = true
x = 126
y = 62
```

---

### 🌐 community_quickdic

On-device WPA cracker with a **federated community ISP password pool**.

- Runs `aircrack-ng` against all `.txt` wordlists on every captured handshake
- Pulls a shared community wordlist hourly (public Gist, no account needed)
- Optionally contribute your ISP router's factory-default password to the pool
- ISP router default passwords combined with hashcat mutation rules = targeted attack surface

> **Privacy:** Only the raw password string is ever uploaded. SSIDs stay local.  
> Only contribute your ISP's **factory-default** sticker password — never your personal password.

**Install:**
```bash
sudo pwnstore install community_quickdic
```

**Config:**
```toml
[main.plugins.community_quickdic]
enabled = true
wordlist_folder = "/home/pi/wordlists/"
root_gist_id = "f5d5e3b858e30c6279507cfd019758f0"
sync_interval = 3600
github_token = ""   # leave blank for read-only
my_gist_id = ""     # auto-set on first run
```

---

### 👿 evil_twin

Automatically launches an **evil twin AP + captive portal** on every captured WPA handshake.

Instead of cracking offline, it:
1. Deauths clients from the real network (`aireplay-ng` on `wlan1mon`)
2. Spins up a rogue open AP with the same SSID (`hostapd` on `wlan0`)
3. Serves a fake "WiFi reconnection" captive portal to any device that connects
4. Verifies the entered password against the handshake in real time using `aircrack-ng` — wrong guesses are re-prompted
5. Saves the plaintext password locally and optionally submits it to the community-quickdic pool

**Requirements:**
- External WiFi adapter with monitor mode + injection (tested with ALFA AWUS036AC / RTL8812AU)
- `sudo apt install -y hostapd dnsmasq aircrack-ng python3-flask`

**Install:**
```bash
sudo pwnstore install evil_twin
```

**Config:**
```toml
[main.plugins.evil_twin]
enabled       = true
iface_ap      = "wlan0"      # built-in WiFi — evil twin AP
iface_mon     = "wlan1mon"   # ALFA in monitor mode
ap_ip         = "10.0.99.1"
portal_port   = 8080
deauth_rounds = 5
submit        = true         # submit cracked passwords to community pool
wordlist_folder = "/home/pi/wordlists/"
```

---

## License

GPL3
