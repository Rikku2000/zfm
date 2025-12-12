# zFM – Digital Voice Communication System

zFM is a cross-platform digital voice communication framework consisting of a:

- **Server**
- **Command-line client**
- **SDL2 GUI client**
- **Optional GPIO / CM108 / VOX support**
- **HTTP Dashboard**

zFM is not strictly a ham-radio system, but its architecture is similar to digital‑voice systems (DMR, YSF, etc.).  
It is designed for experimentation, private networks, and learning.

---

## 🔗 Linked Talkgroups / Cross‑TG Bridging
The server now supports routing audio across multiple linked talkgroups:

```json
"bridges": {
    "weather": ["gateway", "hesse"],
    "gateway": ["germany"]
}
```

A transmission on `weather` also forwards to `gateway` and `hesse`.

## 🔐 Per‑User Talkgroup Permissions
Users may be restricted to specific talkgroups:

```json
{
  "callsign": "DL0XLZ",
  "password": "passw0rd",
  "talkgroups": ["weather", "gateway", "germany"],
  "is_admin": true
}
```

JOIN attempts to unauthorized talkgroups will fail.

## 📡 Server → Client Talkgroup Sync (TGLIST)
After JOIN, the server now sends a list of allowed talkgroups:

```
TGLIST tg1,tg2,tg3
```

The client GUI automatically updates its talkgroup selector.

---

# 📁 Project Structure

```
/server.cpp
/client.cpp
/client_gui.cpp
/cm108.c
/Makefile
*.vcxproj (Windows builds)
```

---

# 🔧 Building

## Linux

```
sudo apt install build-essential
sudo apt install libportaudio2 portaudio19-dev libopus-dev
sudo apt install libsdl2-dev libsdl2-ttf-dev libudev-dev
sudo make
sudo chmod +x client client_gui server
```

## Windows
Use Visual Studio and the included `.vcxproj` files.

---

# 🚀 Features

## ✔ Cross‑platform audio (PortAudio)
Real‑time PCM capture & playback.

## ✔ Low‑latency TCP protocol
Commands include:

- `AUTH <callsign> <password>`
- `JOIN <talkgroup>`
- `TGLIST <tg1,tg2,...>`
- `REQ_SPEAK`
- `END_SPEAK`
- `AUDIO <bytes>`
- `AUDIO_OPUS <bytes>` (if OPUS enabled)

## ✔ SDL2 GUI Client
- Audio meter  
- Device selection  
- PTT / VOX indicators  
- Log viewer  
- Dynamic talkgroup dropdown  

## ✔ Server Features
- User accounts with permissions  
- Talkgroups  
- **Linked talkgroups**  
- Weather announcements  
- Time announcements  
- HTTP dashboard  

---

# 🧩 Example server.json

```json
{
  "server_port": 26613,
  "server_name": "local-server",
  "peer_secret": "peer_secret",
  "max_talk_ms": 300000,
  "http_root": "dashboard",
  "http_port": 8080,
  "users": [
    {
      "callsign": "DL0XYZ",
      "password": "passw0rd",
      "is_admin": true,
      "talkgroups": ["weather","gateway","germany","hesse"]
    }
  ],
  "talkgroups": [
    { "name": "weather" },
    { "name": "gateway" },
    { "name": "germany" },
    { "name": "hesse" },
    { "name": "admin", "mode": "admin" },
    { "name": "demo", "mode": "hide" }
  ],
  "bridges": {
    "weather": ["gateway","hesse"],
    "gateway": ["germany"]
  },
  "peers": [
    {
      "name": "remote-server",
      "host": "127.0.0.1",
      "port": 26613,
      "rules": ["gateway=gateway:both", "germany=germany:tx"]
    }
  ],
  "time_announcement": {
    "enabled": true,
    "folder": "audio",
    "volume_factor": 0.4
  },
  "weather_enabled": true,
  "weather_host_ip": "api.openweathermap.org",
  "weather_talkgroup": "weather",
  "weather_interval_sec": 600,
  "weather_api_key": "API_KEY",
  "weather_lat": "50.1109",
  "weather_lon": "8.6821",
  "weather_city_key": "frankfurt"
}
```

# 🔐 Talkgroup Visibility Modes
Talkgroups now support **visibility modes** defined in the server configuration:

| Mode | Description |
|----|----|
| `public` (default) | Visible to everyone |
| `admin` | Visible only to admin users |
| `hide` | Completely hidden from non-admin users |

---

# 🛠 Admin Commands

- `/kick <user>`
- `/mute <user>`
- `/unmute <user>`
- `/ban <user>`
- `/unban <user>`
- `/add_user <user> <pass>`
- `/remove_user <user>`
- `/set_admin <user> <0|1>`
- `/set_pass <user> <newpass>`
- `/add_tg <user> <tg>`
- `/drop_tg <user> <tg>`
- `/list_users`
- `/list_tgs`

---

# 📦 client.json Example

```
{
  "mode": "server",
  "server_ip": "127.0.0.1",
  "server_port": 26613,
  "callsign": "DL0XYZ",
  "password": "passw0rd",
  "talkgroup": "gateway",
  "sample_rate": 22050,
  "frames_per_buffer": 1440,
  "channels": 1
}
```

---

# 🌐 Dashboard

The HTTP dashboard shows:
- Server time
- Connected clients
- Active speakers
- Public talkgroups only
- Audio levels & activity
- Linked talkgroup visualization
- Live waveform

📌 Hidden/admin talkgroups are never shown, even if active.

Served from `/dashboard/`.

---

# 📢 Weather Announcements
The server periodically:

1. Fetches weather from OpenWeatherMap  
2. Builds WAV segments  
3. Broadcasts to the configured talkgroup  

---

## 📊 Dashboard – Bridge Peers Panel

The dashboard now includes a **Bridge Peers** panel showing:
- Peer name
- Host / port
- Online / Offline state
- Active rules

---

## 🛠 Notes
- Cross‑server audio is forwarded as PCM
- Loop prevention uses bridge IDs + hop limits
- Peer connections auto‑reconnect
