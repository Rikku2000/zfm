# zFM - Digital Voice Communication System

A cross-platform digital communication framework consisting of a
**server**, a **command-line client**, an **SDL2 GUI client**, and
optional **GPIO/CM108 PTT support**.

This project is **not strictly a ham-radio application**, but its architecture and operating style are very similar
to modern amateur-radio digital voice systems. It is designed for experimentation, learning, and private communication
networks, and **may be adapted for amateur-radio use** where permitted by local regulations.

## Project Structure

    /server.cpp
    /client.cpp
    /client_gui.cpp
    /cm108.c
    /Makefile
    /client.vcxproj
    /client_gui.vcxproj
    /server.vcxproj

## Building

### Linux

- sudo apt install build-essential libportaudio2 portaudio19-dev libsdl2-dev libsdl2-ttf-dev libudev-dev
- sudo make
- sudo chmod +x client client_gui server

### Windows

- Use included Visual Studio `.vcxproj` files.

## Features

### Cross-platform Audio (PortAudio)

- The client uses PortAudio for audio capture & playback

### TCP-based low-latency audio transport

Uses a simple line-based command protocol with binary audio frames.
Protocol commands include:
- AUTH <callsign> <password>
- JOIN <talkgroup>
- REQ_SPEAK
- END_SPEAK
- AUDIO <bytes>

### GUI Client (SDL2 + SDL_ttf)

Includes:
- Real-time audio meter
- Talkgroup status
- Log viewer
- Connect/disconnect
- PTT & VOX indicators

### CM108/CM119 USB PTT GPIO Support

- Linux & Windows compatible

### Server with talkgroups, announcements & weather

The server maintains:
- User accounts
- Talkgroup permissions
- Time announcements
- Weather API integration
- HTTP dashboard

## Components

### Server

Handles authentication, talkgroups, audio routing, admin commands,
announcements, weather, dashboard.

## Server Config (server.json)

``` json
{
  "server_port": 26613,
  "max_talk_ms": 300000,
  "http_root": "dashboard",
  "http_port": 8080,
  "users": [
    {
      "callsign": "DL0XYZ",
      "password": "passw0rd",
      "is_admin": true,
      "talkgroups": ["admin", "weather", "gateway"]
    }
  ],
  "talkgroups": [
	{ "name": "admin" },
	{ "name": "weather" }
	{ "name": "gateway" }
  ],
  "time_announcement": {
    "enabled": true,
    "folder": "audio",
    "volume_factor": 0.4
  },
  "weather_enabled": true,
  "weather_host_ip": "api.openweathermap.org"
  "weather_talkgroup": "weather",
  "weather_interval_sec": 600,
  "weather_api_key": "API_KEY",
  "weather_lat": "50.1109",
  "weather_lon": "8.6821",
  "weather_city_key": "frankfurt"
}

```

## Server Commands (Admin)

- /kick <user>
- /mute <user>
- /unmute <user>
- /ban <user>
- /unban <user>
- /add_user <user> <pass>
- /remove_user <user>
- /set_admin <user> <0|1>
- /set_pass <user> <newpass>
- /add_tg <user> <tg>
- /drop_tg <user> <tg>
- /list_users
- /list_tgs

### Client

PortAudio capture/playback, networking, PTT, VOX, GPIO/CM108 support.

## Client Config (client.json)

``` json
{
  "mode": "server",
  "server_ip": "127.0.0.1",
  "server_port": 26613,
  "callsign": "DL0XYZ",
  "password": "passw0rd",
  "talkgroup": "gateway",
  "sample_rate": 22050,
  "frames_per_buffer": 1440,
  "channels": 1,
  "input_device_index": 0,
  "output_device_index": 2,
  "ptt_enabled": true,
  "ptt_pin": 3,
  "active_high": true,
  "ptt_hold_ms": 250,
  "vox_enabled": false,
  "vox_threshold": 5000,
  "input_gain": 100,
  "output_gain": 100,
  "ptt_cmd_on": "",
  "ptt_cmd_off": ""
}

```

### GUI Client

SDL2 interface with meters, logs, PTT, device selection.

### CM108 GPIO Handler

Cross‑platform USB HID GPIO toggle for CM108/CM119 devices.

## Extra

### Dashboard (HTTP)

Server runs a lightweight web server:
- Serves static files from /dashboard
- Shows current talkers
- Group activity
- Server stats

### Weather Announcements

If enabled, server periodically:
- Queries weather API
- Constructs a list of WAV segments
- Concatenates them into a cached WAV
- Broadcasts to talkgroup
