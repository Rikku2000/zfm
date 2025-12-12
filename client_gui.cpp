#include "client.cpp"

#include <cmath>
#include <cstdint>
#include <ctime>

#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>

static std::vector<int> g_inputDevices;
static std::vector<int> g_outputDevices;
static std::vector<std::string> g_inputDeviceNames;
static std::vector<std::string> g_outputDeviceNames;

static void BuildPaDeviceLists() {
    g_inputDevices.clear();
    g_outputDevices.clear();
    g_inputDeviceNames.clear();
    g_outputDeviceNames.clear();

    PaError err = Pa_Initialize();
    if (err != paNoError) {
        std::cerr << "PortAudio init error in BuildPaDeviceLists: "
                  << Pa_GetErrorText(err) << "\n";
        return;
    }

    int devCount = Pa_GetDeviceCount();
    if (devCount < 0) {
        std::cerr << "Pa_GetDeviceCount error in BuildPaDeviceLists: "
                  << Pa_GetErrorText(devCount) << "\n";
        Pa_Terminate();
        return;
    }

    for (int i = 0; i < devCount; ++i) {
        const PaDeviceInfo* info = Pa_GetDeviceInfo(i);
        if (!info) continue;

        std::string name = info->name ? info->name : "(unnamed device)";
        if (info->maxInputChannels > 0) {
            g_inputDevices.push_back(i);
            g_inputDeviceNames.push_back(name);
        }
        if (info->maxOutputChannels > 0) {
            g_outputDevices.push_back(i);
            g_outputDeviceNames.push_back(name);
        }
    }

    Pa_Terminate();
}

static SOCKET g_guiSock = INVALID_SOCKET;
static std::thread g_recvThread;
static std::thread g_voxThread;
static bool g_connected = false;

static std::string g_cfgPath = "client.json";

static std::mutex g_logMutex;
static std::vector<std::string> g_logLines;
static std::atomic<bool> g_isTalking(false);

static std::atomic<bool> g_guiPttHeld(false);
static std::atomic<bool> g_guiPttThreadRunning(false);

static void GuiAppendLog(const std::string& text) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::string s = text;
	auto now = std::chrono::steady_clock::now();

    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) {
        s.pop_back();
    }

    g_logLines.push_back(s);
    if (g_logLines.size() > 500) {
        g_logLines.erase(g_logLines.begin(), g_logLines.begin() + 100);
    }

    std::cout << s << std::endl;

	if (s.find("Starting talk session") != std::string::npos ||
		s.find("TX start") != std::string::npos) {
		g_currentSpeaker = g_cfg.callsign;
		g_talkerStart = now;
		g_talkerActive = true;
	}

	if (s.find("Talk session ended") != std::string::npos ||
		s.find("TX end") != std::string::npos) {
		if (g_currentSpeaker == g_cfg.callsign)
			g_currentSpeaker.clear();
		g_talkerActive = false;
		g_audioLevel = 0.0f;
	}
}

static std::string MakeLogFilename()
{
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm;

#if defined(_WIN32) || defined(_WIN64)
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif

    char buf[64];
    if (std::strftime(buf, sizeof(buf), "console_log_%Y%m%d_%H%M%S.txt", &tm))
        return std::string(buf);

    return "console_log.txt";
}

static void SaveLogToFile()
{
    std::vector<std::string> snapshot;
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        snapshot = g_logLines;
    }

    std::string filename = MakeLogFilename();
    std::ofstream f(filename.c_str());
    if (!f.is_open())
    {
        GuiAppendLog(std::string("[ERROR] Failed to save log to: ") + filename);
        return;
    }

    for (const auto& line : snapshot)
        f << line << "\n";

    GuiAppendLog(std::string("Saved log to: ") + filename);
}

static void ClearLog()
{
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        g_logLines.clear();
    }
    GuiAppendLog("Log cleared");
}

static void GuiStopCore() {
    if (!g_connected) return;

    GuiAppendLog("Disconnecting...");
    g_running = false;

    if (g_guiSock != INVALID_SOCKET) {
        closeSocket(g_guiSock);
        g_guiSock = INVALID_SOCKET;
    }
    if (g_recvThread.joinable()) g_recvThread.join();
    if (g_voxThread.joinable())  g_voxThread.join();

    shutdownPortAudio();
    shutdownGpioPtt();
    cleanupSockets();

    g_connected = false;
	g_isTalking = false;

    GuiAppendLog("Disconnected");
}

static bool GuiStartCore() {
    if (g_connected) return true;

    GuiAppendLog("Starting core: mode=" + g_cfg.mode +
                 ", server=" + g_cfg.server_ip + ":" + std::to_string(g_cfg.server_port) +
                 ", TG=" + g_cfg.talkgroup);

    if (!initPortAudio(g_cfg)) {
        GuiAppendLog("[ERROR] PortAudio init failed");
        return false;
    }
	loadRogerFromConfig();
    if (!initGpioPtt(g_cfg)) {
        GuiAppendLog("GPIO PTT init failed (continuing without)");
    }

    g_pttHoldMs = g_cfg.gpio_ptt_hold_ms;
    std::thread(pttManagerThreadFunc).detach();

    g_running = true;
    g_canTalk = false;

    if (g_cfg.mode == "parrot") {
        g_connected = true;
        GuiAppendLog("Parrot mode active (no server connection).");
        return true;
    }

    initSockets();
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        GuiAppendLog("[ERROR] Failed to create socket");
        cleanupSockets();
        shutdownPortAudio();
        shutdownGpioPtt();
        return false;
    }

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = nullptr;
    std::ostringstream portStr;
    portStr << g_cfg.server_port;
    int rv = getaddrinfo(g_cfg.server_ip.c_str(), portStr.str().c_str(), &hints, &res);
    if (rv != 0 || !res) {
        GuiAppendLog("[ERROR] getaddrinfo failed");
        closeSocket(sock);
        cleanupSockets();
        shutdownPortAudio();
        shutdownGpioPtt();
        return false;
    }

    bool connected = false;
    for (struct addrinfo* p = res; p != NULL; p = p->ai_next) {
        if (connect(sock, p->ai_addr, (int)p->ai_addrlen) == 0) {
            connected = true;
            break;
        }
    }
    freeaddrinfo(res);

    if (!connected) {
        GuiAppendLog("[ERROR] Connect failed");
        closeSocket(sock);
        cleanupSockets();
        shutdownPortAudio();
        shutdownGpioPtt();
        return false;
    }

    if (g_cfg.gpio_ptt_enabled && !g_cfg.vox_enabled) {
        g_pttAutoEnabled = true;
        g_lastRxAudioTime = std::chrono::steady_clock::now();
    } else {
        g_pttAutoEnabled = false;
    }

    if (g_cfg.vox_enabled) {
        std::thread(pttManagerThreadFunc).detach();
    }

    {
        std::ostringstream oss;
        oss << "AUTH " << g_cfg.callsign << " " << g_cfg.password << "\n";
        std::string cmd = oss.str();
        if (!sendAll(sock, cmd.data(), cmd.size())) {
            GuiAppendLog("[ERROR] Send AUTH failed");
            closeSocket(sock);
            cleanupSockets();
            shutdownPortAudio();
            shutdownGpioPtt();
            return false;
        }
        std::string line;
        if (!recvLine(sock, line) || line != "AUTH_OK") {
            GuiAppendLog("[ERROR] AUTH failed");
            closeSocket(sock);
            cleanupSockets();
            shutdownPortAudio();
            shutdownGpioPtt();
            return false;
        }
    }

    {
        std::ostringstream oss;
        oss << "JOIN " << g_cfg.talkgroup << "\n";
        std::string cmd = oss.str();
        if (!sendAll(sock, cmd.data(), cmd.size())) {
            GuiAppendLog("[ERROR] Send JOIN failed");
            closeSocket(sock);
            cleanupSockets();
            shutdownPortAudio();
            shutdownGpioPtt();
            return false;
        }
        std::string line;
        if (!recvLine(sock, line) || line.find("JOIN_OK") != 0) {
            GuiAppendLog("[ERROR] JOIN failed");
            closeSocket(sock);
            cleanupSockets();
            shutdownPortAudio();
            shutdownGpioPtt();
            return false;
        }
    }

    g_guiSock = sock;
    g_recvThread = std::thread(receiverLoop, g_guiSock);
    if (g_cfg.vox_enabled) {
        g_voxThread = std::thread(voxAutoLoop, g_guiSock);
    }

    g_connected = true;
    GuiAppendLog("Connected to server " + g_cfg.server_ip + ":" +
                 std::to_string(g_cfg.server_port) +
                 " mode=" + g_cfg.mode + " TG=" + g_cfg.talkgroup);
    return true;
}

static void TalkThreadWrapper() {
    if (g_isTalking.load())
        return;

	g_isTalking = true;
	GuiAppendLog("Starting talk session");
	g_currentSpeaker = g_cfg.callsign;
	g_talkerStart = std::chrono::steady_clock::now();
	g_talkerActive = true;

    doTalkSession(g_guiSock);

	g_isTalking = false;

	if (g_currentSpeaker == g_cfg.callsign) {
		g_currentSpeaker.clear();
	}
	g_talkerActive = false;
	g_audioLevel = 0.0f;
}

static void GuiHandleCommand(const std::string& input) {
    if (input.empty()) return;

    GuiAppendLog(std::string("> ") + input);

    if (g_cfg.mode == "parrot") {
        if (input == "t" || input == "/talk") {
            GuiAppendLog("Starting parrot session");
            std::thread(doParrotSession, g_cfg.gpio_ptt_enabled).detach();
        }
        return;
    }

    if (input == "q" || input == "/quit") {
        GuiAppendLog("Quit requested");
        GuiStopCore();
	} else if (input == "t" || input == "/talk") {
		if (!g_connected || g_guiSock == INVALID_SOCKET) {
			GuiAppendLog("[WARN] Talk requested but not connected");
			return;
		}
		if (g_isTalking.load()) {
			GuiAppendLog("[INFO] Already talking; ignoring TALK request");
			return;
		}
		std::thread(TalkThreadWrapper).detach();
    } else if (!input.empty() && input[0] == '/') {
        if (!g_connected || g_guiSock == INVALID_SOCKET) {
            GuiAppendLog("[WARN] Admin cmd requested but not connected");
            return;
        }
        std::string payload = input.substr(1);
        std::string cmd = "ADMIN " + payload + "\n";
        if (!sendAll(g_guiSock, cmd.data(), cmd.size())) {
            GuiAppendLog("[ERROR] Failed to send admin cmd: " + payload);
            GuiStopCore();
        } else {
            GuiAppendLog("Sent admin cmd: " + payload);
        }
    } else {
        GuiAppendLog("Unknown cmd");
    }
}

static void GuiPushToTalkLoop() {
    g_guiPttThreadRunning = true;

    if (!g_connected || g_guiSock == INVALID_SOCKET) {
        GuiAppendLog("[WARN] PTT requested but not connected");
        g_guiPttThreadRunning = false;
        return;
    }

    std::string req = "REQ_SPEAK\n";
    if (!sendAll(g_guiSock, req.data(), req.size())) {
        GuiAppendLog("[ERROR] Failed to send REQ_SPEAK");
        g_guiPttThreadRunning = false;
        return;
    }

    int waits = 0;
	while (g_running && g_guiPttHeld && !g_canTalk && waits < 50) {
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		++waits;
	}
	if (!g_canTalk || !g_guiPttHeld) {
		GuiAppendLog("[INFO] PTT: not granted or cancelled");
		g_guiPttThreadRunning = false;
		return;
	}

    if (g_cfg.gpio_ptt_enabled) {
        setPtt(true);
    }

    int maxMs = g_maxTalkMs.load();
    auto start = std::chrono::steady_clock::now();

    GuiAppendLog("[PTT] You may talk now (hold Talk button)");

	g_currentSpeaker = g_cfg.callsign;
	g_talkerStart = std::chrono::steady_clock::now();
	g_talkerActive = true;

    while (g_running && g_guiPttHeld && g_canTalk) {
        auto now = std::chrono::steady_clock::now();
        int elapsed = (int)std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
        if (maxMs > 0 && elapsed >= maxMs) {
            GuiAppendLog("[PTT] Max talk time reached");
            break;
        }

        std::vector<char> frame = captureAudioFrame();
        if (!g_running) break;
        if (frame.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

		if (!frame.empty()) {
			const std::int16_t* samples =
				reinterpret_cast<const std::int16_t*>(frame.data());
			size_t sampleCount = frame.size() / sizeof(std::int16_t);

			if (sampleCount > 0) {
				double sumSq = 0.0;
				for (size_t i = 0; i < sampleCount; ++i) {
					double v = samples[i] / 32768.0;
					sumSq += v * v;
				}
				double rms = std::sqrt(sumSq / sampleCount);
				float level = (float)rms;
				if (level < 0.0f) level = 0.0f;
				if (level > 1.0f) level = 1.0f;

				float old = g_audioLevel.load();
				g_audioLevel = old * 0.7f + level * 0.3f;
			}
		}

#ifdef OPUS
		std::vector<char> payload;
		std::string audioCmd;

		if (g_cfg.use_opus) {
			payload = encodeOpusFrame(frame);
			if (payload.empty()) {
				continue;
			}
			audioCmd = "AUDIO_OPUS";
		} else {
			payload = std::move(frame);
			audioCmd = "AUDIO";
		}

		std::ostringstream oss;
		oss << audioCmd << " " << payload.size() << "\n";
		std::string header = oss.str();

		if (!sendAll(g_guiSock, header.data(), header.size())) {
			GuiAppendLog("[ERROR] Failed to send AUDIO header");
			g_running = false;
			break;
		}
		if (!sendAll(g_guiSock, payload.data(), payload.size())) {
			GuiAppendLog("[ERROR] Failed to send AUDIO data");
			g_running = false;
			break;
		}
#else
        std::ostringstream oss;
        oss << "AUDIO " << frame.size() << "\n";
        std::string header = oss.str();

        if (!sendAll(g_guiSock, header.data(), header.size())) {
            GuiAppendLog("[ERROR] Failed to send AUDIO header");
            g_running = false;
            break;
        }
        if (!sendAll(g_guiSock, frame.data(), frame.size())) {
            GuiAppendLog("[ERROR] Failed to send AUDIO data");
            g_running = false;
            break;
        }
#endif
    }

    if (g_canTalk) {
        std::string endCmd = "END_SPEAK\n";
        sendAll(g_guiSock, endCmd.c_str(), endCmd.size());
        g_canTalk = false;
    }
    if (g_cfg.gpio_ptt_enabled) {
        setPtt(false);
    }
    playMicFreeSound();

    g_guiPttThreadRunning = false;
	g_talkerActive = false;
	g_audioLevel = 0.0f;
}

static SDL_Color COL_BG        = { 0x12, 0x12, 0x12, 255 };
static SDL_Color COL_PANEL     = { 0x1e, 0x1e, 0x1e, 255 };
static SDL_Color COL_PANEL_BD  = { 0x33, 0x33, 0x33, 255 };
static SDL_Color COL_TEXT      = { 0xf5, 0xf5, 0xf5, 255 };
static SDL_Color COL_TEXT_MUT  = { 0xaa, 0xaa, 0xaa, 255 };
static SDL_Color COL_INPUT_BG  = { 0x12, 0x12, 0x12, 255 };
static SDL_Color COL_INPUT_BD  = { 0x33, 0x33, 0x33, 255 };
static SDL_Color COL_FOCUS_BD  = { 0xff, 0x52, 0x52, 255 };
static SDL_Color COL_BUTTON    = { 0x1e, 0x1e, 0x1e, 255 };
static SDL_Color COL_BUTTON_H  = { 0x26, 0x26, 0x26, 255 };
static SDL_Color COL_TX_BTN    = { 0xff, 0x52, 0x52, 255 };
static SDL_Color COL_TX_BTN_H  = { 0xff, 0x73, 0x73, 255 };
static SDL_Color COL_CHECKBOX  = { 0x4c, 0xaf, 0x50, 255 };

static SDL_Color COL_TAB_BG       = { 0x12, 0x12, 0x12, 255 };
static SDL_Color COL_TAB_ACTIVE   = { 0xff, 0x52, 0x52, 255 };
static SDL_Color COL_TAB_INACTIVE = { 0xaa, 0xaa, 0xaa, 255 };

static SDL_Color COL_BTN_CONNECT    = { 0x4c, 0xaf, 0x50, 255 };
static SDL_Color COL_BTN_DISCONNECT = { 0xff, 0x52, 0x52, 255 };

static int g_activeTab = 0;

static void DrawRect(SDL_Renderer* r, const SDL_Rect& rc, SDL_Color c) {
    SDL_SetRenderDrawColor(r, c.r, c.g, c.b, c.a);
    SDL_RenderFillRect(r, &rc);
}

static void DrawRectBorder(SDL_Renderer* r, const SDL_Rect& rc, SDL_Color c, int thickness = 1) {
    SDL_SetRenderDrawColor(r, c.r, c.g, c.b, c.a);
    for (int i = 0; i < thickness; ++i) {
        SDL_Rect rr = { rc.x + i, rc.y + i, rc.w - 2 * i, rc.h - 2 * i };
        SDL_RenderDrawRect(r, &rr);
    }
}

static void DrawText(SDL_Renderer* r, TTF_Font* font, const std::string& text,
                     int x, int y, SDL_Color col) {
    if (text.empty()) return;
    SDL_Surface* surf = TTF_RenderUTF8_Blended(font, text.c_str(), col);
    if (!surf) return;
    SDL_Texture* tex = SDL_CreateTextureFromSurface(r, surf);
    SDL_Rect dst = { x, y, surf->w, surf->h };
    SDL_FreeSurface(surf);
    if (tex) {
        SDL_RenderCopy(r, tex, nullptr, &dst);
        SDL_DestroyTexture(tex);
    }
}

static void DrawTextCentered(SDL_Renderer* r, TTF_Font* font, const std::string& text,
                             const SDL_Rect& rc, SDL_Color col) {
    if (text.empty()) return;
    int tw = 0, th = 0;
    TTF_SizeUTF8(font, text.c_str(), &tw, &th);
    int x = rc.x + (rc.w - tw) / 2;
    int y = rc.y + (rc.h - th) / 2;
    DrawText(r, font, text, x, y, col);
}

enum WidgetType {
    W_LABEL,
    W_EDIT,
    W_BUTTON,
    W_CHECK,
    W_COMBO,
    W_SLIDER
};

struct Widget {
    WidgetType type;
    SDL_Rect   rect;
    int        tab;

    std::string label;
    std::string* boundText;
    bool*       boundBool;
    int*        boundIndex;
    std::vector<std::string>* comboItems;

    int*       boundValue;
    int        minValue;
    int        maxValue;

    int        caretPos;

    bool hovered;
    bool focused;
    bool enabled;
};

static std::vector<Widget> g_widgets;
static int g_focusWidget = -1;
static int g_activeSlider = -1;
static bool g_mouseDown    = false;

static SDL_Rect makeRect(int x, int y, int w, int h) {
    SDL_Rect r = { x, y, w, h };
    return r;
}

static int AddLabel(int tab, int x, int y, const std::string& text) {
    Widget w;
    w.type = W_LABEL;
    w.rect = makeRect(x, y, 150, 22);
    w.tab  = tab;
    w.label = text;
    w.boundText = nullptr;
    w.boundBool = nullptr;
    w.boundIndex = nullptr;
    w.comboItems = nullptr;
    w.hovered = false;
    w.focused = false;
    g_widgets.push_back(w);
    return (int)g_widgets.size() - 1;
}

static int AddEdit(int tab, int x, int y, int w, std::string* bind) {
    Widget wg;
    wg.type = W_EDIT;
    wg.rect = makeRect(x, y, w, 30);
    wg.tab  = tab;
    wg.boundText = bind;
    wg.boundBool = nullptr;
    wg.boundIndex = nullptr;
    wg.comboItems = nullptr;
    wg.hovered = false;
    wg.focused = false;
	wg.enabled = true;
	wg.caretPos = -1;
    g_widgets.push_back(wg);
    return (int)g_widgets.size() - 1;
}

static int AddCheck(int tab, int x, int y, const std::string& text, bool* bind) {
    Widget wg;
    wg.type = W_CHECK;
    wg.rect = makeRect(x, y, 20, 20);
    wg.tab  = tab;
    wg.boundBool = bind;
    wg.label = text;
    wg.boundText = nullptr;
    wg.boundIndex = nullptr;
    wg.comboItems = nullptr;
    wg.hovered = false;
    wg.focused = false;
	wg.enabled = true;
    g_widgets.push_back(wg);
    return (int)g_widgets.size() - 1;
}

static int AddButton(int tab, int x, int y, int w, int h, const std::string& text) {
    Widget wg;
    wg.type = W_BUTTON;
    wg.rect = makeRect(x, y, w, h);
    wg.tab  = tab;
    wg.label = text;
    wg.boundText = nullptr;
    wg.boundBool = nullptr;
    wg.boundIndex = nullptr;
    wg.comboItems = nullptr;
    wg.hovered = false;
    wg.focused = false;
	wg.enabled = true;
    g_widgets.push_back(wg);
    return (int)g_widgets.size() - 1;
}

static int AddCombo(int tab, int x, int y, int w, std::string* display,
                    int* index, std::vector<std::string>* items) {
    Widget wg;
    wg.type = W_COMBO;
    wg.rect = makeRect(x, y, w, 30);
    wg.tab  = tab;
    wg.boundText = display;
    wg.boundIndex = index;
    wg.comboItems = items;
    wg.boundBool = nullptr;
    wg.hovered = false;
    wg.focused = false;
	wg.enabled = true;
    g_widgets.push_back(wg);
    return (int)g_widgets.size() - 1;
}

static int AddSlider(int tab, int x, int y, int w,int* value, int minVal, int maxVal,const std::string& label) {
    Widget wg;
    wg.type = W_SLIDER;
    wg.rect = makeRect(x, y, w, 30);
    wg.tab  = tab;

    wg.label      = label;
    wg.boundText  = nullptr;
    wg.boundBool  = nullptr;
    wg.boundIndex = nullptr;
    wg.comboItems = nullptr;

    wg.boundValue = value;
    wg.minValue   = minVal;
    wg.maxValue   = maxVal;

    wg.hovered = false;
    wg.focused = false;
    wg.enabled = true;

    g_widgets.push_back(wg);
    return (int)g_widgets.size() - 1;
}

static std::string ui_mode;

static std::vector<std::string> g_modeItems;
static int ui_mode_index = 0;

static std::string ui_server_ip;
static std::string ui_server_port;
static std::string ui_callsign;
static std::string ui_password;
static std::string ui_talkgroup;

std::vector<std::string> g_tgComboItems;
int ui_tg_index = 0;

static std::string ui_sample_rate;
static std::string ui_frames_per_buffer;
static std::string ui_channels;

static std::string ui_gpio_pin;
static std::string ui_gpio_hold_ms;
static std::string ui_vox_thresh;

static int ui_in_gain  = 100;
static int ui_out_gain = 100;

static bool ui_gpio_ptt_en = false;
static bool ui_gpio_ah     = false;
static bool ui_vox_en      = false;

#ifdef OPUS
static std::vector<std::string> g_codecItems;
static int         ui_codec_index = 0;
static std::string ui_codec_text;
#endif

static std::string ui_ptt_cmd_on;
static std::string ui_ptt_cmd_off;

static std::vector<std::string> g_pttMethodItems;
static int ui_ptt_method_index = 0;
static std::string ui_ptt_method;

static std::string ui_in_dev_text;
static std::string ui_out_dev_text;
static int ui_in_dev_index  = 0;
static int ui_out_dev_index = 0;

static std::vector<std::string> g_rogerItems;
static int ui_roger_index = 1;
static std::string ui_roger_text;

static std::string ui_cmd;

static void CfgToUi() {
    ui_mode       = (g_cfg.mode == "parrot") ? "parrot" : "server";
    ui_mode_index = (g_cfg.mode == "parrot") ? 1 : 0;
    if (ui_mode_index >= 0 && ui_mode_index < (int)g_modeItems.size())
        ui_mode = g_modeItems[ui_mode_index];
    else
        ui_mode = "server";

    ui_server_ip   = g_cfg.server_ip;
    ui_server_port = std::to_string(g_cfg.server_port);
    ui_callsign    = g_cfg.callsign;
    ui_password    = g_cfg.password;
    ui_talkgroup   = g_cfg.talkgroup;

    if (!ui_talkgroup.empty() && g_tgComboItems.empty()) {
        g_tgComboItems.push_back(ui_talkgroup);
        ui_tg_index = 0;
    }

    if (!g_tgComboItems.empty()) {
        int foundIndex = -1;
        for (size_t i = 0; i < g_tgComboItems.size(); ++i) {
            if (g_tgComboItems[i] == ui_talkgroup) {
                foundIndex = (int)i;
                break;
            }
        }
        if (foundIndex == -1) {
            g_tgComboItems.push_back(ui_talkgroup);
            ui_tg_index = (int)g_tgComboItems.size() - 1;
        } else {
            ui_tg_index = foundIndex;
        }
        ui_talkgroup = g_tgComboItems[ui_tg_index];
    }

    ui_sample_rate       = std::to_string(g_cfg.sample_rate);
    ui_frames_per_buffer = std::to_string(g_cfg.frames_per_buffer);
    ui_channels          = std::to_string(g_cfg.channels);

    ui_gpio_ptt_en   = g_cfg.gpio_ptt_enabled;
    ui_gpio_pin      = std::to_string(g_cfg.gpio_ptt_pin);
    ui_gpio_ah       = g_cfg.gpio_ptt_active_high;
    ui_gpio_hold_ms  = std::to_string(g_cfg.gpio_ptt_hold_ms);

    ui_vox_en        = g_cfg.vox_enabled;
    ui_vox_thresh    = std::to_string(g_cfg.vox_threshold);

    ui_in_gain  = g_cfg.input_gain;
    ui_out_gain = g_cfg.output_gain;

#ifdef OPUS
    if (g_codecItems.empty()) {
        g_codecItems.push_back("Default (PCM)");
        g_codecItems.push_back("Opus");
    }
    ui_codec_index = g_cfg.use_opus ? 1 : 0;
    if (ui_codec_index < 0 || ui_codec_index >= (int)g_codecItems.size())
        ui_codec_index = 0;
    ui_codec_text = g_codecItems[ui_codec_index];
#endif

    ui_ptt_cmd_on  = g_cfg.ptt_cmd_on;
    ui_ptt_cmd_off = g_cfg.ptt_cmd_off;

    if (g_pttMethodItems.empty()) {
        g_pttMethodItems.push_back("None");
        g_pttMethodItems.push_back("CM108 Audio Interface");
        g_pttMethodItems.push_back("Custom");
    }

    int idx = 0;
    if (!g_cfg.ptt_cmd_on.empty() || !g_cfg.ptt_cmd_off.empty()) {
        if (g_cfg.ptt_cmd_on.find("cm108") != std::string::npos) {
            idx = 1;
        } else {
            idx = 2;
        }
    }
    ui_ptt_method_index = idx;
    ui_ptt_method       = g_pttMethodItems[ui_ptt_method_index];

    if (g_rogerItems.empty()) {
        g_rogerItems.push_back("None");
        g_rogerItems.push_back("Roger 1");
        g_rogerItems.push_back("Roger 2");
        g_rogerItems.push_back("Roger 3");
        g_rogerItems.push_back("Roger 4");
    }

    ui_roger_index = g_cfg.roger_sound;
    if (ui_roger_index < 0 || ui_roger_index >= (int)g_rogerItems.size())
        ui_roger_index = 1;

    ui_roger_text = g_rogerItems[ui_roger_index];

    ui_in_dev_index  = 0;
    ui_out_dev_index = 0;
    if (!g_inputDevices.empty()) {
        for (size_t i = 0; i < g_inputDevices.size(); ++i) {
            if (g_inputDevices[i] == g_cfg.input_device_index) {
                ui_in_dev_index = (int)i;
                break;
            }
        }
        if (ui_in_dev_index >= 0 && ui_in_dev_index < (int)g_inputDeviceNames.size())
            ui_in_dev_text = g_inputDeviceNames[ui_in_dev_index];
        else
            ui_in_dev_text.clear();
    } else {
        ui_in_dev_text.clear();
    }

    if (!g_outputDevices.empty()) {
        for (size_t i = 0; i < g_outputDevices.size(); ++i) {
            if (g_outputDevices[i] == g_cfg.output_device_index) {
                ui_out_dev_index = (int)i;
                break;
            }
        }
        if (ui_out_dev_index >= 0 && ui_out_dev_index < (int)g_outputDeviceNames.size())
            ui_out_dev_text = g_outputDeviceNames[ui_out_dev_index];
        else
            ui_out_dev_text.clear();
    } else {
        ui_out_dev_text.clear();
    }

    if (g_inputDeviceNames.empty())  ui_in_dev_text  = "(no input devices)";
    if (g_outputDeviceNames.empty()) ui_out_dev_text = "(no output devices)";
}

static void UiToCfg() {
    if (ui_mode_index == 1)
        g_cfg.mode = "parrot";
    else
        g_cfg.mode = "server";

    g_cfg.server_ip   = ui_server_ip;
    g_cfg.server_port = std::atoi(ui_server_port.c_str());
    g_cfg.callsign    = ui_callsign;
    g_cfg.password    = ui_password;
    g_cfg.talkgroup   = ui_talkgroup;

    g_cfg.sample_rate       = std::atoi(ui_sample_rate.c_str());
    g_cfg.frames_per_buffer = (unsigned long)std::atoi(ui_frames_per_buffer.c_str());
    g_cfg.channels          = std::atoi(ui_channels.c_str());

    g_cfg.gpio_ptt_enabled     = ui_gpio_ptt_en;
    g_cfg.gpio_ptt_pin         = std::atoi(ui_gpio_pin.c_str());
    g_cfg.gpio_ptt_active_high = ui_gpio_ah;
    g_cfg.gpio_ptt_hold_ms     = std::atoi(ui_gpio_hold_ms.c_str());

    g_cfg.input_gain  = ui_in_gain;
    g_cfg.output_gain = ui_out_gain;

#ifdef OPUS
	g_cfg.use_opus = (ui_codec_index == 1);
#endif

    g_cfg.vox_enabled          = ui_vox_en;
    g_cfg.vox_threshold        = std::atoi(ui_vox_thresh.c_str());

    if (ui_in_dev_index >= 0 && ui_in_dev_index < (int)g_inputDevices.size())
        g_cfg.input_device_index = g_inputDevices[ui_in_dev_index];
    if (ui_out_dev_index >= 0 && ui_out_dev_index < (int)g_outputDevices.size())
        g_cfg.output_device_index = g_outputDevices[ui_out_dev_index];

    switch (ui_ptt_method_index) {
        case 0:
            ui_ptt_cmd_on.clear();
            ui_ptt_cmd_off.clear();
            break;
        case 1:
            ui_ptt_cmd_on  = "cm108 -H /dev/hidraw0 -P 3 -L 1";
            ui_ptt_cmd_off = "cm108 -H /dev/hidraw0 -P 3 -L 0";
            break;
        case 2:
        default:
            break;
    }

    g_cfg.ptt_cmd_on  = ui_ptt_cmd_on;
    g_cfg.ptt_cmd_off = ui_ptt_cmd_off;

	g_cfg.roger_sound = ui_roger_index;
}

static void RenderWidgets(SDL_Renderer* r, TTF_Font* font) {
    for (size_t i = 0; i < g_widgets.size(); ++i) {
        Widget& w = g_widgets[i];

        if (w.tab != -1 && w.tab != g_activeTab)
            continue;

        switch (w.type) {
        case W_LABEL: {
            DrawText(r, font, w.label, w.rect.x, w.rect.y, COL_TEXT_MUT);
            break;
        }
        case W_EDIT: {
            DrawRect(r, w.rect, COL_INPUT_BG);
            SDL_Color bd = w.focused ? COL_FOCUS_BD : COL_INPUT_BD;
            DrawRectBorder(r, w.rect, bd, 1);

			std::string txt = w.boundText ? *w.boundText : "";
			int tx = w.rect.x + 6;
			int ty = w.rect.y + 6;
			DrawText(r, font, txt, tx, ty, COL_TEXT);

			if (w.focused) {
				if (w.caretPos < 0) {
					w.caretPos = (int)txt.size();
				} else if (w.caretPos > (int)txt.size()) {
					w.caretPos = (int)txt.size();
				}

				int caretOffset = 0;
				if (!txt.empty() && w.caretPos > 0) {
					std::string prefix = txt.substr(0, w.caretPos);
					int pw = 0, ph = 0;
					TTF_SizeUTF8(font, prefix.c_str(), &pw, &ph);
					caretOffset = pw;
				}

				Uint32 ticks = SDL_GetTicks();
				bool caretOn = ((ticks / 500) % 2) == 0;
				if (caretOn) {
					int cx = tx + caretOffset + 2;
					int cy = w.rect.y + 5;
					SDL_Rect caret = { cx, cy, 2, w.rect.h - 10 };
					DrawRect(r, caret, COL_TEXT);
				}
			}
            break;
        }
		case W_BUTTON: {
			SDL_Color bg;

			if (w.label == "Connect") {
				bg = COL_BTN_CONNECT;
			} else if (w.label == "Disconnect") {
				bg = COL_BTN_DISCONNECT;
			} else {
				bg = w.hovered ? COL_BUTTON_H : COL_BUTTON;
			}

			if (!w.enabled)
				bg = COL_PANEL_BD;

			DrawRect(r, w.rect, bg);
			DrawRectBorder(r, w.rect, COL_PANEL_BD, 1);

			SDL_Color txt = w.enabled ? COL_TEXT : COL_TEXT_MUT;
			DrawTextCentered(r, font, w.label, w.rect, txt);
			break;
		}
        case W_CHECK: {
            SDL_Rect box = w.rect;
            DrawRect(r, box, COL_INPUT_BG);
            SDL_Color bd = w.focused ? COL_FOCUS_BD : COL_INPUT_BD;
            DrawRectBorder(r, box, bd, 1);
            if (w.boundBool && *w.boundBool) {
                SDL_Rect inner = { box.x + 4, box.y + 4, box.w - 8, box.h - 8 };
                DrawRect(r, inner, COL_CHECKBOX);
            }
            DrawText(r, font, w.label, box.x + box.w + 8, box.y + 2, COL_TEXT);
            break;
        }
		case W_COMBO: {
			DrawRect(r, w.rect, COL_INPUT_BG);
			SDL_Color bd = w.focused ? COL_FOCUS_BD : COL_INPUT_BD;
			DrawRectBorder(r, w.rect, bd, 1);

			std::string txt = w.boundText ? *w.boundText : "";
			DrawText(r, font, txt, w.rect.x + 6, w.rect.y + 6, COL_TEXT);

			int ax = w.rect.x + w.rect.w - 14;
			int ay = w.rect.y + w.rect.h / 2 - 2;
			SDL_SetRenderDrawColor(r, COL_TEXT_MUT.r, COL_TEXT_MUT.g, COL_TEXT_MUT.b, COL_TEXT_MUT.a);
			SDL_RenderDrawLine(r, ax,     ay,     ax + 6, ay    );
			SDL_RenderDrawLine(r, ax,     ay,     ax + 3, ay + 4);
			SDL_RenderDrawLine(r, ax + 6, ay,     ax + 3, ay + 4);
			break;
		}
        case W_SLIDER: {
            int trackX = w.rect.x;
            int trackW = w.rect.w - 40;
            if (trackW < 40) trackW = 40;

            int centerY = w.rect.y + w.rect.h / 2;
            SDL_Rect track = { trackX, centerY - 3, trackW, 6 };

            DrawRect(r, track, COL_INPUT_BG);
            SDL_Color bd = w.focused ? COL_FOCUS_BD : COL_INPUT_BD;
            DrawRectBorder(r, track, bd, 1);

            if (w.boundValue) {
                int v = *w.boundValue;
                if (v < w.minValue) v = w.minValue;
                if (v > w.maxValue) v = w.maxValue;

                int range = (w.maxValue > w.minValue) ? (w.maxValue - w.minValue) : 1;
                float t = float(v - w.minValue) / float(range);
                int knobW = 10;
                int knobX = track.x + int(t * (track.w - knobW));

                SDL_Rect knob = { knobX, track.y - 4, knobW, track.h + 8 };
                DrawRect(r, knob, w.hovered ? COL_CHECKBOX : COL_BUTTON);
                DrawRectBorder(r, knob, COL_PANEL_BD, 1);

                std::string txt = std::to_string(v);
                int textX = track.x + track.w + 6;
                int textY = w.rect.y + 3;
                DrawText(r, font, txt, textX, textY, COL_TEXT_MUT);
            }
            break;
		}
        }
    }
}

static bool      g_comboOpen      = false;
static int       g_comboWidget    = -1;
static SDL_Rect  g_comboPopupRect = {0,0,0,0};
static int       g_comboHoverItem = -1;

int main(int argc, char** argv) {
    loadClientConfig(g_cfgPath, g_cfg);
    BuildPaDeviceLists();

	if (g_modeItems.empty()) {
		g_modeItems.push_back("server");
		g_modeItems.push_back("parrot");
	}

    CfgToUi();
    GuiAppendLog("Welcome to zFM");

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS) != 0) {
        std::cerr << "SDL_Init failed: " << SDL_GetError() << "\n";
        return 1;
    }
    if (TTF_Init() != 0) {
        std::cerr << "TTF_Init failed: " << TTF_GetError() << "\n";
        SDL_Quit();
        return 1;
    }

    SDL_Window* window = SDL_CreateWindow("zFM Client",
                                          SDL_WINDOWPOS_CENTERED,
                                          SDL_WINDOWPOS_CENTERED,
                                          460, 700,
                                          SDL_WINDOW_SHOWN);
    if (!window) {
        std::cerr << "CreateWindow failed: " << SDL_GetError() << "\n";
        TTF_Quit();
        SDL_Quit();
        return 1;
    }

    SDL_Renderer* renderer = SDL_CreateRenderer(window, -1,
        SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!renderer) {
        std::cerr << "CreateRenderer failed: " << SDL_GetError() << "\n";
        SDL_DestroyWindow(window);
        TTF_Quit();
        SDL_Quit();
        return 1;
    }

    const char* fontPath = "opensans-regular.ttf";
	TTF_Font* fontTiny = TTF_OpenFont(fontPath, 12);
	TTF_Font* font = TTF_OpenFont(fontPath, 16);
	TTF_Font* fontBig = TTF_OpenFont(fontPath, 26);
    if (!font) {
        std::cerr << "TTF_OpenFont failed (" << fontPath << "): " << TTF_GetError() << "\n";
        SDL_DestroyRenderer(renderer);
        SDL_DestroyWindow(window);
        TTF_Quit();
        SDL_Quit();
        return 1;
    }

    int w, h;
    SDL_GetWindowSize(window, &w, &h);

    g_widgets.clear();

	const int tabW = 90;
	const int tabH = 28;
	const int space  = 10;
	const int tabCount = 4;
	int totalTabsW = tabCount * tabW + (tabCount - 1) * space;
	int startX = (w - totalTabsW) / 2;
	int tabY = 10;

	SDL_Rect rcTabBar = { 0, 0, w, 44 };
	SDL_Rect rcTabMain  = { startX + (tabW + space) * 0, tabY, tabW, tabH };
	SDL_Rect rcTabAudio = { startX + (tabW + space) * 1, tabY, tabW, tabH };
	SDL_Rect rcTabGpio  = { startX + (tabW + space) * 2, tabY, tabW, tabH };
	SDL_Rect rcTabLog   = { startX + (tabW + space) * 3, tabY, tabW, tabH };

    int contentTop = rcTabBar.y + rcTabBar.h + 6;
	int id_btnLoad1, id_btnSave1, id_btnLoad2, id_btnSave2;

    {
        int xLabel = 16;
        int xCtrl  = 130;
        int y = contentTop + 10;

		AddLabel(0, xLabel, y, "Mode");
		AddCombo(0, xCtrl, y - 2, w - xCtrl - 20, &ui_mode, &ui_mode_index, &g_modeItems); y += 34;

        AddLabel(0, xLabel, y, "Server");
        AddEdit(0, xCtrl, y - 2, w - xCtrl - 20, &ui_server_ip); y += 34;

        AddLabel(0, xLabel, y, "Port");
        AddEdit(0, xCtrl, y - 2, w - xCtrl - 20, &ui_server_port); y += 34;

        AddLabel(0, xLabel, y, "Callsign");
        AddEdit(0, xCtrl, y - 2, w - xCtrl - 20, &ui_callsign); y += 34;

        AddLabel(0, xLabel, y, "Password");
        AddEdit(0, xCtrl, y - 2, w - xCtrl - 20, &ui_password); y += 34;

		AddLabel(0, xLabel, y, "Talkgroup");
		AddCombo(0, xCtrl, y - 2, w - xCtrl - 20, &ui_talkgroup, &ui_tg_index, &g_tgComboItems); y += 40;

        AddLabel(0, xLabel, y, "Status:");
    }

	{
		int xLabel = 16;
		int xCtrl  = 150;
		int y = contentTop + 10;

#ifdef OPUS
        AddLabel(1, xLabel, y, "Audio Codec");
        AddCombo(1, xCtrl, y - 2, w - xCtrl - 20, &ui_codec_text, &ui_codec_index, &g_codecItems); y += 34;
#endif

		AddLabel(1, xLabel, y, "Sample Rate");
		AddEdit(1, xCtrl, y - 2, w - xCtrl - 20, &ui_sample_rate); y += 34;

		AddLabel(1, xLabel, y, "Frames / Buffer");
		AddEdit(1, xCtrl, y - 2, w - xCtrl - 20, &ui_frames_per_buffer); y += 34;

		AddLabel(1, xLabel, y, "Channels");
		AddEdit(1, xCtrl, y - 2, w - xCtrl - 20, &ui_channels); y += 40;

		AddLabel(1, xLabel, y, "Roger Sound");
		AddCombo(1, xCtrl, y - 2, w - xCtrl - 20, &ui_roger_text, &ui_roger_index, &g_rogerItems); y += 34;

		AddCheck(1, xLabel, y, "VOX Enabled", &ui_vox_en); y += 34;

		AddLabel(1, xLabel, y, "VOX Threshold");
		AddEdit(1, xCtrl, y - 2, w - xCtrl - 20, &ui_vox_thresh); y += 34;

		AddLabel(1, xLabel, y, "Input Device");
		AddCombo(1, xCtrl, y - 2, w - xCtrl - 20, &ui_in_dev_text, &ui_in_dev_index, &g_inputDeviceNames); y += 34;

		AddLabel(1, xLabel, y, "Input Gain");
		AddSlider(1, xCtrl, y, 290, &ui_in_gain, 0, 200, ""); y += 40;

		AddLabel(1, xLabel, y, "Output Device");
		AddCombo(1, xCtrl, y - 2, w - xCtrl - 20, &ui_out_dev_text, &ui_out_dev_index, &g_outputDeviceNames); y += 34;

		AddLabel(1, xLabel, y, "Output Gain");
		AddSlider(1, xCtrl, y, 290, &ui_out_gain, 0, 200, ""); y += 40;

		id_btnLoad1 = AddButton(1, w - 190, y + 8, 80, 30, "Load");
		id_btnSave1 = AddButton(1, w - 100, y + 8, 80, 30, "Save");
	}

	{
		int xLabel = 16;
		int xCtrl  = 150;
		int y = contentTop + 10;

		AddCheck(2, xLabel, y, "GPIO PTT", &ui_gpio_ptt_en); y += 34;

		AddLabel(2, xLabel, y, "GPIO Pin");
		AddEdit(2, xCtrl, y - 2, w - xCtrl - 20, &ui_gpio_pin); y += 34;

		AddCheck(2, xLabel, y, "Active High", &ui_gpio_ah); y += 34;

		AddLabel(2, xLabel, y, "PTT Hold (ms)");
		AddEdit(2, xCtrl, y - 2, w - xCtrl - 20, &ui_gpio_hold_ms); y += 34;

		AddLabel(2, xLabel, y, "PTT Method");
		AddCombo(2, xCtrl, y - 2, w - xCtrl - 20, &ui_ptt_method, &ui_ptt_method_index, &g_pttMethodItems); y += 34;

		AddLabel(2, xLabel, y, "PTT cmd ON");
		AddEdit(2, xCtrl, y - 2, w - xCtrl - 20, &ui_ptt_cmd_on); y += 34;

		AddLabel(2, xLabel, y, "PTT cmd OFF");
		AddEdit(2, xCtrl, y - 2, w - xCtrl - 20, &ui_ptt_cmd_off); y += 34;

		id_btnLoad2 = AddButton(2, w - 190, y + 8, 80, 30, "Load");
		id_btnSave2 = AddButton(2, w - 100, y + 8, 80, 30, "Save");
	}

	const int gap           = 16;
	const int txHeight      = 52;
	const int rowHeight     = 30;
	const int cmdHeight     = 30;
	const int bottomPadding = 16;

	int cmdY = h - bottomPadding - cmdHeight;
	int row2Y = cmdY - gap - rowHeight;
	int txBtnY = row2Y - gap - txHeight;

	int bottomTop = txBtnY;
	int bottomAreaHeight = h - bottomTop;

	SDL_Rect rcTxBtnRect = { 16, txBtnY, w - 32, txHeight };
	int id_txButton = AddButton(-1, rcTxBtnRect.x, rcTxBtnRect.y + 4,
								rcTxBtnRect.w, rcTxBtnRect.h, "TALK");

	int id_parrotBtn = AddButton(-1, 16,  row2Y, 200, 30, "Parrot");
	int id_btnConnect = AddButton(-1, w - 216, row2Y, 200, 30, "Connect");

	int cmdX         = 16;
	int sendWidth    = 72;
	int cmdW = w - cmdX - sendWidth - 24;

	int id_cmdEdit = AddEdit(-1, cmdX, cmdY, cmdW, &ui_cmd);
	int id_sendBtn = AddButton(-1, w - sendWidth - 16, cmdY, sendWidth, cmdHeight, "Send");

	int logTop    = contentTop + 6;
	int logBottom = bottomTop - 10;
	int logHeight = logBottom - logTop;
	SDL_Rect rcLogCard = { 10, logTop, w - 20, logHeight };
	SDL_Rect rcLogInner = { rcLogCard.x + 8, rcLogCard.y + 24,
						 rcLogCard.w - 16, rcLogCard.h - 72 };

	int id_btnClearLog = AddButton(3, 20, rcLogCard.h + 16, 80, 30, "Clear Log");
	int id_btnSaveLog = AddButton(3, w - 100, rcLogCard.h + 16, 80, 30, "Save Log");

    bool running = true;
    SDL_StartTextInput();

    while (running) {
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) {
            if (ev.type == SDL_QUIT) {
                running = false;
			} else if (ev.type == SDL_MOUSEMOTION) {
				int mx = ev.motion.x;
				int my = ev.motion.y;
				SDL_Point pt = { mx, my };

				for (int i = 0; i < (int)g_widgets.size(); ++i) {
					Widget& wdg = g_widgets[i];
					bool visibleTab = (wdg.tab == -1 || wdg.tab == g_activeTab);
					if (!visibleTab) { wdg.hovered = false; continue; }
					wdg.hovered = SDL_PointInRect(&pt, &wdg.rect) ? true : false;
				}

				if (g_mouseDown && g_activeSlider >= 0 &&
					g_activeSlider < (int)g_widgets.size()) {

					Widget& wdg = g_widgets[g_activeSlider];
					if (wdg.type == W_SLIDER && wdg.boundValue && wdg.enabled) {
						int trackX = wdg.rect.x;
						int trackW = wdg.rect.w - 40;
						if (trackW < 40) trackW = 40;

						if (mx < trackX) mx = trackX;
						if (mx > trackX + trackW) mx = trackX + trackW;

						float t = float(mx - trackX) / float(trackW);
						int range = (wdg.maxValue > wdg.minValue) ? (wdg.maxValue - wdg.minValue) : 1;
						int newVal = wdg.minValue + int(t * range + 0.5f);
						*wdg.boundValue = newVal;
					}
				}
			} else if (ev.type == SDL_MOUSEBUTTONDOWN && ev.button.button == SDL_BUTTON_LEFT) {
				g_mouseDown = true;
				g_activeSlider = -1;

				int mx = ev.button.x;
				int my = ev.button.y;
				SDL_Point pt = { mx, my };

				if (SDL_PointInRect(&pt, &rcTabMain)) {
					g_activeTab = 0; g_focusWidget = -1; g_comboOpen = false;
					continue;
				} else if (SDL_PointInRect(&pt, &rcTabAudio)) {
					g_activeTab = 1; g_focusWidget = -1; g_comboOpen = false;
					continue;
				} else if (SDL_PointInRect(&pt, &rcTabGpio)) {
					g_activeTab = 2; g_focusWidget = -1; g_comboOpen = false;
					continue;
				} else if (SDL_PointInRect(&pt, &rcTabLog)) {
					g_activeTab = 3; g_focusWidget = -1; g_comboOpen = false;
					continue;
				}

				if (g_comboOpen && g_comboWidget >= 0 &&
					g_comboWidget < (int)g_widgets.size()) {
					Widget& cw = g_widgets[g_comboWidget];
					if (SDL_PointInRect(&pt, &g_comboPopupRect)) {
						if (cw.comboItems && !cw.comboItems->empty()) {
							int itemHeight = TTF_FontHeight(font) + 4;
							int relY = my - g_comboPopupRect.y;
							int idx  = relY / itemHeight;
							if (idx >= 0 && idx < (int)cw.comboItems->size()) {
								std::string oldTg = ui_talkgroup;

								if (cw.boundIndex) *cw.boundIndex = idx;
								if (cw.boundText)  *cw.boundText  = (*cw.comboItems)[idx];

								if (cw.boundIndex == &ui_tg_index && cw.boundText == &ui_talkgroup) {
									std::string newTg = ui_talkgroup;

									if (!newTg.empty() && newTg != oldTg &&
										g_connected && g_guiSock != INVALID_SOCKET) {

										g_cfg.talkgroup = newTg;

										std::ostringstream oss;
										oss << "JOIN " << newTg << "\n";
										std::string joinCmd = oss.str();

										if (!sendAll(g_guiSock, joinCmd.data(), joinCmd.size())) {
											GuiAppendLog("[ERROR] Failed to send JOIN for talkgroup " + newTg);
										} else {
											GuiAppendLog("Requesting switch to talkgroup: " + newTg);
										}
									}
								}
							}
						}
						g_comboOpen = false;
						g_comboWidget = -1;
						g_comboHoverItem = -1;
						continue;
					} else if (!SDL_PointInRect(&pt, &cw.rect)) {
						g_comboOpen = false;
						g_comboWidget = -1;
						g_comboHoverItem = -1;
					}
				}

				g_focusWidget = -1;
				for (int i = 0; i < (int)g_widgets.size(); ++i) {
					Widget& wdg = g_widgets[i];
					bool visibleTab = (wdg.tab == -1 || wdg.tab == g_activeTab);
					if (!visibleTab) {
						wdg.focused = false;
						continue;
					}

					bool hit = SDL_PointInRect(&pt, &wdg.rect);
					if (!hit) {
						wdg.focused = false;
						continue;
					}

					if (wdg.type == W_EDIT) {
						wdg.focused = true;
						g_focusWidget = i;

						if (wdg.boundText) {
							std::string& s = *wdg.boundText;

							int tx = wdg.rect.x + 6;
							int clickX = mx;

							if (clickX <= tx) {
								wdg.caretPos = 0;
							} else {
								int fullW = 0, fullH = 0;
								TTF_SizeUTF8(font, s.c_str(), &fullW, &fullH);

								int dx = clickX - tx;

								if (dx >= fullW) {
									wdg.caretPos = (int)s.size();
								} else {
									int pos = 0;
									for (int j = 1; j <= (int)s.size(); ++j) {
										std::string prefix = s.substr(0, j);
										int pw = 0, ph = 0;
										TTF_SizeUTF8(font, prefix.c_str(), &pw, &ph);
										if (pw >= dx) {
											pos = j;
											break;
										}
									}
									wdg.caretPos = pos;
								}
							}
						} else {
							wdg.caretPos = 0;
						}
					} else if (wdg.type == W_COMBO) {
						wdg.focused = true;
						g_focusWidget = i;
						if (g_comboOpen && g_comboWidget == i) {
							g_comboOpen = false;
							g_comboWidget = -1;
							g_comboHoverItem = -1;
						} else {
							g_comboOpen = true;
							g_comboWidget = i;
							g_comboHoverItem = -1;
						}

					} else if (wdg.type == W_CHECK && wdg.boundBool) {
						*wdg.boundBool = !*wdg.boundBool;
						wdg.focused = true;
						g_focusWidget = i;

					} else if (wdg.type == W_BUTTON) {
						if (!wdg.enabled)
							continue;

						if (i == id_txButton) {
							if (g_cfg.mode == "parrot" || g_cfg.vox_enabled) {
								GuiHandleCommand("t");
							} else {
								if (!g_guiPttThreadRunning) {
									g_guiPttHeld = true;
									std::thread(GuiPushToTalkLoop).detach();
								} else {
									g_guiPttHeld = true;
								}
							}
						} else if (i == id_parrotBtn) {
							GuiHandleCommand("/talk");
						} else if (i == id_sendBtn) {
							GuiHandleCommand(ui_cmd);
						} else if (i == id_btnConnect) {
							if (!g_connected) {
								UiToCfg();
								if (!GuiStartCore()) {
									GuiAppendLog("Connect failed");
								} else {
									wdg.label = "Disconnect";
								}
							} else {
								GuiStopCore();
								wdg.label = "Connect";
							}
						} else if (i == id_btnLoad1 || i == id_btnLoad2) {
							ClientConfig tmp;
							if (!loadClientConfig(g_cfgPath, tmp)) {
								GuiAppendLog("[ERROR] Failed to load config from: " + g_cfgPath);
							} else {
								g_cfg = tmp;
								CfgToUi();
								GuiAppendLog("Loaded config from: " + g_cfgPath);
							}
						} else if (i == id_btnSave1 || i == id_btnSave2) {
							UiToCfg();
							if (!saveClientConfigFile(g_cfgPath, g_cfg)) {
								GuiAppendLog("[ERROR] Failed to save config to: " + g_cfgPath);
							} else {
								GuiAppendLog("Saved config to: " + g_cfgPath);
							}
						} else if (i == id_btnSaveLog) {
							SaveLogToFile();
						} else if (i == id_btnClearLog) {
							ClearLog();
						}
					} else if (wdg.type == W_SLIDER && wdg.boundValue && wdg.enabled) {
						int trackX = wdg.rect.x;
						int trackW = wdg.rect.w - 40;
						if (trackW < 40) trackW = 40;

						if (mx < trackX) mx = trackX;
						if (mx > trackX + trackW) mx = trackX + trackW;

						float t = float(mx - trackX) / float(trackW);
						int range = (wdg.maxValue > wdg.minValue) ? (wdg.maxValue - wdg.minValue) : 1;
						int newVal = wdg.minValue + int(t * range + 0.5f);
						*wdg.boundValue = newVal;

						wdg.focused = true;
						g_focusWidget = i;

						g_activeSlider = i;
					}
				}
			} else if (ev.type == SDL_MOUSEBUTTONUP && ev.button.button == SDL_BUTTON_LEFT) {
				g_mouseDown = false;
				g_activeSlider = -1;

				if (!g_cfg.vox_enabled && g_cfg.mode != "parrot") {
					g_guiPttHeld = false;
				}
			} else if (ev.type == SDL_TEXTINPUT) {
				if (g_focusWidget >= 0 &&
					g_focusWidget < (int)g_widgets.size()) {
					Widget& wdg = g_widgets[g_focusWidget];
					if (wdg.type == W_EDIT && wdg.boundText) {
						std::string& s = *wdg.boundText;

						int len = (int)s.size();
						if (wdg.caretPos < 0 || wdg.caretPos > len)
							wdg.caretPos = len;

						const char* t = ev.text.text;
						int addLen = (int)std::strlen(t);

						s.insert(wdg.caretPos, t);
						wdg.caretPos += addLen;
					}
				}
            } else if (ev.type == SDL_KEYDOWN) {
                SDL_Keycode key = ev.key.keysym.sym;

                if (key == SDLK_ESCAPE) {
                    running = false;
				} else if (key == SDLK_BACKSPACE) {
					if (g_focusWidget >= 0 &&
						g_focusWidget < (int)g_widgets.size()) {
						Widget& wdg = g_widgets[g_focusWidget];
						if (wdg.type == W_EDIT && wdg.boundText) {
							std::string& s = *wdg.boundText;
							if (!s.empty() && wdg.caretPos > 0) {
								if (wdg.caretPos > (int)s.size())
									wdg.caretPos = (int)s.size();
								int erasePos = wdg.caretPos - 1;
								s.erase(erasePos, 1);
								wdg.caretPos--;
							}
						}
					}
				} else if (key == SDLK_LEFT || key == SDLK_RIGHT) {
					if (g_focusWidget >= 0 &&
						g_focusWidget < (int)g_widgets.size()) {
						Widget& wdg = g_widgets[g_focusWidget];
						if (wdg.type == W_EDIT && wdg.boundText) {
							std::string& s = *wdg.boundText;

							if (wdg.caretPos < 0) wdg.caretPos = 0;
							if (wdg.caretPos > (int)s.size())
								wdg.caretPos = (int)s.size();

							if (key == SDLK_LEFT && wdg.caretPos > 0) {
								wdg.caretPos--;
							} else if (key == SDLK_RIGHT &&
									   wdg.caretPos < (int)s.size()) {
								wdg.caretPos++;
							}
						}
					}
				} else if (key == SDLK_TAB) {
                    std::vector<int> focusable;
                    for (int i = 0; i < (int)g_widgets.size(); ++i) {
                        Widget& wdg = g_widgets[i];
                        bool visibleTab = (wdg.tab == -1 || wdg.tab == g_activeTab);
                        if (!visibleTab) continue;
                        if (wdg.type == W_EDIT || wdg.type == W_COMBO || wdg.type == W_CHECK)
                            focusable.push_back(i);
                    }
                    if (!focusable.empty()) {
                        int idx = 0;
                        if (g_focusWidget != -1) {
                            auto it = std::find(focusable.begin(), focusable.end(), g_focusWidget);
                            if (it != focusable.end())
                                idx = (int)((it - focusable.begin() + 1) % focusable.size());
                        }
                        g_focusWidget = focusable[idx];
                        for (int i = 0; i < (int)g_widgets.size(); ++i)
                            g_widgets[i].focused = false;
                        g_widgets[g_focusWidget].focused = true;
						if (g_widgets[g_focusWidget].type == W_EDIT && g_widgets[g_focusWidget].boundText) {
							g_widgets[g_focusWidget].caretPos = (int)g_widgets[g_focusWidget].boundText->size();
						}
                    }

                } else if (key == SDLK_RETURN || key == SDLK_KP_ENTER) {
                    if (g_focusWidget == id_cmdEdit) {
                        GuiHandleCommand(ui_cmd);
                    }
                }
            }
        }

        if (!g_inputDeviceNames.empty()) {
            if (ui_in_dev_index < 0) ui_in_dev_index = 0;
            if (ui_in_dev_index >= (int)g_inputDeviceNames.size())
                ui_in_dev_index = (int)g_inputDeviceNames.size() - 1;
            ui_in_dev_text = g_inputDeviceNames[ui_in_dev_index];
        } else {
            ui_in_dev_text = "(none)";
        }
        if (!g_outputDeviceNames.empty()) {
            if (ui_out_dev_index < 0) ui_out_dev_index = 0;
            if (ui_out_dev_index >= (int)g_outputDeviceNames.size())
                ui_out_dev_index = (int)g_outputDeviceNames.size() - 1;
            ui_out_dev_text = g_outputDeviceNames[ui_out_dev_index];
        } else {
            ui_out_dev_text = "(none)";
        }

        if (!g_tgComboItems.empty()) {
            if (ui_tg_index < 0) ui_tg_index = 0;
            if (ui_tg_index >= (int)g_tgComboItems.size())
                ui_tg_index = (int)g_tgComboItems.size() - 1;
            ui_talkgroup = g_tgComboItems[ui_tg_index];
        }

        auto clampSlider = [](int v) {
            if (v < 0)   v = 0;
            if (v > 200) v = 200;
            return v;
        };
        ui_in_gain  = clampSlider(ui_in_gain);
        ui_out_gain = clampSlider(ui_out_gain);

        g_inputGain  = ui_in_gain  / 100.0f;
        g_outputGain = ui_out_gain / 100.0f;

		if (id_txButton >= 0 && id_txButton < (int)g_widgets.size()) {
			bool enabled = g_connected && !g_isTalking.load();
			g_widgets[id_txButton].enabled = enabled;
		}

		if (id_btnConnect >= 0 && id_btnConnect < (int)g_widgets.size()) {
			if (g_connected)
				g_widgets[id_btnConnect].label = "Disconnect";
			else
				g_widgets[id_btnConnect].label = "Connect";
		}

        SDL_SetRenderDrawColor(renderer, COL_BG.r, COL_BG.g, COL_BG.b, COL_BG.a);
        SDL_RenderClear(renderer);

        DrawRect(renderer, rcTabBar, COL_TAB_BG);
        auto drawTab = [&](const SDL_Rect& rc, const char* label, int idx) {
            bool active = (g_activeTab == idx);
            SDL_Color frame = active ? COL_TAB_ACTIVE : COL_PANEL_BD;
            SDL_Color txt   = active ? COL_TAB_ACTIVE : COL_TAB_INACTIVE;
            DrawRectBorder(renderer, rc, frame, 2);
            DrawTextCentered(renderer, font, label, rc, txt);
        };
		drawTab(rcTabMain,  "Main",  0);
		drawTab(rcTabAudio, "Audio", 1);
		drawTab(rcTabGpio,  "GPIO",  2);
		drawTab(rcTabLog,   "Log",   3);

        if (g_activeTab == 0 || g_activeTab == 1 || g_activeTab == 2) {
            SDL_Rect rcContent = { 10, contentTop, w - 20, (h - bottomAreaHeight) - contentTop - 6 };
            DrawRect(renderer, rcContent, COL_PANEL);
            DrawRectBorder(renderer, rcContent, COL_PANEL_BD, 1);
        }

        if (g_activeTab == 3) {
            DrawRect(renderer, rcLogCard, COL_PANEL);
            DrawRectBorder(renderer, rcLogCard, COL_PANEL_BD, 1);
            DrawText(renderer, font, "Console log", rcLogCard.x + 8, rcLogCard.y + 6, COL_TEXT);

            DrawRect(renderer, rcLogInner, COL_INPUT_BG);
            DrawRectBorder(renderer, rcLogInner, COL_INPUT_BD, 1);

            SDL_RenderSetClipRect(renderer, &rcLogInner);

            {
                std::lock_guard<std::mutex> lock(g_logMutex);
                int lineHeight = TTF_FontHeight(font) + 2;
                int maxLines = rcLogInner.h / lineHeight;
                int start = (int)g_logLines.size() - maxLines;
                if (start < 0) start = 0;
                int yy = rcLogInner.y + 2;
				for (int i = start; i < (int)g_logLines.size(); ++i) {
					std::string line = g_logLines[i];
					while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
						line.pop_back();
					}

					DrawText(renderer, fontTiny, line,
							 rcLogInner.x + 4, yy, COL_TEXT_MUT);
					yy += lineHeight;
					if (yy > rcLogInner.y + rcLogInner.h - lineHeight) break;
				}
            }

            SDL_RenderSetClipRect(renderer, nullptr);
        }

        RenderWidgets(renderer, font);

		if (g_activeTab == 0) {
			int statusY = contentTop + 10 + 34 * 6 + 6;

			std::string status = g_connected ? "Connected" : "Disconnected";
			status += " / Mode: " + g_cfg.mode;
			DrawText(renderer, font, status, 130, statusY, COL_TEXT_MUT);

			int talkerTop    = statusY + 84;
			int talkerBottom = bottomTop - 10;
			int talkerHeight = 140;

			if (talkerTop + talkerHeight > talkerBottom) {
				talkerHeight = talkerBottom - talkerTop;
				if (talkerHeight < 40)
					talkerHeight = 40;
			}

			SDL_Rect rcTalkerCard = { 20, talkerTop, w - 40, talkerHeight };
			SDL_Rect rcTalkerInner = {
				rcTalkerCard.x + 8,
				rcTalkerCard.y + 24,
				rcTalkerCard.w - 16,
				rcTalkerCard.h - 32
			};

			DrawRect(renderer, rcTalkerCard, COL_PANEL);
			DrawRectBorder(renderer, rcTalkerCard, COL_PANEL_BD, 1);
			{
				const char* hdr = "Current User";
				int hW, hH;
				TTF_SizeUTF8(font, hdr, &hW, &hH);

				int hdrX = rcTalkerCard.x + (rcTalkerCard.w - hW) / 2;
				int hdrY = rcTalkerCard.y + 6;

				DrawText(renderer, font, hdr, hdrX, hdrY, COL_TEXT);
			}

			DrawRect(renderer, rcTalkerInner, COL_INPUT_BG);
			DrawRectBorder(renderer, rcTalkerInner, COL_INPUT_BD, 1);

			std::string talker = g_currentSpeaker.empty() ? "" : g_currentSpeaker;
			if (!talker.empty()) {
				int tw = 0, th = 0;
				TTF_SizeUTF8(fontBig, talker.c_str(), &tw, &th);

				int centerX = rcTalkerInner.x + (rcTalkerInner.w - tw) / 2;
				int centerY = rcTalkerInner.y + 10;

				DrawText(renderer, fontBig, talker, centerX, centerY, COL_TAB_ACTIVE);

				if (g_talkerActive.load()) {
					auto now  = std::chrono::steady_clock::now();
					auto diff = std::chrono::duration_cast<std::chrono::seconds>(
						now - g_talkerStart);
					int totalSec = (int)diff.count();
					if (totalSec < 0) totalSec = 0;
					int mm = totalSec / 60;
					int ss = totalSec % 60;

					std::ostringstream oss;
					if (mm < 10) oss << '0';
					oss << mm << ':';
					if (ss < 10) oss << '0';
					oss << ss;
					std::string dur = oss.str();

					int dW = 0, dH = 0;
					TTF_SizeUTF8(font, dur.c_str(), &dW, &dH);
					int durX = rcTalkerInner.x + (rcTalkerInner.w - dW) / 2;
					int durY = centerY + th + 6;
					DrawText(renderer, font, dur, durX, durY, COL_TEXT_MUT);

					float levelMic = g_audioLevel.load();
					float levelRx  = g_rxAudioLevel.load();

					auto clamp01 = [](float v) {
						if (v < 0.0f) return 0.0f;
						if (v > 1.0f) return 1.0f;
						return v;
					};

					levelMic = clamp01(levelMic);
					levelRx  = clamp01(levelRx);

					int totalBarWidth = rcTalkerInner.w - 40;
					if (totalBarWidth < 80) totalBarWidth = 80;

					int barHeight = 10;
					int barX      = rcTalkerInner.x + (rcTalkerInner.w - totalBarWidth) / 2;
					int barY      = durY + dH + 10;

					int gap = 20;
					int singleWidth = (totalBarWidth - gap) / 2;
					if (singleWidth < 40) singleWidth = 40;

					{
						const char* label = "Transmit";
						int lw = 0, lh = 0;
						TTF_SizeUTF8(font, label, &lw, &lh);
						int lx = barX + (singleWidth - lw) / 2;
						int ly = barY - lh - 2;
						DrawText(renderer, font, label, lx, ly, COL_TEXT_MUT);
					}

					{
						const char* label = "Receive";
						int lw = 0, lh = 0;
						TTF_SizeUTF8(font, label, &lw, &lh);
						int lx = barX + singleWidth + gap + (singleWidth - lw) / 2;
						int ly = barY - lh - 2;
						DrawText(renderer, font, label, lx, ly, COL_TEXT_MUT);
					}

					SDL_Rect micBg = { barX, barY, singleWidth, barHeight };
					DrawRect(renderer, micBg, COL_INPUT_BG);
					DrawRectBorder(renderer, micBg, COL_PANEL_BD, 1);

					SDL_Rect rxBg = { barX + singleWidth + gap, barY, singleWidth, barHeight };
					DrawRect(renderer, rxBg, COL_INPUT_BG);
					DrawRectBorder(renderer, rxBg, COL_PANEL_BD, 1);

					int micFillWidth = (int)(singleWidth * levelMic);
					if (micFillWidth > 0) {
						SDL_Rect micFill = {
							micBg.x + 1,
							micBg.y + 1,
							micFillWidth - 2,
							barHeight - 2
						};
						if (micFill.w < 0) micFill.w = 0;
						DrawRect(renderer, micFill, COL_TAB_ACTIVE);
					}

					int rxFillWidth = (int)(singleWidth * levelRx);
					if (rxFillWidth > 0) {
						SDL_Rect rxFill = {
							rxBg.x + 1,
							rxBg.y + 1,
							rxFillWidth - 2,
							barHeight - 2
						};
						if (rxFill.w < 0) rxFill.w = 0;
						DrawRect(renderer, rxFill, COL_TAB_ACTIVE);
					}
				}
			}
		}

        if (g_comboOpen && g_comboWidget >= 0 &&
            g_comboWidget < (int)g_widgets.size()) {
            Widget& cw = g_widgets[g_comboWidget];
            if (cw.type == W_COMBO && cw.comboItems &&
                !cw.comboItems->empty()) {

                int itemCount  = (int)cw.comboItems->size();
                int itemHeight = TTF_FontHeight(font) + 4;
                int popupH     = itemCount * itemHeight;
                int popupW     = cw.rect.w;
                int popupX     = cw.rect.x;
                int popupY     = cw.rect.y + cw.rect.h;

                g_comboPopupRect = makeRect(popupX, popupY, popupW, popupH);
                DrawRect(renderer, g_comboPopupRect, COL_PANEL);
                DrawRectBorder(renderer, g_comboPopupRect, COL_PANEL_BD, 1);

                for (int i = 0; i < itemCount; ++i) {
                    SDL_Rect irc = {
                        popupX + 2,
                        popupY + i * itemHeight + 2,
                        popupW - 4,
                        itemHeight - 4
                    };
                    if (i == g_comboHoverItem ||
                        (cw.boundIndex && *cw.boundIndex == i)) {
                        DrawRect(renderer, irc, COL_INPUT_BG);
                    }
                    DrawText(renderer, font, (*cw.comboItems)[i],
                             irc.x + 4, irc.y + 2, COL_TEXT);
                }
            }
        }
		
        SDL_RenderPresent(renderer);
    }

    GuiStopCore();

    SDL_StopTextInput();
    TTF_CloseFont(font);
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    TTF_Quit();
    SDL_Quit();
    return 0;
}
