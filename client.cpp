#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <string>
#include <sstream>
#include <chrono>
#include <limits>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstddef>
#include <cstdarg>
#include <ctime>
#include <cstdio>
#include <cmath>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #define NOMINMAX
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef int socklen_t;
  #pragma comment(lib, "Ws2_32.lib")
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <netdb.h>
  #include <unistd.h>
  #define INVALID_SOCKET -1
  #define SOCKET_ERROR -1
  typedef int SOCKET;
#endif

#if !defined(__ANDROID__)
#include <portaudio.h>
#else
#include <SDL.h>
#endif

extern "C" {
#if defined(__ANDROID__)
    static int cm108_set_gpio_pin(char*, int, int) { return -1; }
#else
    int cm108_set_gpio_pin(char *name, int num, int state);
#endif
}

static std::atomic<float> g_audioLevel(0.0f);

std::atomic<float> g_rxAudioLevel(0.0f);

std::atomic<bool> g_rxSquelchEnabled(false);
std::atomic<bool> g_rxSquelchAuto(true);
std::atomic<int>  g_rxSquelchLevel(55);
std::atomic<int>  g_rxSquelchVoicePct(55);
std::atomic<int>  g_rxSquelchHangMs(450);

static void stopAdpcmPlayoutThread();

#ifdef GUI
std::atomic<bool>  g_talkerActive(false);
std::chrono::steady_clock::time_point g_talkerStart;
#endif

static const size_t MAX_LINE_BYTES = 4096;
static const size_t MAX_RX_PAYLOAD = 256 * 1024;
static const size_t MAX_TX_PAYLOAD = 256 * 1024;

static std::string g_sockStash;

#define RESET       "\033[0m"
#define RED         "\033[1;31m"
#define GREEN       "\033[1;32m"
#define BLUE        "\033[1;34m"
#define YELLOW      "\033[1;33m"
#define CYAN        "\033[1;36m"
#define WHITE       "\033[1;37m"

enum LogColorLevel {
	LOG_RED,
	LOG_GREEN,
	LOG_YELLOW,
	LOG_BLUE,
	LOG_PURPLE,
	LOG_CYAN,
	LOG_WHITE
};


#ifdef _WIN32
void title() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD saved_attributes;

    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    saved_attributes = consoleInfo.wAttributes;

	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf ("=====================================================================\n");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf ("| ");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED); printf ("zFM ");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE); printf ("SERVER                          ");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf ("| ");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_BLUE); printf ("Digital Voice Communication");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf (" |\n");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf ("=====================================================================\n");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf ("| ");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); printf ("                  Programmed by Martin (13MAD86)                 ");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf (" |\n");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf ("=====================================================================\n\n");

    SetConsoleTextAttribute(hConsole, saved_attributes);
}
#else
void title() {
    printf(YELLOW "=====================================================================\n" RESET);
    printf(YELLOW "| " RESET);
    printf(RED "zFM " RESET);
    printf(CYAN "CLIENT                          " RESET);
    printf(YELLOW "| " RESET);
    printf(BLUE "Digital Voice Communication" RESET);
    printf(YELLOW " |\n" RESET);
    printf(YELLOW "=====================================================================\n" RESET);
    printf(YELLOW "| " RESET);
    printf(WHITE "               Programmed by Martin D. (Rikku2000)               " RESET);
    printf(YELLOW " |\n" RESET);
    printf(YELLOW "=====================================================================\n\n" RESET);
}
#endif

void logmsg(enum LogColorLevel level, int timed, const char *fmt, ...)
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "[%d.%m.%Y / %H:%M:%S]: ", t);

    va_list args;
    va_start(args, fmt);

#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD saved_attributes;

    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    saved_attributes = consoleInfo.wAttributes;

    switch (level) {
        case LOG_RED:    SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED); break;
        case LOG_GREEN:  SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_GREEN); break;
        case LOG_YELLOW: SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); break;
        case LOG_BLUE:   SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_BLUE); break;
        case LOG_PURPLE: SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_BLUE); break;
        case LOG_CYAN:   SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE); break;
        case LOG_WHITE:  SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); break;
    }

    if (timed == 1)
        printf("%s", timestr);
    vprintf(fmt, args);

    SetConsoleTextAttribute(hConsole, saved_attributes);
#else
    const char *color = "\033[0m";
    switch (level) {
        case LOG_RED:    color = "\033[31m"; break;
        case LOG_GREEN:  color = "\033[32m"; break;
        case LOG_YELLOW: color = "\033[33m"; break;
        case LOG_BLUE:   color = "\033[34m"; break;
        case LOG_PURPLE: color = "\033[35m"; break;
        case LOG_CYAN:   color = "\033[36m"; break;
        case LOG_WHITE:  color = "\033[37m"; break;
    }

    if (timed == 1)
        printf("%s%s", color, timestr);
    else
        printf("%s", color);

    vprintf(fmt, args);
    printf("\033[0m");
#endif

    va_end(args);
}

#define LOG_ERROR(...)  logmsg(LOG_RED,   1, __VA_ARGS__)
#define LOG_WARN(...)   logmsg(LOG_YELLOW,1, __VA_ARGS__)
#define LOG_INFO(...)   logmsg(LOG_WHITE, 1, __VA_ARGS__)
#define LOG_OK(...)     logmsg(LOG_GREEN, 1, __VA_ARGS__)
#define LOG_EVENT(...)  logmsg(LOG_CYAN,  1, __VA_ARGS__)

std::mutex g_speakerMutex;
std::string g_currentSpeaker;

std::atomic<bool> g_pttAutoEnabled(false);
std::atomic<bool> g_pttState(false);
std::atomic<std::chrono::steady_clock::time_point> g_lastRxAudioTime;
std::atomic<std::chrono::steady_clock::time_point> g_lastRxVoiceTime;
std::atomic<int> g_pttHoldMs(250);

static std::vector<int16_t> resampleMono16Linear(const std::vector<int16_t>& in, uint32_t inRate, uint32_t outRate);

void initSockets() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);
#endif
}

void cleanupSockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

void closeSocket(SOCKET s) {
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

static bool sendAll(SOCKET sock, const void* data, size_t len)
{
    const char* p = reinterpret_cast<const char*>(data);
    size_t sent = 0;

    while (sent < len) {
        size_t want = len - sent;

#ifdef _WIN32
        int n = ::send(sock, p + sent, (int)want, 0);
        if (n == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e == WSAEINTR) continue;
            return false;
        }
#else
        ssize_t n = ::send(sock, p + sent, want, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
#endif
        if (n == 0) return false;
        sent += (size_t)n;
    }
    return true;
}

static bool recvSome(SOCKET sock, void* out, size_t outCap, size_t& got)
{
    got = 0;
    if (outCap == 0) return true;

#ifdef _WIN32
    int n = ::recv(sock, (char*)out, (int)outCap, 0);
    if (n == 0) return false;
    if (n == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e == WSAEINTR) return recvSome(sock, out, outCap, got);
        return false;
    }
    got = (size_t)n;
    return true;
#else
    ssize_t n = ::recv(sock, out, outCap, 0);
    if (n == 0) return false;
    if (n < 0) {
        if (errno == EINTR) return recvSome(sock, out, outCap, got);
        return false;
    }
    got = (size_t)n;
    return true;
#endif
}

static bool recvAll(SOCKET sock, void* out, size_t len)
{
    char* dst = reinterpret_cast<char*>(out);
    size_t done = 0;

    if (!g_sockStash.empty() && len > 0) {
        size_t take = std::min(len, g_sockStash.size());
        std::memcpy(dst, g_sockStash.data(), take);
        g_sockStash.erase(0, take);
        done += take;
    }

    while (done < len) {
        size_t got = 0;
        if (!recvSome(sock, dst + done, len - done, got)) return false;
        if (got == 0) return false;
        done += got;
    }
    return true;
}

static bool recvLine(SOCKET sock, std::string& outLine)
{
    outLine.clear();

    for (;;) {
        size_t nl = g_sockStash.find('\n');
        if (nl != std::string::npos) {
            outLine = g_sockStash.substr(0, nl);
            g_sockStash.erase(0, nl + 1);
            if (!outLine.empty() && outLine.back() == '\r') outLine.pop_back();
            return true;
        }

        if (g_sockStash.size() >= MAX_LINE_BYTES) {
            return false;
        }

        char tmp[1024];
        size_t got = 0;
        if (!recvSome(sock, tmp, sizeof(tmp), got)) return false;
        if (got == 0) return false;

        g_sockStash.append(tmp, tmp + got);
    }
}

bool connectToServerHost(const std::string& host, int port, SOCKET& outSock)
{
    outSock = INVALID_SOCKET;
	g_sockStash.clear();
	{
		std::lock_guard<std::mutex> lock(g_speakerMutex);
		g_currentSpeaker.clear();
	}

#ifdef GUI
	g_talkerActive = false;
	g_rxAudioLevel = 0.0f;
	g_audioLevel   = 0.0f;
#endif

	g_lastRxAudioTime = std::chrono::steady_clock::now() - std::chrono::seconds(10);
	g_lastRxVoiceTime = std::chrono::steady_clock::now() - std::chrono::seconds(10);

    char portStr[16];
#ifdef _WIN32
    _snprintf_s(portStr, sizeof(portStr), _TRUNCATE, "%d", port);
#else
    std::snprintf(portStr, sizeof(portStr), "%d", port);
#endif

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = NULL;
    int rc = getaddrinfo(host.c_str(), portStr, &hints, &res);
    if (rc != 0 || res == NULL) {
        LOG_ERROR("getaddrinfo failed for %s:%d\n", host.c_str(), port);
        return false;
    }

    SOCKET s = INVALID_SOCKET;
    for (struct addrinfo* p = res; p != NULL; p = p->ai_next) {
        s = (SOCKET)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET) continue;

        if (connect(s, p->ai_addr, (int)p->ai_addrlen) == 0) {
            break;
        }

        closeSocket(s);
        s = INVALID_SOCKET;
    }

    freeaddrinfo(res);

    if (s == INVALID_SOCKET) {
#ifdef _WIN32
        int werr = WSAGetLastError();
		LOG_ERROR("Connect failed to %s:%d (WSA error %d)\n",host.c_str(), port, werr);
#else
        LOG_ERROR("Connect failed to %s:%d\n", host.c_str(), port);
#endif
        return false;
    }

    int flag = 1;
    if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                   (char*)&flag, sizeof(flag)) != 0) {
        LOG_WARN("Warning: failed to set TCP_NODELAY on client socket\n");
    }

    outSock = s;
    return true;
}

static inline std::string trim(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && (s[a]==' ' || s[a]=='\t' || s[a]=='\r' || s[a]=='\n')) a++;
    size_t b = s.size();
    while (b > a && (s[b-1]==' ' || s[b-1]=='\t' || s[b-1]=='\r' || s[b-1]=='\n')) b--;
    return s.substr(a, b-a);
}

static bool parseStringField(const std::string& line, const std::string& key, std::string& out) {
    std::string token = "\"" + key + "\"";
    if (line.find(token) == std::string::npos) return false;
    size_t colon = line.find(':', line.find(token));
    if (colon == std::string::npos) return false;
    size_t q1 = line.find('"', colon+1);
    if (q1 == std::string::npos) return false;
    size_t q2 = line.find('"', q1+1);
    if (q2 == std::string::npos) return false;
    out = line.substr(q1+1, q2 - q1 - 1);
    return true;
}

static bool parseIntField(const std::string& line, const std::string& key, int& out) {
    std::string token = "\"" + key + "\"";
    if (line.find(token) == std::string::npos) return false;
    size_t colon = line.find(':', line.find(token));
    if (colon == std::string::npos) return false;
    std::string num = trim(line.substr(colon+1));
    if (!num.empty() && num.back()==',') num.pop_back();
    out = std::atoi(num.c_str());
    return true;
}

static bool parseBoolField(const std::string& line, const std::string& key, bool& out) {
    std::string token = "\"" + key + "\"";
    if (line.find(token) == std::string::npos) return false;
    size_t colon = line.find(':', line.find(token));
    if (colon == std::string::npos) return false;
    std::string val = trim(line.substr(colon+1));
    if (!val.empty() && val.back()==',') val.pop_back();
    if (val == "true")  { out = true; return true; }
    if (val == "false") { out = false; return true; }
    return false;
}

struct ClientConfig {
    std::string mode;
    std::string server_ip;
    int server_port;
    std::string callsign;
    std::string password;
    std::string talkgroup;

    int sample_rate;
    unsigned long frames_per_buffer;
    int channels;

    int input_device_index;
    int output_device_index;

    bool gpio_ptt_enabled;
    int  gpio_ptt_pin;
    bool gpio_ptt_active_high;
    int  gpio_ptt_hold_ms;

	bool keyboard_ptt_enabled;
	int  keyboard_ptt_keycode;

    bool vox_enabled;
    int  vox_threshold;

    int  input_gain;
    int  output_gain;

    std::string ptt_cmd_on;
    std::string ptt_cmd_off;

    std::string ptt_serial_port;
    std::string ptt_serial_line;
    bool        ptt_serial_invert;

	int roger_sound;

	bool use_adpcm;
	bool adpcm_adaptive;
	int  adpcm_jitter_frames;
	int  adpcm_plc_ms;

	bool rx_squelch_enabled;
	bool rx_squelch_auto;
	int  rx_squelch_level;
	int  rx_squelch_voice_pct;
	int  rx_squelch_hang_ms;
};

bool loadClientConfig(const std::string& path, ClientConfig& cfg) {
    cfg.mode = "Server";
    cfg.server_ip = "127.0.0.1";
    cfg.server_port = 26613;
    cfg.callsign = "guest";
    cfg.password = "passw0rd";
    cfg.talkgroup = "Gateway";

    cfg.sample_rate = 22050;
    cfg.frames_per_buffer = 960;
    cfg.channels = 1;
    cfg.input_device_index = 0;
    cfg.output_device_index = 0;

    cfg.gpio_ptt_enabled = false;
    cfg.gpio_ptt_pin = 18;
    cfg.gpio_ptt_active_high = true;
    cfg.gpio_ptt_hold_ms = 250;

	cfg.keyboard_ptt_enabled = true;
	cfg.keyboard_ptt_keycode = 32;

    cfg.vox_enabled = false;
    cfg.vox_threshold = 5000;

    cfg.input_gain  = 100;
    cfg.output_gain = 100;

    cfg.ptt_cmd_on.clear();
    cfg.ptt_cmd_off.clear();
	
    cfg.ptt_serial_port.clear();
    cfg.ptt_serial_line = "RTS";
    cfg.ptt_serial_invert = false;
	cfg.roger_sound = 1;

	cfg.use_adpcm = false;
	cfg.adpcm_adaptive = true;
	cfg.adpcm_jitter_frames = 3;
	cfg.adpcm_plc_ms = 120;

	cfg.rx_squelch_enabled = false;
	cfg.rx_squelch_auto    = true;
	cfg.rx_squelch_level   = 55;
	cfg.rx_squelch_voice_pct = 55;
	cfg.rx_squelch_hang_ms = 450;

    std::ifstream f(path.c_str());
    if (!f.is_open()) {
        LOG_ERROR("Failed to open client config: %s\n", path.c_str());
        return false;
    }
	LOG_OK("Loaded client config from %s\n", path.c_str());

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) {
        lines.push_back(line);
    }

    for (size_t i = 0; i < lines.size(); ++i) {
        std::string l = trim(lines[i]);
        std::string sval;
        int ival;
        bool bval;

        if (parseStringField(l, "mode", sval)) cfg.mode = sval;
        else if (parseStringField(l, "server_ip", sval)) cfg.server_ip = sval;
        else if (parseIntField(l, "server_port", ival)) cfg.server_port = ival;
        else if (parseStringField(l, "callsign", sval)) cfg.callsign = sval;
        else if (parseStringField(l, "password", sval)) cfg.password = sval;
        else if (parseStringField(l, "talkgroup", sval)) cfg.talkgroup = sval;
        else if (parseIntField(l, "sample_rate", ival)) cfg.sample_rate = ival;
        else if (parseIntField(l, "frames_per_buffer", ival)) cfg.frames_per_buffer = (unsigned long)ival;
        else if (parseIntField(l, "channels", ival)) cfg.channels = ival;
        else if (parseIntField(l, "input_device_index", ival)) cfg.input_device_index = ival;
        else if (parseIntField(l, "output_device_index", ival)) cfg.output_device_index = ival;
        else if (parseBoolField(l, "ptt_enabled", bval)) cfg.gpio_ptt_enabled = bval;
        else if (parseIntField(l, "ptt_pin", ival)) cfg.gpio_ptt_pin = ival;
        else if (parseBoolField(l, "active_high", bval)) cfg.gpio_ptt_active_high = bval;
        else if (parseIntField(l, "ptt_hold_ms", ival)) cfg.gpio_ptt_hold_ms = ival;
		else if (parseBoolField(l, "keyboard_ptt_enabled", bval)) cfg.keyboard_ptt_enabled = bval;
		else if (parseIntField(l, "keyboard_ptt_keycode", ival)) cfg.keyboard_ptt_keycode = ival;
        else if (parseStringField(l, "ptt_cmd_on", sval))  cfg.ptt_cmd_on  = sval;
        else if (parseStringField(l, "ptt_cmd_off", sval)) cfg.ptt_cmd_off = sval;
        else if (parseStringField(l, "ptt_serial_port", sval)) cfg.ptt_serial_port = sval;
        else if (parseStringField(l, "ptt_serial_line", sval)) cfg.ptt_serial_line = sval;
        else if (parseBoolField(l, "ptt_serial_invert", bval)) cfg.ptt_serial_invert = bval;
        else if (parseBoolField(l, "vox_enabled", bval)) cfg.vox_enabled = bval;
        else if (parseIntField(l, "vox_threshold", ival)) cfg.vox_threshold = ival;
        else if (parseIntField(l, "input_gain", ival))    cfg.input_gain  = ival;
        else if (parseIntField(l, "output_gain", ival))   cfg.output_gain = ival;
		else if (parseIntField(l, "roger_sound", ival)) cfg.roger_sound = ival;
		else if (parseBoolField(l, "use_adpcm", bval)) cfg.use_adpcm = bval;
		else if (parseBoolField(l, "adpcm_adaptive", bval)) cfg.adpcm_adaptive = bval;
		else if (parseIntField(l, "adpcm_jitter_frames", ival)) cfg.adpcm_jitter_frames = ival;
		else if (parseIntField(l, "adpcm_plc_ms", ival)) cfg.adpcm_plc_ms = ival;
		else if (parseBoolField(l, "rx_squelch_enabled", bval)) cfg.rx_squelch_enabled = bval;
		else if (parseBoolField(l, "rx_squelch_auto", bval)) cfg.rx_squelch_auto = bval;
		else if (parseIntField(l,  "rx_squelch_level", ival)) cfg.rx_squelch_level = ival;
		else if (parseIntField(l,  "rx_squelch_voice_pct", ival)) cfg.rx_squelch_voice_pct = ival;
		else if (parseIntField(l,  "rx_squelch_hang_ms", ival)) cfg.rx_squelch_hang_ms = ival;
    }

    {
        std::string m = cfg.mode;
        std::transform(m.begin(), m.end(), m.begin(), [](unsigned char c){ return (char)tolower(c); });
        if (m == "Parrot") cfg.mode = "Parrot";
        else cfg.mode = "Server";
    }

    if (cfg.use_adpcm) {
		cfg.sample_rate       = 22050;
		cfg.frames_per_buffer = 960;
		cfg.channels          = 1;
	}

    return true;
}

static bool saveClientConfigFile(const std::string& path, const ClientConfig& cfg) {
    std::ofstream f(path.c_str());
    if (!f.is_open()) {
        std::cerr << "Failed to open client config for writing: " << path << "\n";
        return false;
    }

    f << "{\n";
    f << "  \"mode\": \"" << cfg.mode << "\",\n";
    f << "  \"server_ip\": \"" << cfg.server_ip << "\",\n";
    f << "  \"server_port\": " << cfg.server_port << ",\n";
    f << "  \"callsign\": \"" << cfg.callsign << "\",\n";
    f << "  \"password\": \"" << cfg.password << "\",\n";
    f << "  \"talkgroup\": \"" << cfg.talkgroup << "\",\n";
    f << "  \"sample_rate\": " << cfg.sample_rate << ",\n";
    f << "  \"frames_per_buffer\": " << cfg.frames_per_buffer << ",\n";
    f << "  \"channels\": " << cfg.channels << ",\n";
    f << "  \"input_device_index\": " << cfg.input_device_index << ",\n";
    f << "  \"output_device_index\": " << cfg.output_device_index << ",\n";
    f << "  \"ptt_enabled\": " << (cfg.gpio_ptt_enabled ? "true" : "false") << ",\n";
    f << "  \"ptt_pin\": " << cfg.gpio_ptt_pin << ",\n";
    f << "  \"active_high\": " << (cfg.gpio_ptt_active_high ? "true" : "false") << ",\n";
    f << "  \"ptt_hold_ms\": " << cfg.gpio_ptt_hold_ms << ",\n";
	f << "  \"keyboard_ptt_enabled\": " << (cfg.keyboard_ptt_enabled ? "true" : "false") << ",\n";
	f << "  \"keyboard_ptt_keycode\": " << cfg.keyboard_ptt_keycode << ",\n";
    f << "  \"vox_enabled\": " << (cfg.vox_enabled ? "true" : "false") << ",\n";
    f << "  \"vox_threshold\": " << cfg.vox_threshold << ",\n";
    f << "  \"input_gain\": " << cfg.input_gain << ",\n";
    f << "  \"output_gain\": " << cfg.output_gain << ",\n";
	f << "  \"roger_sound\": " << cfg.roger_sound << ",\n";
    f << "  \"ptt_cmd_on\": \""  << cfg.ptt_cmd_on  << "\",\n";
	f << "  \"ptt_cmd_off\": \"" << cfg.ptt_cmd_off << "\",\n";
	f << "  \"ptt_serial_port\": \"" << cfg.ptt_serial_port << "\",\n";
    f << "  \"ptt_serial_line\": \"" << cfg.ptt_serial_line << "\",\n";
    f << "  \"ptt_serial_invert\": " << (cfg.ptt_serial_invert ? "true" : "false") << ",\n";
    f << "  \"rx_squelch_enabled\": " << (cfg.rx_squelch_enabled ? "true" : "false") << ",\n";
	f << "  \"rx_squelch_auto\": " << (cfg.rx_squelch_auto ? "true" : "false") << ",\n";
	f << "  \"rx_squelch_level\": " << cfg.rx_squelch_level << ",\n";
	f << "  \"rx_squelch_voice_pct\": " << cfg.rx_squelch_voice_pct << ",\n";
	f << "  \"rx_squelch_hang_ms\": " << cfg.rx_squelch_hang_ms << ",\n";
	f << "  \"use_adpcm\": " << (cfg.use_adpcm ? "true" : "false") << ",\n";
	f << "  \"adpcm_adaptive\": " << (cfg.adpcm_adaptive ? "true" : "false") << ",\n";
	f << "  \"adpcm_jitter_frames\": " << cfg.adpcm_jitter_frames << ",\n";
	f << "  \"adpcm_plc_ms\": " << cfg.adpcm_plc_ms << "\n";
    f << "}\n";

    return true;
}

#if defined(__ANDROID__)
struct PaStream {};
using PaDeviceIndex = int;
struct PaDeviceInfo { const char* name; int maxInputChannels; int maxOutputChannels; };

static inline int Pa_GetDeviceCount() { return 1; }
static inline const PaDeviceInfo* Pa_GetDeviceInfo(PaDeviceIndex) {
    static PaDeviceInfo di{"Android Default", 1, 1};
    return &di;
}
static inline const char* Pa_GetErrorText(int) { return "PortAudio disabled on Android"; }

static std::mutex g_sdlAudioMutex;
#endif

PaStream* g_inputStream = NULL;
PaStream* g_outputStream = NULL;

#if !defined(__ANDROID__)
static std::mutex g_paOutMutex;
#endif

int g_sampleRate = 22050;
unsigned long g_framesPerBuffer = 960;
int g_channels = 1;

#if defined(__ANDROID__)
static SDL_AudioDeviceID g_sdlInDev  = 0;
static SDL_AudioDeviceID g_sdlOutDev = 0;
static SDL_AudioSpec     g_sdlInSpec;
static SDL_AudioSpec     g_sdlOutSpec;
static const int         ANDROID_MAX_QUEUE_MS = 250;

static inline void AndroidFlushMicQueue() {
    if (g_sdlInDev) SDL_ClearQueuedAudio(g_sdlInDev);
}
#endif

static bool audioOutWrite(const int16_t* samples, unsigned long frames) {
#if !defined(__ANDROID__)
    if (!g_outputStream || !samples || frames == 0) return false;

    std::lock_guard<std::mutex> lk(g_paOutMutex);

    long avail = Pa_GetStreamWriteAvailable(g_outputStream);
    if (avail >= 0 && (unsigned long)avail < frames) {
        static int dropCount = 0;
        dropCount++;
        if (dropCount <= 5 || (dropCount % 50) == 0) {
            LOG_WARN("Audio overrun protection: dropping %lu frames (avail=%ld)\n",
                     frames, avail);
        }

        if ((dropCount % 200) == 0) {
            Pa_AbortStream(g_outputStream);
            Pa_StartStream(g_outputStream);
        }
        return true;
    }

	PaError err = Pa_WriteStream(g_outputStream, samples, frames);

    static int underflowWarnCount = 0;
    if (err == paOutputUnderflowed) {
        if (underflowWarnCount < 5) {
            LOG_WARN("Warning: output underflow (audio may glitch)\n");
            underflowWarnCount++;
        }
        return true;
    }
    if (err != paNoError) {
        LOG_ERROR("Pa_WriteStream fatal error: %s\n", Pa_GetErrorText(err));
        return false;
    }
    return true;
#else
    if (!g_sdlOutDev || !samples || frames == 0) return false;

    const Uint32 bytes = (Uint32)(frames * (unsigned long)g_channels * sizeof(int16_t));

    const Uint32 maxQueueBytes = (Uint32)(
        (uint64_t)g_sampleRate * (uint64_t)g_channels * sizeof(int16_t) *
        (uint64_t)ANDROID_MAX_QUEUE_MS / 1000ULL
    );

    Uint32 q = SDL_GetQueuedAudioSize(g_sdlOutDev);
    if (q > maxQueueBytes) {
        SDL_ClearQueuedAudio(g_sdlOutDev);
        q = 0;
    }

    if (SDL_QueueAudio(g_sdlOutDev, samples, bytes) != 0) {
        LOG_WARN("SDL_QueueAudio failed: %s\n", SDL_GetError());
        return false;
    }
    return true;
#endif
}

static bool audioOutWriteBlockingChunked(const int16_t* samples, unsigned long frames)
{
#if defined(__ANDROID__)
    return audioOutWrite(samples, frames);
#else
    if (!g_outputStream || !samples || frames == 0) return false;

    std::lock_guard<std::mutex> lk(g_paOutMutex);

    const unsigned long chunk = (g_framesPerBuffer > 0) ? (unsigned long)g_framesPerBuffer : 480;

    unsigned long pos = 0;
    while (pos < frames) {
        unsigned long remain = frames - pos;
        unsigned long toWrite = (remain < chunk) ? remain : chunk;

        long avail = Pa_GetStreamWriteAvailable(g_outputStream);
        if (avail >= 0 && avail < (long)toWrite) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        PaError err = Pa_WriteStream(g_outputStream, samples + pos * g_channels, toWrite);
        if (err == paOutputUnderflowed) {

        } else if (err != paNoError) {
            LOG_ERROR("Pa_WriteStream (UI sound) error: %s\n", Pa_GetErrorText(err));
            return false;
        }

        pos += toWrite;
    }

    return true;
#endif
}

static bool g_pttUseShell = false;
static std::string g_pttCmdOn;
static std::string g_pttCmdOff;

static bool         g_pttUseCm108 = false;
static std::string  g_cm108Dev;
static int          g_cm108Pin    = 0;

extern ClientConfig g_cfg;

std::atomic<bool> g_running(true);

extern std::atomic<float> g_inputGain;
extern std::atomic<float> g_outputGain;

#define PTT_HAL_IMPLEMENTATION
#include "ptt_hal.h"

void pttManagerThreadFunc() {
    while (true) {
        auto now  = std::chrono::steady_clock::now();
        auto last = g_lastRxAudioTime.load();
        int holdMs = g_pttHoldMs.load();
        long long diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count();

        if (g_pttAutoEnabled) {
            if (diff <= holdMs) {
                if (!g_pttState.load()) {
                    g_pttState = true;
                    setPtt(true);
                }
            } else {
                if (g_pttState.load()) {
                    g_pttState = false;
                    setPtt(false);
                }
            }
        } else {
            if (g_pttState.load()) {
                g_pttState = false;
                setPtt(false);
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

#pragma pack(push, 1)
struct WavHeader {
    char riff[4];
    uint32_t size;
    char wave[4];
    char fmt[4];
    uint32_t fmtSize;
    uint16_t audioFormat;
    uint16_t numChannels;
    uint32_t sampleRate;
    uint32_t byteRate;
    uint16_t blockAlign;
    uint16_t bitsPerSample;
    char dataId[4];
    uint32_t dataSize;
};
#pragma pack(pop)

std::vector<int16_t> g_rogerSamples;
uint32_t g_rogerSampleRate = 0;

bool loadWavMono16(const std::string& path, std::vector<int16_t>& outPcm, uint32_t& outSampleRate) {
#if !defined(__ANDROID__)
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f.is_open()) {
        LOG_WARN("Roger WAV open failed: %s\n", path.c_str());
        return false;
    }

    WavHeader h;
    f.read(reinterpret_cast<char*>(&h), sizeof(h));
    if (!f.good()) {
        LOG_WARN("Failed to read WAV header for %s\n", path.c_str());
        return false;
    }

    if (std::strncmp(h.riff, "RIFF", 4) != 0 ||
        std::strncmp(h.wave, "WAVE", 4) != 0 ||
        std::strncmp(h.fmt,  "fmt ", 4)  != 0 ||
        std::strncmp(h.dataId, "data", 4) != 0) {
        LOG_WARN("%s is not a simple PCM WAV\n", path.c_str());
        return false;
    }

    if (h.audioFormat != 1 || h.numChannels != 1 || h.bitsPerSample != 16) {
        LOG_WARN("%s must be PCM, mono, 16-bit\n", path.c_str());
        return false;
    }

    outSampleRate = h.sampleRate;
    size_t numSamples = h.dataSize / sizeof(int16_t);
    outPcm.resize(numSamples);
    f.read(reinterpret_cast<char*>(outPcm.data()), h.dataSize);
    if (!f.good()) {
        LOG_WARN("Failed to read %s samples\n", path.c_str());
        return false;
    }
    return true;
#else
    (void)outSampleRate;

    SDL_AudioSpec srcSpec;
    Uint8* srcBuf = nullptr;
    Uint32 srcLen = 0;

	SDL_RWops* rw = SDL_RWFromFile(path.c_str(), "rb");
	if (!rw) SDL_Log("SDL_RWFromFile roger.wav failed: %s", SDL_GetError());

    if (!SDL_LoadWAV_RW(rw, 1, &srcSpec, &srcBuf, &srcLen)) {
        LOG_WARN("Roger WAV open failed (SDL_LoadWAV_RW): %s (%s)\n", path.c_str(), SDL_GetError());
        return false;
    }

    SDL_AudioSpec dstSpec;
    SDL_zero(dstSpec);

    dstSpec.freq     = g_sampleRate;
    dstSpec.format   = AUDIO_S16SYS;
    dstSpec.channels = 1;

    SDL_AudioCVT cvt;
    if (SDL_BuildAudioCVT(&cvt,
                          srcSpec.format, srcSpec.channels, srcSpec.freq,
                          dstSpec.format, dstSpec.channels, dstSpec.freq) < 0) {
        LOG_WARN("SDL_BuildAudioCVT failed for %s: %s\n", path.c_str(), SDL_GetError());
        SDL_FreeWAV(srcBuf);
        return false;
    }

    cvt.len = (int)srcLen;
    cvt.buf = (Uint8*)SDL_malloc((size_t)cvt.len * (size_t)cvt.len_mult);
    if (!cvt.buf) {
        LOG_WARN("SDL_malloc failed while loading %s\n", path.c_str());
        SDL_FreeWAV(srcBuf);
        return false;
    }
    SDL_memcpy(cvt.buf, srcBuf, srcLen);
    SDL_FreeWAV(srcBuf);

    if (SDL_ConvertAudio(&cvt) < 0) {
        LOG_WARN("SDL_ConvertAudio failed for %s: %s\n", path.c_str(), SDL_GetError());
        SDL_free(cvt.buf);
        return false;
    }

    const size_t outSamples = (size_t)cvt.len_cvt / sizeof(int16_t);
    outPcm.resize(outSamples);
    SDL_memcpy(outPcm.data(), cvt.buf, (size_t)cvt.len_cvt);
    SDL_free(cvt.buf);

    outSampleRate = (uint32_t)dstSpec.freq;
    return true;
#endif
}

void loadRogerSound(const std::string& path = "roger.wav") {
    g_rogerSamples.clear();
    g_rogerSampleRate = 0;
    if (!loadWavMono16(path, g_rogerSamples, g_rogerSampleRate)) {
        LOG_WARN("Roger sound not loaded, fallback to console message.\n");
    } else {
        LOG_OK("Loaded roger.wav (%zu samples @ %u Hz)\n",g_rogerSamples.size(), g_rogerSampleRate);
    }
}

void loadRogerFromConfig()
{
    g_rogerSamples.clear();
    g_rogerSampleRate = 0;

    std::string wav;

    switch (g_cfg.roger_sound) {
        case 0:
            LOG_INFO("Roger sound disabled (config roger_sound=0)\n");
            return;
        case 1:
            wav = "roger.wav";
            break;
        case 2:
            wav = "roger2.wav";
            break;
        case 3:
            wav = "roger3.wav";
            break;
        case 4:
            wav = "roger4.wav";
            break;
        default:
            wav = "roger.wav";
            break;
    }

    loadRogerSound(wav);
}

void playMicFreeSound() {
    if (!g_rogerSamples.empty()) {
        std::vector<int16_t> mono;
        if (g_rogerSampleRate != 0 && (uint32_t)g_sampleRate != g_rogerSampleRate) {
            mono = resampleMono16Linear(g_rogerSamples, g_rogerSampleRate, (uint32_t)g_sampleRate);
        } else {
            mono = g_rogerSamples;
        }

        std::vector<int16_t> out;
        if (g_channels == 1) {
            out = mono;
        } else {
            out.resize(mono.size() * (size_t)g_channels);
            for (size_t i = 0; i < mono.size(); ++i) {
                for (int ch = 0; ch < g_channels; ++ch) {
                    out[i * (size_t)g_channels + (size_t)ch] = mono[i];
                }
            }
        }

        unsigned long frames = (unsigned long)(out.size() / g_channels);
        audioOutWriteBlockingChunked(out.data(), frames);
    } else {
        LOG_INFO("[SOUND] Mic is now free!\n");
    }
}

void logPaDevices() {
    int devCount = Pa_GetDeviceCount();
    if (devCount < 0) {
        LOG_ERROR("Pa_GetDeviceCount error: %s\n", Pa_GetErrorText(devCount));
        return;
    }
    LOG_INFO("PortAudio devices:\n");
    for (int i = 0; i < devCount; ++i) {
        const PaDeviceInfo* info = Pa_GetDeviceInfo(i);
        if (!info) continue;
        LOG_INFO("  [%d] %s (in=%d, out=%d)\n", i, info->name, info->maxInputChannels, info->maxOutputChannels);
    }
    std::cout << std::flush;
}

bool findFirstInputDevice(PaDeviceIndex& idxOut) {
    int devCount = Pa_GetDeviceCount();
    for (int i = 0; i < devCount; ++i) {
        const PaDeviceInfo* info = Pa_GetDeviceInfo(i);
        if (info && info->maxInputChannels > 0) {
            idxOut = i;
            return true;
        }
    }
    return false;
}

bool findFirstOutputDevice(PaDeviceIndex& idxOut) {
    int devCount = Pa_GetDeviceCount();
    for (int i = 0; i < devCount; ++i) {
        const PaDeviceInfo* info = Pa_GetDeviceInfo(i);
        if (info && info->maxOutputChannels > 0) {
            idxOut = i;
            return true;
        }
    }
    return false;
}

#if !defined(__ANDROID__)
bool initPortAudio(const ClientConfig& cfg) {
    PaError err = Pa_Initialize();
    if (err != paNoError) {
        LOG_ERROR("PortAudio init error: %s\n", Pa_GetErrorText(err));
        return false;
    }

    logPaDevices();

    g_sampleRate      = cfg.sample_rate;
    g_framesPerBuffer = cfg.frames_per_buffer;

	g_rxSquelchEnabled  = cfg.rx_squelch_enabled;
	g_rxSquelchAuto     = cfg.rx_squelch_auto;
	g_rxSquelchLevel    = cfg.rx_squelch_level;
	g_rxSquelchVoicePct = cfg.rx_squelch_voice_pct;
	g_rxSquelchHangMs   = cfg.rx_squelch_hang_ms;

    int devCount = Pa_GetDeviceCount();
    if (devCount < 0) {
        LOG_ERROR("No input device with channels > 0 found.\n");
        return false;
    }

    PaDeviceIndex inIndex  = cfg.input_device_index;
    PaDeviceIndex outIndex = cfg.output_device_index;

    if (inIndex < 0 || inIndex >= devCount)  inIndex  = paNoDevice;
    if (outIndex < 0 || outIndex >= devCount) outIndex = paNoDevice;

    if (inIndex == paNoDevice || !Pa_GetDeviceInfo(inIndex) ||
        Pa_GetDeviceInfo(inIndex)->maxInputChannels <= 0) {
        if (!findFirstInputDevice(inIndex)) {
            std::cerr << "No input device with channels > 0 found.\n";
            return false;
        }
    }

    if (outIndex == paNoDevice || !Pa_GetDeviceInfo(outIndex) ||
        Pa_GetDeviceInfo(outIndex)->maxOutputChannels <= 0) {
        if (!findFirstOutputDevice(outIndex)) {
            LOG_ERROR("No output device with channels > 0 found.\n");
            return false;
        }
    }

    const PaDeviceInfo* inInfo  = Pa_GetDeviceInfo(inIndex);
    const PaDeviceInfo* outInfo = Pa_GetDeviceInfo(outIndex);
    if (!inInfo || !outInfo) {
        std::cerr << "Failed to get device info.\n";
        return false;
    }

    int ch = cfg.channels;
    if (ch <= 0) ch = 1;
    if (ch > inInfo->maxInputChannels)  ch = inInfo->maxInputChannels;
    if (ch > outInfo->maxOutputChannels) ch = outInfo->maxOutputChannels;

    if (ch <= 0) {
        std::cerr << "No common channel count between input and output devices.\n";
        return false;
    }

    g_channels = ch;

    LOG_INFO("Using audio:\n"
         "  input:  dev=%d (%s)\n"
         "  output: dev=%d (%s)\n",
         inIndex, Pa_GetDeviceInfo(inIndex)->name,
         outIndex, Pa_GetDeviceInfo(outIndex)->name);

    PaStreamParameters inParams;
    inParams.device = inIndex;
    inParams.channelCount = g_channels;
    inParams.sampleFormat = paInt16;
    inParams.suggestedLatency = inInfo->defaultLowInputLatency;
    inParams.hostApiSpecificStreamInfo = NULL;

    PaStreamParameters outParams;
    outParams.device = outIndex;
    outParams.channelCount = g_channels;
    outParams.sampleFormat = paInt16;

    double outLatency = outInfo->defaultHighOutputLatency;
    if (outLatency < outInfo->defaultLowOutputLatency * 2.0)
        outLatency = outInfo->defaultLowOutputLatency * 2.0;
    outParams.suggestedLatency = outLatency;
    outParams.hostApiSpecificStreamInfo = NULL;

    err = Pa_OpenStream(
        &g_inputStream,
        &inParams,
        NULL,
        g_sampleRate,
        g_framesPerBuffer,
        paClipOff,
        NULL,
        NULL
    );
    if (err != paNoError) {
        LOG_ERROR("Start input stream error: %s\n", Pa_GetErrorText(err));
        return false;
    }

    unsigned long outFramesPerBuffer = g_framesPerBuffer * 2;

    err = Pa_OpenStream(
        &g_outputStream,
        NULL,
        &outParams,
        g_sampleRate,
        outFramesPerBuffer,
        paClipOff,
        NULL,
        NULL
    );
    if (err != paNoError) {
        LOG_ERROR("Start output stream error: %s\n", Pa_GetErrorText(err));
        return false;
    }

    err = Pa_StartStream(g_inputStream);
    if (err != paNoError) {
        LOG_WARN("Warning: input overflow (some audio lost)\n");
        return false;
    }

    err = Pa_StartStream(g_outputStream);
    if (err != paNoError) {
        LOG_ERROR("Pa_ReadStream fatal error: %s\n", Pa_GetErrorText(err));
        return false;
    }

    {
        std::vector<int16_t> silence(outFramesPerBuffer * g_channels, 0);
        for (int i = 0; i < 3; ++i) {
            Pa_WriteStream(g_outputStream, silence.data(), outFramesPerBuffer);
        }
    }

    return true;
}
#else
bool initPortAudio(const ClientConfig& cfg) {
    g_sampleRate      = cfg.sample_rate;
    g_framesPerBuffer = cfg.frames_per_buffer;
    g_channels        = cfg.channels;

    g_rxSquelchEnabled  = cfg.rx_squelch_enabled;
    g_rxSquelchAuto     = cfg.rx_squelch_auto;
    g_rxSquelchLevel    = cfg.rx_squelch_level;
    g_rxSquelchVoicePct = cfg.rx_squelch_voice_pct;
    g_rxSquelchHangMs   = cfg.rx_squelch_hang_ms;

    SDL_AudioSpec want;
    SDL_zero(want);
    want.freq     = g_sampleRate;
    want.format   = AUDIO_S16SYS;
    want.channels = (Uint8)g_channels;
    want.samples  = (Uint16)g_framesPerBuffer;
    want.callback = nullptr;

    SDL_zero(g_sdlOutSpec);
    g_sdlOutDev = SDL_OpenAudioDevice(nullptr, 0, &want, &g_sdlOutSpec, SDL_AUDIO_ALLOW_FREQUENCY_CHANGE);
    if (!g_sdlOutDev) {
        LOG_ERROR("SDL_OpenAudioDevice(output) failed: %s\n", SDL_GetError());
        return false;
    }

    SDL_zero(g_sdlInSpec);
    g_sdlInDev = SDL_OpenAudioDevice(nullptr, 1, &want, &g_sdlInSpec, SDL_AUDIO_ALLOW_FREQUENCY_CHANGE);
    if (!g_sdlInDev) {
        LOG_ERROR("SDL_OpenAudioDevice(input) failed: %s\n", SDL_GetError());
        SDL_CloseAudioDevice(g_sdlOutDev); g_sdlOutDev = 0;
        return false;
    }

    g_sampleRate = g_sdlOutSpec.freq;
    g_channels   = g_sdlOutSpec.channels;

    SDL_PauseAudioDevice(g_sdlOutDev, 0);
    SDL_PauseAudioDevice(g_sdlInDev, 0);

    LOG_OK("Android SDL audio ready: %d Hz, ch=%d, fpb=%lu\n", g_sampleRate, g_channels, g_framesPerBuffer);
    return true;
}
#endif

#if !defined(__ANDROID__)
void shutdownPortAudio() {
	stopAdpcmPlayoutThread();
    if (g_inputStream) {
        Pa_StopStream(g_inputStream);
        Pa_CloseStream(g_inputStream);
        g_inputStream = NULL;
    }
    if (g_outputStream) {
        Pa_StopStream(g_outputStream);
        Pa_CloseStream(g_outputStream);
        g_outputStream = NULL;
    }
    Pa_Terminate();
}
#else
void shutdownPortAudio() {
	stopAdpcmPlayoutThread();
    std::lock_guard<std::mutex> lk(g_sdlAudioMutex);
    if (g_sdlInDev)  {
        SDL_PauseAudioDevice(g_sdlInDev, 1);
        SDL_ClearQueuedAudio(g_sdlInDev);
        SDL_CloseAudioDevice(g_sdlInDev);
        g_sdlInDev = 0;
    }
    if (g_sdlOutDev) {
        SDL_PauseAudioDevice(g_sdlOutDev, 1);
        SDL_ClearQueuedAudio(g_sdlOutDev);
        SDL_CloseAudioDevice(g_sdlOutDev);
        g_sdlOutDev = 0;
    }
}
#endif

static void applySoftLimiter(std::vector<int16_t>& samples, float threshold)
{
    if (threshold <= 0.0f || threshold > 1.0f) threshold = 0.9f;
    const float t = threshold * 32767.0f;

    for (size_t i = 0; i < samples.size(); ++i) {
        float v = (float)samples[i];
        float av = std::fabs(v);
        if (av > t) {
            float sign = (v >= 0.0f) ? 1.0f : -1.0f;
            float over = av - t;
            v = sign * (t + over * 0.25f);
            if (v > 32767.0f)  v = 32767.0f;
            if (v < -32768.0f) v = -32768.0f;
            samples[i] = (int16_t)v;
        }
    }
}

#if !defined(__ANDROID__)
std::vector<char> captureAudioFrame() {
    std::vector<int16_t> samples(g_framesPerBuffer * g_channels);
    PaError err = Pa_ReadStream(g_inputStream, samples.data(), g_framesPerBuffer);

    static int overflowWarnCount = 0;

    if (err == paInputOverflowed) {
        if (overflowWarnCount < 5) {
            std::cerr << "Warning: input overflow (some audio lost)\n";
            overflowWarnCount++;
        }
    } else if (err != paNoError) {
        std::cerr << "Pa_ReadStream fatal error: " << Pa_GetErrorText(err) << "\n";
        return std::vector<char>();
    }

    float gain = g_inputGain.load();
    if (gain != 1.0f) {
        for (size_t i = 0; i < samples.size(); ++i) {
            float v = samples[i] * gain;
            if (v > 32767.0f)  v = 32767.0f;
            if (v < -32768.0f) v = -32768.0f;
            samples[i] = static_cast<int16_t>(v);
        }
    }

    if (!samples.empty()) {
        applySoftLimiter(samples, 0.9f);
    }

    std::vector<char> bytes(samples.size() * sizeof(int16_t));
    std::memcpy(bytes.data(), samples.data(), bytes.size());
    return bytes;
}
#else
std::vector<char> captureAudioFrame() {
    std::lock_guard<std::mutex> lk(g_sdlAudioMutex);

    const Uint32 bytesNeeded = (Uint32)(g_framesPerBuffer * (unsigned long)g_channels * sizeof(int16_t));
    if (!g_sdlInDev || bytesNeeded == 0) return {};

    for (int spins = 0; spins < 200; ++spins) {
        Uint32 have = SDL_GetQueuedAudioSize(g_sdlInDev);
        if (have >= bytesNeeded) break;
        SDL_Delay(2);
        if (!g_running) return {};
        if (!g_sdlInDev) return {};
    }

    std::vector<char> bytes(bytesNeeded);
    Uint32 got = SDL_DequeueAudio(g_sdlInDev, bytes.data(), bytesNeeded);
    if (got < bytesNeeded) bytes.resize(got);
    if (got < bytesNeeded) {
        bytes.resize(got);
        if (bytes.empty()) return {};
    }

    size_t sampleCount = bytes.size() / sizeof(int16_t);
    int16_t* samples = (int16_t*)bytes.data();

    float gain = g_inputGain.load();
    if (gain != 1.0f) {
        for (size_t i = 0; i < sampleCount; ++i) {
            float v = samples[i] * gain;
            if (v > 32767.0f)  v = 32767.0f;
            if (v < -32768.0f) v = -32768.0f;
            samples[i] = (int16_t)v;
        }
    }

    if (sampleCount > 0) {
        std::vector<int16_t> tmp(samples, samples + sampleCount);
        applySoftLimiter(tmp, 0.9f);
        std::memcpy(samples, tmp.data(), sampleCount * sizeof(int16_t));
    }

    return bytes;
}
#endif

struct RxVoiceMetrics {
    float rms;
    float voiceRatio;
    RxVoiceMetrics() : rms(0.0f), voiceRatio(0.0f) {}
};

static RxVoiceMetrics analyzeRxVoice(const int16_t* samples, size_t sampleCount, int channels, int sampleRate) {
	RxVoiceMetrics m;
	if (!samples || sampleCount == 0 || channels <= 0 || sampleRate <= 0) return m;

	static float hp_y = 0.0f;
	static float hp_x1 = 0.0f;
	static float lp_y = 0.0f;

	float dt = 1.0f / (float)sampleRate;
	float rc_hp = 1.0f / (2.0f * 3.14159265f * 300.0f);
	float a = rc_hp / (rc_hp + dt);
	float rc_lp = 1.0f / (2.0f * 3.14159265f * 3000.0f);
	float b = rc_lp / (rc_lp + dt);

	double sumSq = 0.0;
	double sumBandSq = 0.0;
	size_t frames = sampleCount / (size_t)channels;

	for (size_t f = 0; f < frames; ++f) {
		double acc = 0.0;
		for (int c = 0; c < channels; ++c) {
			acc += samples[f * (size_t)channels + (size_t)c] / 32768.0;
		}
		float x = (float)(acc / (double)channels);
		sumSq += (double)x * (double)x;

		float hp = a * (hp_y + x - hp_x1);
		hp_y = hp;
		hp_x1 = x;
		float lp = b * lp_y + (1.0f - b) * hp;
		lp_y = lp;

		sumBandSq += (double)lp * (double)lp;
	}

	if (frames > 0) {
		m.rms = (float)std::sqrt(sumSq / (double)frames);
		double totalE = sumSq / (double)frames;
		double bandE  = sumBandSq / (double)frames;
		m.voiceRatio = (totalE > 1e-12) ? (float)(bandE / totalE) : 0.0f;
		if (m.voiceRatio < 0.0f) m.voiceRatio = 0.0f;
		if (m.voiceRatio > 1.0f) m.voiceRatio = 1.0f;
	}

	return m;
}

static const int NET_AUDIO_RATE = 22050;

struct LinearResamplerState {
    double pos;
    std::vector<int16_t> lastFrame;
    bool hasLast;

    LinearResamplerState() : pos(0.0), lastFrame(), hasLast(false) {}
};

static int round_to_int(double v) {
    if (v >= 0.0) return (int)floor(v + 0.5);
    return (int)ceil(v - 0.5);
}

static int16_t sample_at(const int16_t* in,
                             size_t inFrames,
                             int channels,
                             const LinearResamplerState& st,
                             size_t frameIndex,
                             int ch)
{
    if (frameIndex == 0) return st.lastFrame[(size_t)ch];
    size_t srcFrame = frameIndex - 1;
    if (srcFrame >= inFrames) srcFrame = inFrames ? (inFrames - 1) : 0;
    return in[srcFrame * (size_t)channels + (size_t)ch];
}


static std::vector<int16_t> resampleMono16Linear(const std::vector<int16_t>& in,
                                                 uint32_t inRate,
                                                 uint32_t outRate)
{
    std::vector<int16_t> out;
    if (in.empty() || inRate == 0 || outRate == 0) return out;
    if (inRate == outRate) return in;

    const double ratio = (double)outRate / (double)inRate;
    const size_t outCount = (size_t)std::max<double>(1.0, std::floor((double)in.size() * ratio));
    out.resize(outCount);

    for (size_t i = 0; i < outCount; ++i) {
        const double srcPos = (double)i / ratio;
        const size_t idx = (size_t)srcPos;
        const double frac = srcPos - (double)idx;

        const int16_t s0 = in[std::min(idx, in.size() - 1)];
        const int16_t s1 = in[std::min(idx + 1, in.size() - 1)];

        const double v = (1.0 - frac) * (double)s0 + frac * (double)s1;
		long vv = (long)round_to_int(v);
        if (vv > 32767) vv = 32767;
        if (vv < -32768) vv = -32768;
        out[i] = (int16_t)vv;
    }

    return out;
}

static std::vector<int16_t> resampleLinearInterleaved(const int16_t* in,
                                                      size_t inFrames,
                                                      int channels,
                                                      int inRate,
                                                      int outRate,
                                                      LinearResamplerState& st)
{
    std::vector<int16_t> out;
    if (!in || inFrames == 0 || channels <= 0 || inRate <= 0 || outRate <= 0) return out;

    if (!st.hasLast) {
        st.lastFrame.assign((size_t)channels, 0);
        for (int c = 0; c < channels; ++c) {
            st.lastFrame[(size_t)c] = in[(size_t)c];
        }
        st.hasLast = true;
        st.pos = 1.0;
    }

    const size_t totalFrames = inFrames + 1;
    const double step = (double)inRate / (double)outRate;

    const size_t estOutFrames = (size_t)ceil(((double)inFrames) * ((double)outRate / (double)inRate)) + 4;
    out.reserve(estOutFrames * (size_t)channels);

    while (st.pos < (double)(totalFrames - 1)) {
        const size_t i0 = (size_t)st.pos;
        const double frac = st.pos - (double)i0;
        const size_t i1 = i0 + 1;

        for (int c = 0; c < channels; ++c) {
            const int16_t s0 = sample_at(in, inFrames, channels, st, i0, c);
            const int16_t s1 = sample_at(in, inFrames, channels, st, i1, c);
            const double v = (1.0 - frac) * (double)s0 + frac * (double)s1;
            int iv = round_to_int(v);
            if (iv > 32767) iv = 32767;
            if (iv < -32768) iv = -32768;
            out.push_back((int16_t)iv);
        }

        st.pos += step;
    }

    st.pos -= (double)inFrames;

    st.lastFrame.resize((size_t)channels);
    const size_t lastOff = (inFrames - 1) * (size_t)channels;
    for (int c = 0; c < channels; ++c) {
        st.lastFrame[(size_t)c] = in[lastOff + (size_t)c];
    }

    return out;
}

void playAudioFrame(const std::vector<char>& frame) {
    if (frame.empty()) return;

    size_t sampleCount = frame.size() / sizeof(int16_t);
    unsigned long inFrames = (unsigned long)(sampleCount / g_channels);
    if (inFrames == 0) return;

    const int16_t* inSamples = reinterpret_cast<const int16_t*>(frame.data());

    static LinearResamplerState s_rxResampler;
    std::vector<int16_t> resampled;
    if (g_sampleRate != NET_AUDIO_RATE) {
        resampled = resampleLinearInterleaved(inSamples,
                                              (size_t)inFrames,
                                              g_channels,
                                              NET_AUDIO_RATE,
                                              g_sampleRate,
                                              s_rxResampler);
        if (resampled.empty()) return;
        inSamples = resampled.data();
        sampleCount = resampled.size();
        inFrames = (unsigned long)(sampleCount / (size_t)g_channels);
        if (inFrames == 0) return;
    }

    float gain = g_outputGain.load();
    std::vector<int16_t> outSamples(sampleCount);

    if (gain == 1.0f) {
        std::memcpy(outSamples.data(), inSamples, sampleCount * sizeof(int16_t));
    } else {
        for (size_t i = 0; i < sampleCount; ++i) {
            float v = inSamples[i] * gain;
            if (v > 32767.0f)  v = 32767.0f;
            if (v < -32768.0f) v = -32768.0f;
            outSamples[i] = static_cast<int16_t>(v);
        }
    }

    if (!outSamples.empty()) {
        applySoftLimiter(outSamples, 0.95f);
    }

	static bool gateOpen = true;
	static std::chrono::steady_clock::time_point lastVoice = std::chrono::steady_clock::now();
	static std::chrono::steady_clock::time_point lastAudio = std::chrono::steady_clock::now();
	static float noiseFloor = 0.015f;

	const bool sqEnabled = g_rxSquelchEnabled.load();
	const bool sqAuto    = g_rxSquelchAuto.load();
	int sqLevel          = g_rxSquelchLevel.load();
	int sqVoicePct       = g_rxSquelchVoicePct.load();
	int sqHangMs         = g_rxSquelchHangMs.load();
	if (sqLevel < 0) sqLevel = 0; if (sqLevel > 100) sqLevel = 100;
	if (sqVoicePct < 0) sqVoicePct = 0; if (sqVoicePct > 100) sqVoicePct = 100;
	if (sqHangMs < 0) sqHangMs = 0; if (sqHangMs > 5000) sqHangMs = 5000;

	RxVoiceMetrics met = analyzeRxVoice(outSamples.data(), sampleCount, g_channels, g_sampleRate);

	float t = (float)sqLevel / 100.0f;
	float thrStatic = 0.08f + (0.01f - 0.08f) * t;
	float voiceThr  = (float)sqVoicePct / 100.0f;

	float thr = thrStatic;
	if (sqAuto) {
		bool looksVoice = (met.voiceRatio >= voiceThr);
		if (!gateOpen && !looksVoice) {
			noiseFloor = noiseFloor * 0.995f + met.rms * 0.005f;
			if (noiseFloor < 0.004f) noiseFloor = 0.004f;
			if (noiseFloor > 0.30f)  noiseFloor = 0.30f;
		}
		thr = std::max(0.008f, noiseFloor * 2.8f);
		thr *= (1.4f - 0.7f * t);
	}

	bool isVoiceNow = (met.rms >= thr) && (met.voiceRatio >= voiceThr);
	auto now = std::chrono::steady_clock::now();
	if (isVoiceNow) {
		lastVoice = now;
		lastAudio = now;
		gateOpen = true;
	}

	if (sqEnabled) {
		long long sinceVoiceMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastVoice).count();
		if (sinceVoiceMs > (long long)sqHangMs) {
			gateOpen = false;
		}
		if (!gateOpen) {
			std::fill(outSamples.begin(), outSamples.end(), 0);
		}
	}

	if (!sqEnabled || gateOpen) {
		g_lastRxAudioTime = std::chrono::steady_clock::now();
	}

	{
		bool nonZero = false;
		for (size_t i = 0; i < sampleCount; ++i) {
			if (outSamples[i] != 0) { nonZero = true; break; }
		}
		if (nonZero) {
			g_lastRxVoiceTime = std::chrono::steady_clock::now();
		}
	}

	audioOutWrite(outSamples.data(), inFrames);

#ifdef GUI
    const int16_t* samples = outSamples.data();
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

        float old = g_rxAudioLevel.load();
        g_rxAudioLevel = old * 0.7f + level * 0.3f;
    }
#endif
}

std::atomic<bool> g_canTalk(false);
std::atomic<int>  g_maxTalkMs(0);
ClientConfig g_cfg;

std::atomic<float> g_inputGain(1.0f);
std::atomic<float> g_outputGain(1.0f);

std::mutex g_tgListMutex;
std::vector<std::string> g_serverTalkgroups;

#ifdef GUI
extern std::vector<std::string> g_tgComboItems;
extern int ui_tg_index;
#if defined(__linux__)
static std::string ui_talkgroup;
#else
extern std::string ui_talkgroup;
#endif
#endif

static const int VOX_TRIGGER_FRAMES_NEEDED  = 6;
static const int VOX_SILENCE_FRAMES_NEEDED  = 100;
static const int VOX_SPEAK_GRANT_TIMEOUT_MS = 50;

static const int VOX_CALIB_FRAMES        = 40;
static const int VOX_MIN_THRESHOLD_PEAK  = 1000;
static const int VOX_MAX_THRESHOLD_PEAK  = 25000;

#include <map>
#include <deque>

std::vector<char> captureAudioFrame();
void playAudioFrame(const std::vector<char>& pcm);

static std::mutex g_adpcmJbMutex;
static std::atomic<bool> g_adpcmPlayoutRun(false);
static std::thread g_adpcmPlayoutThread;

static inline int clamp16i(int v) {
    if (v > 32767) return 32767;
    if (v < -32768) return -32768;
    return v;
}

static const int g_imaIndexTable[16] = {
    -1,-1,-1,-1, 2,4,6,8,
    -1,-1,-1,-1, 2,4,6,8
};
static const int g_imaStepTable[89] = {
     7,8,9,10,11,12,13,14,16,17,
     19,21,23,25,28,31,34,37,41,45,
     50,55,60,66,73,80,88,97,107,118,
     130,143,157,173,190,209,230,253,279,307,
     337,371,408,449,494,544,598,658,724,796,
     876,963,1060,1166,1282,1411,1552,1707,1878,2066,
     2272,2499,2749,3024,3327,3660,4026,4428,4871,5358,
     5894,6484,7132,7845,8630,9493,10442,11487,12635,13899,
     15289,16818,18500,20350,22385,24623,27086,29794,32767
};

static inline int clamp16(int v) {
    return (v > 32767) ? 32767 : (v < -32768 ? -32768 : v);
}

static std::vector<char> imaAdpcmEncode(const int16_t* pcm, size_t n)
{
    std::vector<char> out;
    if (!pcm || n < 1) return out;

    int pred = pcm[0];
    int idx  = 0;

    out.resize(4);
    out[0] = (char)(pred & 0xFF);
    out[1] = (char)((pred >> 8) & 0xFF);
    out[2] = (char)(idx & 0xFF);
    out[3] = 0;

    int step = g_imaStepTable[idx];
    unsigned char curByte = 0;
    bool highNibble = false;

    for (size_t i = 1; i < n; ++i) {
        int diff = (int)pcm[i] - pred;
        int sign = (diff < 0) ? 8 : 0;
        if (diff < 0) diff = -diff;

        int delta = 0;
        int vpdiff = step >> 3;

        if (diff >= step) { delta |= 4; diff -= step; vpdiff += step; }
        if (diff >= (step >> 1)) { delta |= 2; diff -= (step >> 1); vpdiff += (step >> 1); }
        if (diff >= (step >> 2)) { delta |= 1; vpdiff += (step >> 2); }

        if (sign) pred -= vpdiff; else pred += vpdiff;
        pred = clamp16i(pred);

        delta |= sign;

        idx += g_imaIndexTable[delta & 0x0F];
        if (idx < 0) idx = 0;
        if (idx > 88) idx = 88;
        step = g_imaStepTable[idx];

        unsigned char nib = (unsigned char)(delta & 0x0F);
        if (!highNibble) {
            curByte = nib;
            highNibble = true;
        } else {
            curByte |= (unsigned char)(nib << 4);
            out.push_back((char)curByte);
            highNibble = false;
        }
    }

    if (highNibble) {
        out.push_back((char)curByte);
    }

    out[2] = (char)(idx & 0xFF);
    return out;
}

static std::vector<int16_t> imaAdpcmDecode(const char* data, size_t len, size_t outSamples)
{
    std::vector<int16_t> pcm;
    if (!data || len < 4 || outSamples < 1) return pcm;

    int pred = (int)(int16_t)((unsigned char)data[0] | ((unsigned char)data[1] << 8));
    int idx  = (int)(unsigned char)data[2];
    if (idx < 0) idx = 0;
    if (idx > 88) idx = 88;

    int step = g_imaStepTable[idx];
    pcm.resize(outSamples);
    pcm[0] = (int16_t)pred;

    size_t si = 1;
    for (size_t bi = 4; bi < len && si < outSamples; ++bi) {
        unsigned char b = (unsigned char)data[bi];
        for (int half = 0; half < 2 && si < outSamples; ++half) {
            int delta = (half == 0) ? (b & 0x0F) : ((b >> 4) & 0x0F);
            idx += g_imaIndexTable[delta];
            if (idx < 0) idx = 0;
            if (idx > 88) idx = 88;

            int sign = delta & 8;
            int mag  = delta & 7;

            int vpdiff = step >> 3;
            if (mag & 4) vpdiff += step;
            if (mag & 2) vpdiff += (step >> 1);
            if (mag & 1) vpdiff += (step >> 2);

            if (sign) pred -= vpdiff; else pred += vpdiff;
            pred = clamp16i(pred);

            step = g_imaStepTable[idx];
            pcm[si++] = (int16_t)pred;
        }
    }

    for (; si < outSamples; ++si) {
        pcm[si] = pcm[si ? (si - 1) : 0];
    }
    return pcm;
}

static std::vector<int16_t> downsample2x(const int16_t* in, size_t n)
{
    std::vector<int16_t> out;
    if (!in || n < 2) return out;
    out.reserve(n / 2);
    for (size_t i = 0; i + 1 < n; i += 2) out.push_back(in[i]);
    return out;
}

static std::vector<int16_t> upsample2x_dup(const int16_t* in, size_t n)
{
    std::vector<int16_t> out;
    if (!in || n < 1) return out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(in[i]);
        out.push_back(in[i]);
    }
    return out;
}

struct AdpcmRxFrame {
    std::string from;
    uint32_t    seq;
    uint16_t    rate;
    std::vector<char> payload;
};

static std::mutex g_adpcmJitMutex;
static std::map<uint32_t, AdpcmRxFrame> g_adpcmReorder;
static std::atomic<uint32_t> g_adpcmExpectedSeq(0);
static std::vector<int16_t> g_adpcmLastGood;
static std::chrono::steady_clock::time_point g_adpcmLastRx = std::chrono::steady_clock::now();

static void stopAdpcmPlayoutThread()
{
    g_adpcmPlayoutRun = false;

    if (g_adpcmPlayoutThread.joinable()) {
        g_adpcmPlayoutThread.join();
    }

    {
        std::lock_guard<std::mutex> lock(g_adpcmJitMutex);
        g_adpcmReorder.clear();
        g_adpcmExpectedSeq = 0;
    }
    g_adpcmLastGood.clear();
}

static inline std::vector<int16_t> plcFromLast(size_t n)
{
    std::vector<int16_t> out(n, 0);
    if (g_adpcmLastGood.empty()) return out;

    for (size_t i = 0; i < n; ++i) {
        int16_t s = g_adpcmLastGood[i < g_adpcmLastGood.size() ? i : (g_adpcmLastGood.size() - 1)];
        int v = (int)s;
        v = (v * 7) / 8;
        out[i] = (int16_t)v;
    }
    return out;
}

static void ensureAdpcmPlayoutThread()
{
    if (g_adpcmPlayoutRun.load()) return;

    g_adpcmPlayoutRun = true;
    g_adpcmPlayoutThread = std::thread([]() {
        const int frameSamples = 220;
        const auto tick = std::chrono::milliseconds(10);

        while (g_running && g_adpcmPlayoutRun.load()) {
            auto t0 = std::chrono::steady_clock::now();

            AdpcmRxFrame fr;
            bool have = false;

            {
                std::lock_guard<std::mutex> lock(g_adpcmJitMutex);
                uint32_t want = g_adpcmExpectedSeq.load();
                auto it = g_adpcmReorder.find(want);
                if (it != g_adpcmReorder.end()) {
                    fr = std::move(it->second);
                    g_adpcmReorder.erase(it);
                    g_adpcmExpectedSeq = want + 1;
                    have = true;
                }
            }

            std::vector<int16_t> pcm;
            if (have) {
                size_t outS = (fr.rate == 11025) ? 110 : 220;
                pcm = imaAdpcmDecode(fr.payload.data(), fr.payload.size(), outS);
                if (fr.rate == 11025) {
                    auto up = upsample2x_dup(pcm.data(), pcm.size());
                    pcm.swap(up);
                }
                if (!pcm.empty()) g_adpcmLastGood = pcm;
            } else {
                pcm = plcFromLast(frameSamples);
            }

            if (!pcm.empty()) {
                std::vector<char> bytes(pcm.size() * sizeof(int16_t));
                std::memcpy(bytes.data(), pcm.data(), bytes.size());
                playAudioFrame(bytes);
            }

            auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0);
            if (dt < tick) std::this_thread::sleep_for(tick - dt);
        }
    });
}

static std::atomic<uint32_t> g_adpcmTxSeq(1);
static std::atomic<uint16_t> g_adpcmTxRate(22050);

static bool sendVoiceFrameToServer(SOCKET sock, const std::vector<char>& pcmBytes)
{
    if (pcmBytes.empty()) return true;

    if (pcmBytes.size() > MAX_TX_PAYLOAD) {
        LOG_WARN("Refusing to send huge PCM payload: %zu bytes\n", pcmBytes.size());
        return false;
    }

    if (!g_cfg.use_adpcm) {
        std::ostringstream oss;
        oss << "AUDIO " << pcmBytes.size() << "\n";
        std::string header = oss.str();
        if (!sendAll(sock, header.data(), header.size())) return false;
        if (!sendAll(sock, pcmBytes.data(), pcmBytes.size())) return false;
        return true;
    }

    const uint32_t seq = g_adpcmTxSeq.fetch_add(1);
    const int16_t* pcm = reinterpret_cast<const int16_t*>(pcmBytes.data());
    size_t nSamp = pcmBytes.size() / sizeof(int16_t);

    uint16_t rate = g_adpcmTxRate.load();
    if (!g_cfg.adpcm_adaptive) rate = 22050;

    std::vector<int16_t> work;
    const int frameSamples22 = 220;
    const int frameSamples11 = 110;

    if (rate == 11025 && nSamp >= (size_t)frameSamples22) {
        work = downsample2x(pcm, frameSamples22);
    } else {
        work.assign(pcm, pcm + std::min(nSamp, (size_t)frameSamples22));
    }

    if (rate == 11025) {
        if (work.size() < (size_t)frameSamples11) work.resize(frameSamples11, work.empty() ? 0 : work.back());
    } else {
        if (work.size() < (size_t)frameSamples22) work.resize(frameSamples22, work.empty() ? 0 : work.back());
    }

    std::vector<char> enc = imaAdpcmEncode(work.data(), work.size());
    if (enc.empty()) return true;

    std::ostringstream oss;
    oss << "AUDIO_ADPCM " << seq << " " << rate << " " << enc.size() << "\n";
    std::string header = oss.str();

    auto t0 = std::chrono::steady_clock::now();
    if (!sendAll(sock, header.data(), header.size())) return false;
    if (!sendAll(sock, enc.data(), enc.size())) return false;
    auto t1 = std::chrono::steady_clock::now();

    long long txMs = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    if (g_cfg.adpcm_adaptive) {
        if (txMs > 18) g_adpcmTxRate = 11025;
        else if (txMs < 8) g_adpcmTxRate = 22050;
    }
    return true;
}

static int frameMaxAbsSample(const std::vector<char>& frame)
{
    if (frame.empty()) return 0;
    size_t n = frame.size() / sizeof(int16_t);
    const int16_t* samples = (const int16_t*)frame.data();
    int maxAbs = 0;
    for (size_t i = 0; i < n; ++i) {
        int v = samples[i];
        if (v < 0) v = -v;
        if (v > maxAbs) maxAbs = v;
    }
    return maxAbs;
}

bool frameAboveVoxThreshold(const std::vector<char>& frame, int threshold)
{
    if (threshold <= 0) return false;
    int maxAbs = frameMaxAbsSample(frame);
    return maxAbs >= threshold;
}

void voxAutoLoop(SOCKET sock) {
    bool isTalking = false;

    int silenceFrames = 0;
    int triggerFrames = 0;

    std::chrono::steady_clock::time_point talkStart;

    int adaptiveThreshold = (g_cfg.vox_threshold > 0) ? g_cfg.vox_threshold : 5000;
    int calibFrames       = 0;
    int calibNoisePeak    = 0;
    bool haveCalibrated   = false;

    LOG_INFO("[VOX] Hands-free VOX mode enabled (no 't' needed).\n");
    LOG_INFO("[VOX] Just speak into the mic. Use Ctrl+C to exit client.\n");

    while (g_running) {
        std::vector<char> frame = captureAudioFrame();
        if (!g_running) break;
        if (frame.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        int peak = frameMaxAbsSample(frame);

        if (!isTalking && !haveCalibrated) {
            if (peak > calibNoisePeak)
                calibNoisePeak = peak;

            ++calibFrames;
            if (calibFrames >= VOX_CALIB_FRAMES) {
                int thr = calibNoisePeak * 4;
                if (thr < VOX_MIN_THRESHOLD_PEAK) thr = VOX_MIN_THRESHOLD_PEAK;
                if (thr > VOX_MAX_THRESHOLD_PEAK) thr = VOX_MAX_THRESHOLD_PEAK;

                adaptiveThreshold = thr;
                haveCalibrated    = true;

                LOG_INFO("[VOX] Auto-calibrated threshold: %d (noise peak=%d, cfg=%d)\n",
                         adaptiveThreshold, calibNoisePeak, g_cfg.vox_threshold);
            }
        }

        if (!isTalking && haveCalibrated) {
            if (peak < adaptiveThreshold / 3) {
                int target = peak * 4;
                if (target < VOX_MIN_THRESHOLD_PEAK) target = VOX_MIN_THRESHOLD_PEAK;
                if (target > VOX_MAX_THRESHOLD_PEAK) target = VOX_MAX_THRESHOLD_PEAK;
                adaptiveThreshold = (adaptiveThreshold * 9 + target) / 10;
            }
        }

        int effectiveThreshold = haveCalibrated ? adaptiveThreshold : g_cfg.vox_threshold;
        if (effectiveThreshold <= 0) {
            effectiveThreshold = adaptiveThreshold;
        }

        bool above = (peak >= effectiveThreshold);

        if (!isTalking) {
            if (!above) {
                triggerFrames = 0;
                continue;
            }

            ++triggerFrames;

            if (triggerFrames < VOX_TRIGGER_FRAMES_NEEDED) {
                continue;
            }

            triggerFrames = 0;

            std::string req = "REQ_SPEAK\n";
            if (!sendAll(sock, req.c_str(), req.size())) {
                LOG_ERROR("Failed to send REQ_SPEAK\n");
                g_running = false;
                break;
            }

            auto waitStart = std::chrono::steady_clock::now();
            while (g_running && !g_canTalk.load()) {
                auto now = std::chrono::steady_clock::now();
                long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - waitStart).count();
                if (ms > VOX_SPEAK_GRANT_TIMEOUT_MS) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            if (!g_canTalk.load() || !g_running) {
                continue;
            }

            isTalking     = true;
            silenceFrames = 0;
            talkStart     = std::chrono::steady_clock::now();

            if (g_cfg.gpio_ptt_enabled) {
                setPtt(true);
            }

            LOG_INFO("[VOX] MIC opened.\n");
        }

        int maxMs = g_maxTalkMs.load();
        if (maxMs > 0) {
            auto now = std::chrono::steady_clock::now();
            long long elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - talkStart).count();
            if (elapsed >= maxMs) {
                std::cout << "[VOX] Reached server talk time limit, closing MIC.\n";
                std::string endCmd = "END_SPEAK\n";
                sendAll(sock, endCmd.c_str(), endCmd.size());
                g_canTalk = false;
                isTalking = false;
                playMicFreeSound();
                if (g_cfg.gpio_ptt_enabled) {
                    setPtt(false);
                }
                continue;
            }
        }

        if (above) {
            silenceFrames = 0;
        } else {
            ++silenceFrames;
            if (silenceFrames > VOX_SILENCE_FRAMES_NEEDED) {
                LOG_INFO("[VOX] Silence detected, closing MIC.\n");
                std::string endCmd = "END_SPEAK\n";
                sendAll(sock, endCmd.c_str(), endCmd.size());
                g_canTalk = false;
                isTalking = false;
                playMicFreeSound();
                if (g_cfg.gpio_ptt_enabled) {
                    setPtt(false);
                }
                continue;
            }
        }

        if (above) {
            std::vector<char> frame = captureAudioFrame();
            if (!sendVoiceFrameToServer(sock, frame)) {
                std::cout << "Failed to send voice frame (ending talk session).";
                break;
            }
        }
    }

    if (isTalking) {
        std::string endCmd = "END_SPEAK\n";
        sendAll(sock, endCmd.c_str(), endCmd.size());
        g_canTalk = false;
        playMicFreeSound();
        if (g_cfg.gpio_ptt_enabled) {
            setPtt(false);
        }
    }

    std::cout << "[VOX] Loop ended.\n";
}

static inline int16_t seqDiff(uint16_t a, uint16_t b) {
    return (int16_t)(a - b);
}

static void downsample_by_2_mono16(const int16_t* in, size_t n, std::vector<int16_t>& out) {
    out.clear();
    out.reserve((n + 1) / 2);
    for (size_t i = 0; i + 1 < n; i += 2) {
        int v = (int)in[i] + (int)in[i + 1];
        out.push_back((int16_t)(v / 2));
    }
    if (n & 1) out.push_back(in[n - 1]);
}

static void upsample_by_2_hold_mono16(const int16_t* in, size_t n, std::vector<int16_t>& out) {
    out.clear();
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(in[i]);
        out.push_back(in[i]);
    }
}

static std::vector<char> adpcmEncode(const int16_t* pcm, size_t n)
{
    std::vector<char> out;
    if (!pcm || n == 0) return out;

    int pred = pcm[0];
    int idx = 0;

    out.resize(4);
    out[0] = (char)(pred & 0xFF);
    out[1] = (char)((pred >> 8) & 0xFF);
    out[2] = (char)(idx & 0xFF);
    out[3] = 0;

    int step = g_imaStepTable[idx];

    size_t nNibbles = (n >= 1) ? (n - 1) : 0;
    out.resize(4 + (nNibbles + 1) / 2, 0);

    size_t nib = 0;
    for (size_t i = 1; i < n; ++i, ++nib) {
        int diff = (int)pcm[i] - pred;
        int sign = (diff < 0) ? 8 : 0;
        if (diff < 0) diff = -diff;

        int delta = 0;
        int vpdiff = step >> 3;
        if (diff >= step)      { delta |= 4; diff -= step;      vpdiff += step; }
        if (diff >= (step>>1)) { delta |= 2; diff -= (step>>1); vpdiff += (step>>1); }
        if (diff >= (step>>2)) { delta |= 1;                    vpdiff += (step>>2); }

        pred += sign ? -vpdiff : vpdiff;
        pred = clamp16(pred);

        delta |= sign;

        idx += g_imaIndexTable[delta & 0x0F];
        if (idx < 0) idx = 0; else if (idx > 88) idx = 88;
        step = g_imaStepTable[idx];

        size_t bytePos = 4 + (nib / 2);
        if ((nib & 1) == 0) out[bytePos] = (char)(delta & 0x0F);
        else out[bytePos] = (char)((out[bytePos] & 0x0F) | ((delta & 0x0F) << 4));
    }

    return out;
}

static bool adpcmDecode(const std::vector<char>& in, std::vector<int16_t>& pcm)
{
    pcm.clear();
    if (in.size() < 4) return false;

    int pred = (int16_t)((uint8_t)in[0] | ((uint8_t)in[1] << 8));
    int idx  = (uint8_t)in[2];
    if (idx < 0) idx = 0; else if (idx > 88) idx = 88;

    int step = g_imaStepTable[idx];
    pcm.push_back((int16_t)pred);

    for (size_t i = 4; i < in.size(); ++i) {
        uint8_t b = (uint8_t)in[i];
        for (int k = 0; k < 2; ++k) {
            int d = (k == 0) ? (b & 0x0F) : ((b >> 4) & 0x0F);
            int sign = d & 8;
            int code = d & 7;

            int vpdiff = step >> 3;
            if (code & 4) vpdiff += step;
            if (code & 2) vpdiff += (step >> 1);
            if (code & 1) vpdiff += (step >> 2);

            pred += sign ? -vpdiff : vpdiff;
            pred = clamp16(pred);

            idx += g_imaIndexTable[d];
            if (idx < 0) idx = 0; else if (idx > 88) idx = 88;
            step = g_imaStepTable[idx];

            pcm.push_back((int16_t)pred);
        }
    }
    return true;
}

struct PlcState {
    int16_t lastSample;
    int plcSamplesLeft;

    PlcState() : lastSample(0), plcSamplesLeft(0) {}
};

static void plcMakeFrame(std::vector<char>& outPcmBytes, PlcState& st, int samplesPerFrame) {
    outPcmBytes.resize(samplesPerFrame * 2);
    int16_t* p = (int16_t*)outPcmBytes.data();

    int32_t s = st.lastSample;
    for (int i = 0; i < samplesPerFrame; ++i) {
        s = (s * 995) / 1000;
        p[i] = (int16_t)s;
    }
    if (samplesPerFrame > 0) st.lastSample = p[samplesPerFrame - 1];
}

struct AdpcmJitterBuffer {
    AdpcmJitterBuffer() : nextSeq(0), haveSync(false), targetFrames(3), samplesPerFrame(220), srDiv(1) {}
    std::map<uint16_t, std::vector<char>> q;
    uint16_t nextSeq;
    bool haveSync;
    int targetFrames;
    int samplesPerFrame;
    int srDiv;
    PlcState plc;

    void reset(int tgtFrames, int spf) {
        q.clear();
        haveSync = false;
        targetFrames = std::max(2, std::min(8, tgtFrames));
        samplesPerFrame = spf;
        srDiv = 1;
        plc = PlcState();
    }

    void push(uint16_t seq, int inSrDiv, const std::vector<char>& payload) {
        if (inSrDiv != 1 && inSrDiv != 2) inSrDiv = 1;
        srDiv = inSrDiv;

        q[seq] = payload;

        if (!haveSync) {
            if ((int)q.size() >= targetFrames) {
                nextSeq = q.begin()->first;
                haveSync = true;
            }
        }
    }

    bool pop(std::vector<char>& outPcmBytes) {
        outPcmBytes.clear();
        if (!haveSync) return false;

        auto it = q.find(nextSeq);
        if (it == q.end()) {
            plcMakeFrame(outPcmBytes, plc, samplesPerFrame);
            nextSeq++;
            return true;
        }

        std::vector<int16_t> pcm;
        if (!adpcmDecode(it->second, pcm) || pcm.empty()) {
            plcMakeFrame(outPcmBytes, plc, samplesPerFrame);
            q.erase(it);
            nextSeq++;
            return true;
        }

        std::vector<int16_t> norm;

        if (srDiv == 2) {
            std::vector<int16_t> up;
            upsample_by_2_hold_mono16(pcm.data(), pcm.size(), up);
            norm.swap(up);
        } else {
            norm.swap(pcm);
        }

        if ((int)norm.size() < samplesPerFrame) {
            int16_t last = norm.empty() ? 0 : norm.back();
            norm.resize(samplesPerFrame, last);
        } else if ((int)norm.size() > samplesPerFrame) {
            norm.resize(samplesPerFrame);
        }

        plc.lastSample = norm.back();

        outPcmBytes.resize(samplesPerFrame * 2);
        std::memcpy(outPcmBytes.data(), norm.data(), outPcmBytes.size());

        q.erase(it);
        nextSeq++;
        return true;
    }
};

void receiverLoop(SOCKET sock) {
    while (g_running) {
        std::string line;
        if (!recvLine(sock, line)) {
            LOG_WARN("Disconnected from server.\n");

            {
                std::lock_guard<std::mutex> lock(g_speakerMutex);
                g_currentSpeaker.clear();
            }
#ifdef GUI
            g_talkerActive = false;
            g_rxAudioLevel = 0.0f;
#endif

            g_running = false;
            break;
        }

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "SPEAK_GRANTED") {
            int ms;
            iss >> ms;
            g_maxTalkMs = ms;
            g_canTalk = true;
            LOG_INFO("[SERVER] You can talk now (max %d ms).\n", ms);
        }
		else if (cmd == "SPEAK_OK") {
			g_canTalk = true;
			LOG_INFO("[SERVER] You can talk now.\n");
		}
        else if (cmd == "SPEAK_DENIED") {
            std::string reason;
            iss >> reason;
            LOG_WARN("[SERVER] Speak denied: %s\n", reason.c_str());
        }
        else if (cmd == "SPEAK_REVOKED") {
            std::string reason;
            iss >> reason;
            g_canTalk = false;
            std::cout << "[SERVER] Speak revoked: " << reason << "\n";
        }
		else if (cmd == "MIC_FREE") {
			playMicFreeSound();
			{
				std::lock_guard<std::mutex> lock(g_speakerMutex);
				if (!g_currentSpeaker.empty()) {
					LOG_INFO("[INFO] %s finished talking.\n", g_currentSpeaker.c_str());
					g_currentSpeaker.clear();
#ifdef GUI
					g_talkerActive = false;
					g_rxAudioLevel = 0.0f;
#endif
				} else {
					LOG_INFO("[INFO] Mic is now free.\n");
				}
			}
		}
		else if (cmd == "SPEAKER") {
			std::string who;
			iss >> who;
			{
				std::lock_guard<std::mutex> lock(g_speakerMutex);
				if (g_currentSpeaker != who) {
					g_currentSpeaker = who;
#ifdef GUI
					g_talkerStart  = std::chrono::steady_clock::now();
					g_talkerActive = true;
#endif
					std::cout << "[TG] Now talking: " << who << "\n";
				}
			}
		}
		else if (cmd == "SPEAKER_NONE") {
			std::lock_guard<std::mutex> lock(g_speakerMutex);
			if (!g_currentSpeaker.empty()) {
				std::cout << "[INFO] " << g_currentSpeaker << " finished talking.\n";
				g_currentSpeaker.clear();
#ifdef GUI
				g_talkerActive = false;
				g_rxAudioLevel = 0.0f;
#endif
			} else {
				std::cout << "[INFO] Mic is now free.\n";
			}
		}
        else if (cmd == "TGLIST") {
            std::string rest;
            std::getline(iss, rest);
            if (!rest.empty() && rest[0] == ' ')
                rest.erase(0, 1);

            std::vector<std::string> items;
            std::stringstream ss(rest);
            std::string tg;
            while (std::getline(ss, tg, ',')) {
                tg = trim(tg);
                if (!tg.empty()) items.push_back(tg);
            }

            {
                std::lock_guard<std::mutex> lock(g_tgListMutex);
                g_serverTalkgroups = items;
            }

#ifndef GUI
            std::cout << "[SERVER] Talkgroups: ";
            for (size_t i = 0; i < items.size(); ++i) {
                if (i) std::cout << ", ";
                std::cout << items[i];
            }
            std::cout << "\n";
#else
            if (!items.empty()) {
                g_tgComboItems = items;

                int newIndex = 0;
                for (size_t i = 0; i < g_tgComboItems.size(); ++i) {
                    if (g_tgComboItems[i] == ui_talkgroup) {
                        newIndex = (int)i;
                        break;
                    }
                }
                ui_tg_index   = newIndex;
                ui_talkgroup  = g_tgComboItems[ui_tg_index];
            }
#endif
        }
		else if (cmd == "AUDIO_FROM") {
			std::string user;
			size_t size = 0;
			iss >> user >> size;

			if (user.empty() || size == 0 || size > MAX_RX_PAYLOAD) {
				LOG_WARN("Bad AUDIO_FROM frame header (user='%s' size=%zu)\n", user.c_str(), size);
				g_running = false;
				break;
			}

			std::vector<char> buf(size);
			if (!recvAll(sock, buf.data(), size)) {
				LOG_ERROR("Failed to receive audio frame\n");
				g_running = false;
				break;
			}

			{
				std::lock_guard<std::mutex> lock(g_speakerMutex);
				if (g_currentSpeaker != user) {
					g_currentSpeaker = user;
#ifdef GUI
					g_talkerStart  = std::chrono::steady_clock::now();
					g_talkerActive = true;
#endif
					std::cout << "[TG] Now talking: " << user << "\n";
				}
			}
			auto tNow = std::chrono::steady_clock::now();
			g_lastRxAudioTime = tNow;
			g_lastRxVoiceTime = tNow;

			std::vector<char> pcm;
			pcm = std::move(buf);

			if (!pcm.empty()) {
				playAudioFrame(pcm);
			}
		}
        else if (cmd == "AUDIO_ADPCM_FROM") {
			std::string user;
			uint32_t seq = 0;
			uint16_t rate = 22050;
			size_t size = 0;
			iss >> user >> seq >> rate >> size;

			if (user.empty() || size == 0 || size > MAX_RX_PAYLOAD) {
				LOG_WARN("Bad AUDIO_ADPCM_FROM header (user='%s' seq=%u rate=%u size=%zu)\n",
						 user.c_str(), seq, (unsigned)rate, size);
				g_running = false;
				break;
			}

			std::vector<char> buf(size);
			if (!recvAll(sock, buf.data(), size)) {
				LOG_ERROR("Failed to receive ADPCM frame");
				g_running = false;
				break;
			}

            {
                std::lock_guard<std::mutex> lock(g_speakerMutex);
                if (g_currentSpeaker != user) {
                    g_currentSpeaker = user;
#ifdef GUI
                    g_talkerStart  = std::chrono::steady_clock::now();
                    g_talkerActive = true;
#endif
                    std::cout << "[TG] Now talking: " << user << "";
                }
            }
			auto tNow = std::chrono::steady_clock::now();
			g_lastRxAudioTime = tNow;
			g_lastRxVoiceTime = tNow;

            ensureAdpcmPlayoutThread();
            {
                std::lock_guard<std::mutex> lock(g_adpcmJitMutex);

                if (g_adpcmExpectedSeq.load() == 0) {
                    g_adpcmExpectedSeq = seq;
                }

                AdpcmRxFrame fr;
                fr.from = user;
                fr.seq  = seq;
                fr.rate = rate;
                fr.payload = std::move(buf);
                g_adpcmReorder[seq] = std::move(fr);

                const size_t maxFrames = (size_t)std::max(2, g_cfg.adpcm_jitter_frames) * 8;
                while (g_adpcmReorder.size() > maxFrames) {
                    g_adpcmReorder.erase(g_adpcmReorder.begin());
                }
            }
        }

        else if (cmd == "ADMIN_INFO") {
            std::string info;
            iss >> info;
            std::cout << "[ADMIN_INFO] " << info << "\n";
            if (info == "kicked_by_admin") {
                std::cout << "You were kicked by an admin.\n";
                g_running = false;
                break;
            }
        }
        else if (cmd == "ADMIN_USERS") {
            std::string rest;
            std::getline(iss, rest);
            std::cout << "[ADMIN_USERS]" << rest << "\n";
        }
        else if (cmd == "ADMIN_TGS") {
            std::string rest;
            std::getline(iss, rest);
            std::cout << "[ADMIN_TGS]" << rest << "\n";
        }
        else if (cmd == "ADMIN_LASTHEARD") {
            std::string rest;
            std::getline(iss, rest);
            std::cout << "[LAST_HEARD]" << rest << "\n";
        }
        else if (cmd == "ADMIN_OK") {
            std::string sub;
            iss >> sub;
            std::cout << "[ADMIN_OK] " << sub << "\n";
        }
        else if (cmd == "ADMIN_FAIL") {
            std::string reason;
            iss >> reason;
            std::cout << "[ADMIN_FAIL] " << reason << "\n";
        }
        else if (cmd == "JOIN_OK") {
            std::string tg;
            iss >> tg;
            std::cout << "[SERVER] Joined talkgroup: " << tg << "\n";
        }
        else if (cmd == "JOIN_FAIL") {
            std::string reason;
            iss >> reason;
            std::cout << "[SERVER] Join failed: " << reason << "\n";
        }
        else {
            std::cout << "[SERVER] " << line << "\n";
        }
    }
}

void doTalkSession(SOCKET sock) {
    std::string cmd = "REQ_SPEAK\n";
    if (!sendAll(sock, cmd.data(), cmd.size())) {
        LOG_ERROR("Failed to send REQ_SPEAK\n");
        return;
    }

    LOG_INFO("Waiting for speak permission...\n");
    int waits = 0;
    while (g_running && !g_canTalk && waits < 50) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        waits++;
    }

    if (!g_canTalk) {
        std::cout << "Not granted or timed out.\n";
        return;
    }

    const bool voxMode = g_cfg.vox_enabled;
    LOG_INFO("You may talk now.");
    if (voxMode) {
        LOG_INFO(" [VOX auto mode]\n");
    } else {
        LOG_INFO(" Press ENTER to stop.\n");
    }
#if defined(__ANDROID__)
	AndroidFlushMicQueue();
#endif

    auto start = std::chrono::steady_clock::now();
    std::atomic<bool> stopTalk(false);
    std::thread stopThread;

    if (!voxMode) {
        stopThread = std::thread([&]() {
            std::string dummy;
            std::getline(std::cin, dummy);
            stopTalk = true;
        });
    }

    int silenceFrames = 0;
    const int maxSilenceFrames = 20;

    while (g_running && g_canTalk && !stopTalk) {
        auto now = std::chrono::steady_clock::now();
        long long elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();

        int maxTalkMs = g_maxTalkMs.load();
        if (maxTalkMs > 0 && elapsed >= maxTalkMs) {
            std::cout << "Reached max talk time.\n";
            break;
        }

        std::vector<char> frame = captureAudioFrame();
        if (frame.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        if (voxMode) {
            if (!frameAboveVoxThreshold(frame, g_cfg.vox_threshold)) {
                ++silenceFrames;
                if (silenceFrames >= maxSilenceFrames) {
                    std::cout << "[VOX] Silence detected, closing MIC.\n";
                    break;
                }
                continue;
            } else {
                silenceFrames = 0;
            }
        }

        if (!sendVoiceFrameToServer(sock, frame)) {
            std::cout << "Failed to send voice frame (ending talk session).";
            break;
        }
    }

    if (!voxMode && stopThread.joinable()) {
        stopThread.join();
    }

#if defined(__ANDROID__)
	AndroidFlushMicQueue();
#endif

    std::string endCmd = "END_SPEAK\n";
    sendAll(sock, endCmd.data(), endCmd.size());
    g_canTalk = false;
    std::cout << "Stopped talking.\n";
}

static inline void UpdateTxMicLevelFromFrame(const std::vector<char>& frame)
{
#ifdef GUI
    if (frame.empty()) return;

    const int16_t* samples = reinterpret_cast<const int16_t*>(frame.data());
    const size_t sampleCount = frame.size() / sizeof(int16_t);
    if (sampleCount == 0) return;

    double sumSq = 0.0;
    for (size_t i = 0; i < sampleCount; ++i) {
        double v = samples[i] / 32768.0;
        sumSq += v * v;
    }
    double rms = std::sqrt(sumSq / (double)sampleCount);

    float level = (float)rms;
    if (level < 0.0f) level = 0.0f;
    if (level > 1.0f) level = 1.0f;

    float old = g_audioLevel.load();
    g_audioLevel = old * 0.7f + level * 0.3f;
#else
    (void)frame;
#endif
}

static inline void FlushAudioOutput()
{
#if defined(__ANDROID__)
    if (g_sdlOutDev) SDL_ClearQueuedAudio(g_sdlOutDev);
#else
    if (g_outputStream) {
        Pa_AbortStream(g_outputStream);
        Pa_StartStream(g_outputStream);
    }
#endif
}

void doParrotSession(bool usePtt)
{
    const bool voxMode = g_cfg.vox_enabled;

#ifdef GUI
    const int maxRecordMs = 3500;
    const int minRecordMs = 800;
#else
    const int maxRecordMs = 0;
    const int minRecordMs = 0;
#endif

#ifdef GUI
    g_currentSpeaker = g_cfg.callsign;
    g_talkerStart = std::chrono::steady_clock::now();
    g_talkerActive = true;
#endif

    if (usePtt) {
        setPtt(true);
    }

    const int silenceFramesNeeded = 50;
    int  silenceFrames = 0;
    bool hadVoice      = false;

    std::vector<std::vector<char>> recordedFrames;
    recordedFrames.reserve(400);

    auto tStart = std::chrono::steady_clock::now();

#ifndef GUI
    std::atomic<bool> stop(false);
    std::thread stopThread;
    if (!voxMode) {
        stopThread = std::thread([&]() {
            std::string s;
            std::getline(std::cin, s);
            stop = true;
        });
    }
#endif

    while (g_running) {
        if (maxRecordMs > 0) {
            auto now = std::chrono::steady_clock::now();
            int elapsed = (int)std::chrono::duration_cast<std::chrono::milliseconds>(now - tStart).count();
            if (elapsed >= maxRecordMs) break;
        }

#ifndef GUI
        if (!voxMode && stop.load()) break;
#endif

        std::vector<char> frame = captureAudioFrame();
        if (frame.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        UpdateTxMicLevelFromFrame(frame);
        recordedFrames.push_back(frame);

        if (voxMode) {
            bool above = frameAboveVoxThreshold(frame, g_cfg.vox_threshold);
            if (above) {
                hadVoice = true;
                silenceFrames = 0;
            } else if (hadVoice) {
                ++silenceFrames;
                auto now = std::chrono::steady_clock::now();
                int elapsed = (int)std::chrono::duration_cast<std::chrono::milliseconds>(now - tStart).count();
                if (silenceFrames >= silenceFramesNeeded && elapsed >= minRecordMs) break;
            }
        }
    }

#ifndef GUI
    if (!voxMode && stopThread.joinable()) stopThread.join();
#endif

    if (usePtt) setPtt(false);

#ifdef GUI
    g_talkerActive = false;
    g_audioLevel = 0.0f;
#endif

    if (recordedFrames.empty()) {
        std::cout << "Parrot: nothing recorded.\n";
#ifdef GUI
        g_talkerActive = false;
        g_audioLevel = 0.0f;
        if (g_currentSpeaker == g_cfg.callsign) g_currentSpeaker.clear();
#endif
        return;
    }

    const bool savedSqEn   = g_rxSquelchEnabled.load();
    const bool savedSqAuto = g_rxSquelchAuto.load();
    const int  savedSqLvl  = g_rxSquelchLevel.load();
    const int  savedSqVPct = g_rxSquelchVoicePct.load();
    const int  savedSqHang = g_rxSquelchHangMs.load();

    g_rxSquelchEnabled = false;
    g_rxSquelchAuto    = false;

    FlushAudioOutput();

#ifdef GUI
    g_currentSpeaker = g_cfg.callsign + " (Parrot)";
    g_talkerStart = std::chrono::steady_clock::now();
    g_talkerActive = true;
#endif

    for (const auto& f : recordedFrames) {
        if (f.empty()) continue;

        size_t sampleCount = f.size() / sizeof(int16_t);
        unsigned long frames = (unsigned long)(sampleCount / (size_t)g_channels);
        if (frames == 0) continue;

        const int16_t* inSamples = reinterpret_cast<const int16_t*>(f.data());

        float gain = g_outputGain.load();
        std::vector<int16_t> outSamples(sampleCount);

        if (gain == 1.0f) {
            std::memcpy(outSamples.data(), inSamples, sampleCount * sizeof(int16_t));
        } else {
            for (size_t i = 0; i < sampleCount; ++i) {
                float v = inSamples[i] * gain;
                if (v > 32767.0f)  v = 32767.0f;
                if (v < -32768.0f) v = -32768.0f;
                outSamples[i] = (int16_t)v;
            }
        }

        if (!outSamples.empty()) {
            applySoftLimiter(outSamples, 0.95f);
        }

        audioOutWriteBlockingChunked(outSamples.data(), frames);
    }

#ifdef GUI
    g_talkerActive = false;
    g_audioLevel = 0.0f;
    if (g_currentSpeaker == g_cfg.callsign + " (Parrot)") g_currentSpeaker.clear();
#endif

    g_rxSquelchEnabled  = savedSqEn;
    g_rxSquelchAuto     = savedSqAuto;
    g_rxSquelchLevel    = savedSqLvl;
    g_rxSquelchVoicePct = savedSqVPct;
    g_rxSquelchHangMs   = savedSqHang;

    std::cout << "Parrot done.\n";
}

void parrotLoop(const ClientConfig& cfg) {
    bool usePtt = cfg.gpio_ptt_enabled;
    std::cout << "Parrot mode (local audio test).\n"
              << "GPIO PTT: " << (usePtt ? "ON" : "OFF") << "\n"
              << "VOX: " << (cfg.vox_enabled ? "ON" : "OFF")
              << " threshold=" << cfg.vox_threshold << "\n";

    if (cfg.vox_enabled) {
        std::cout << "VOX is ENABLED.\n"
                  << "Parrot will run in continuous VOX mode:\n"
                  << "  - Talk to record\n"
                  << "  - Stay silent to stop and hear playback\n"
                  << "  - After playback, a new VOX parrot session starts automatically\n"
                  << "Use Ctrl+C to exit.\n";

        while (true) {
            doParrotSession(usePtt);
            LOG_INFO("---- VOX parrot round finished, ready for next one ----\n");
        }
    }

    LOG_INFO("Commands:\n"
         "  t or /talk  - start parrot record+playback\n"
         "  q or /quit  - exit\n");

    while (true) {
        std::cout << "PARROT> ";
        std::string input;
        if (!std::getline(std::cin, input)) break;

        if (input == "q" || input == "/quit") {
            break;
        } else if (input == "t" || input == "/talk") {
            doParrotSession(usePtt);
            std::cout << "Ready.\n";
        } else {
            std::cout << "Unknown command.\n";
        }
    }
}

#ifndef GUI
int main(int argc, char** argv) {
	title();

    std::string cfgPath = "client.json";
    if (argc >= 2) cfgPath = argv[1];

    if (!loadClientConfig(cfgPath, g_cfg)) {
        std::cerr << "Failed to load client config.\n";
        return 1;
    }

    auto clampGain = [](int v) {
        if (v < 0)   v = 0;
        if (v > 200) v = 200;
        return v;
    };

    g_cfg.input_gain  = clampGain(g_cfg.input_gain);
    g_cfg.output_gain = clampGain(g_cfg.output_gain);

    g_inputGain  = g_cfg.input_gain  / 100.0f;
    g_outputGain = g_cfg.output_gain / 100.0f;

	LOG_INFO("Client cfg:\n"
         "  mode: %s\n"
         "  server: %s:%d\n"
         "  user: %s / TG=%s\n"
         "  VOX: %s (thr=%d)\n",
         g_cfg.mode.c_str(),
         g_cfg.server_ip.c_str(), g_cfg.server_port,
         g_cfg.callsign.c_str(), g_cfg.talkgroup.c_str(),
         g_cfg.vox_enabled ? "ENABLED" : "DISABLED",
         g_cfg.vox_threshold);

    if (!initPortAudio(g_cfg)) {
        std::cerr << "PortAudio init failed.\n";
        return 1;
    }
	loadRogerFromConfig();
    if (!initGpioPtt(g_cfg)) {
        std::cerr << "GPIO PTT init failed.\n";
    }
	g_pttHoldMs = g_cfg.gpio_ptt_hold_ms;
	if (g_cfg.gpio_ptt_enabled && !g_cfg.vox_enabled) {
		std::thread(pttManagerThreadFunc).detach();
	}

    if (g_cfg.mode == "Parrot") {
        parrotLoop(g_cfg);
        shutdownPortAudio();
        shutdownGpioPtt();
        return 0;
    }

    initSockets();
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Failed to create socket\n";
        cleanupSockets();
        shutdownPortAudio();
        shutdownGpioPtt();
        return 1;
    }

	struct addrinfo hints;
	std::memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo* res = NULL;
	std::ostringstream portStr;
	portStr << g_cfg.server_port;

	int rv = getaddrinfo(g_cfg.server_ip.c_str(), portStr.str().c_str(), &hints, &res);
	if (rv != 0 || !res) {
#ifdef _WIN32
		LOG_ERROR("getaddrinfo failed for server '%s': %s\n",g_cfg.server_ip.c_str(), gai_strerrorA(rv));
#else
		LOG_ERROR("getaddrinfo failed for server '%s': %s\n",g_cfg.server_ip.c_str(), gai_strerror(rv));
#endif
		closeSocket(sock);
		cleanupSockets();
		shutdownPortAudio();
		shutdownGpioPtt();
		return 1;
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
		LOG_ERROR("Connect failed to %s:%d\n",g_cfg.server_ip.c_str(), g_cfg.server_port);
		closeSocket(sock);
		cleanupSockets();
		shutdownPortAudio();
		shutdownGpioPtt();
		return 1;
	}

	if (g_cfg.gpio_ptt_enabled && !g_cfg.vox_enabled) {
		g_pttAutoEnabled = true;
		g_lastRxAudioTime = std::chrono::steady_clock::now();
	} else {
		g_pttAutoEnabled = false;
	}

    {
        std::ostringstream oss;
        oss << "AUTH " << g_cfg.callsign << " " << g_cfg.password << "\n";
        std::string cmd = oss.str();
        if (!sendAll(sock, cmd.data(), cmd.size())) {
            LOG_ERROR("Send AUTH failed\n");
            closeSocket(sock);
            cleanupSockets();
            shutdownPortAudio();
            shutdownGpioPtt();
            return 1;
        }
        std::string line;
        if (!recvLine(sock, line)) {
            LOG_ERROR("AUTH response failed\n");
            closeSocket(sock);
            cleanupSockets();
            shutdownPortAudio();
            shutdownGpioPtt();
            return 1;
        }
        if (line != "AUTH_OK") {
            LOG_ERROR("Auth failed: %s\n", line.c_str());
            closeSocket(sock);
            cleanupSockets();
            shutdownPortAudio();
            shutdownGpioPtt();
            return 1;
        }
        LOG_OK("Authenticated.\n");
    }

    {
        std::ostringstream oss;
        oss << "JOIN " << g_cfg.talkgroup << "\n";
        std::string cmd = oss.str();
        if (!sendAll(sock, cmd.data(), cmd.size())) {
            LOG_ERROR("Send JOIN failed\n");
            closeSocket(sock);
            cleanupSockets();
            shutdownPortAudio();
            shutdownGpioPtt();
            return 1;
        }
        std::string line;
        if (!recvLine(sock, line)) {
            LOG_ERROR("JOIN response failed\n");
            closeSocket(sock);
            cleanupSockets();
            shutdownPortAudio();
            shutdownGpioPtt();
            return 1;
        }
        LOG_INFO("[SERVER] %s\n", line.c_str());
        if (line.find("JOIN_OK") != 0) {
            LOG_ERROR("Join failed.\n");
            closeSocket(sock);
            cleanupSockets();
            shutdownPortAudio();
            shutdownGpioPtt();
            return 1;
        }
    }

    std::thread recvThread(receiverLoop, sock);

    if (g_cfg.vox_enabled) {
        LOG_INFO("[VOX] Hands-free mode: no 't' needed.\n");
        LOG_INFO("Use Ctrl+C to terminate the client.\n");
        voxAutoLoop(sock);
        g_running = false;
    } else {
        while (g_running) {
            LOG_INFO("> ");
            std::string input;
            if (!std::getline(std::cin, input)) {
                g_running = false;
                break;
            }

            if (input == "q" || input == "/quit") {
                g_running = false;
                break;
            } else if (input == "t" || input == "/talk") {
                if (!g_running) break;
                doTalkSession(sock);
            } else if (!input.empty() && input[0] == '/') {
                std::string adminPayload = input.substr(1);
                std::string cmd = "ADMIN " + adminPayload + "\n";
                if (!sendAll(sock, cmd.data(), cmd.size())) {
                    LOG_ERROR("Failed to send admin cmd.\n");
                    g_running = false;
                    break;
                }
            } else {
                LOG_WARN("Unknown cmd.\n");
            }
        }
    }

	g_running = false;
#if defined(_WIN32) || defined(_WIN64)
	if (sock != INVALID_SOCKET) shutdown(sock, SD_BOTH);
#else
	if (sock != INVALID_SOCKET) shutdown(sock, SHUT_RDWR);
#endif
	if (recvThread.joinable()) recvThread.join();
	closeSocket(sock);

    shutdownPortAudio();
    shutdownGpioPtt();
    cleanupSockets();
    return 0;
}
#endif
