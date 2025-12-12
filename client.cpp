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
#include <cstring>
#include <cstdlib>

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

#include <portaudio.h>

extern "C" {
    int cm108_set_gpio_pin(char *name, int num, int state);
}

#ifdef GUI
static std::atomic<float> g_audioLevel(0.0f);

std::atomic<float> g_rxAudioLevel(0.0f);
std::atomic<bool>  g_talkerActive(false);
std::chrono::steady_clock::time_point g_talkerStart;
#endif

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

bool sendAll(SOCKET sock, const void* data, size_t len) {
    const char* buf = static_cast<const char*>(data);
    while (len > 0) {
        int sent = send(sock, buf, (int)len, 0);
        if (sent <= 0) return false;
        buf += sent;
        len -= sent;
    }
    return true;
}

bool recvAll(SOCKET sock, void* data, size_t len) {
    char* buf = static_cast<char*>(data);
    while (len > 0) {
        int r = recv(sock, buf, (int)len, 0);
        if (r <= 0) return false;
        buf += r;
        len -= r;
    }
    return true;
}

bool recvLine(SOCKET sock, std::string& line) {
    line.clear();
    char c;
    while (true) {
        int r = recv(sock, &c, 1, 0);
        if (r <= 0) return false;
        if (c == '\n') break;
        if (c != '\r') line.push_back(c);
    }
    return true;
}

bool connectToServerHost(const std::string& host, int port, SOCKET& outSock)
{
    outSock = INVALID_SOCKET;

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

    bool vox_enabled;
    int  vox_threshold;

    int  input_gain;
    int  output_gain;

    std::string ptt_cmd_on;
    std::string ptt_cmd_off;

	int roger_sound;

#ifdef OPUS
	bool use_opus;
#endif
};

bool loadClientConfig(const std::string& path, ClientConfig& cfg) {
    cfg.mode = "server";
    cfg.server_ip = "127.0.0.1";
    cfg.server_port = 26613;
    cfg.callsign = "guest";
    cfg.password = "passw0rd";
    cfg.talkgroup = "gateway";

    cfg.sample_rate = 48000;
    cfg.frames_per_buffer = 960;
    cfg.channels = 1;
    cfg.input_device_index = 0;
    cfg.output_device_index = 0;

    cfg.gpio_ptt_enabled = false;
    cfg.gpio_ptt_pin = 18;
    cfg.gpio_ptt_active_high = true;
    cfg.gpio_ptt_hold_ms = 250;

    cfg.vox_enabled = false;
    cfg.vox_threshold = 5000;

    cfg.input_gain  = 100;
    cfg.output_gain = 100;

    cfg.ptt_cmd_on.clear();
    cfg.ptt_cmd_off.clear();

	cfg.roger_sound = 1;

#ifdef OPUS
	cfg.use_opus = false;
#endif

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
        else if (parseStringField(l, "ptt_cmd_on", sval))  cfg.ptt_cmd_on  = sval;
        else if (parseStringField(l, "ptt_cmd_off", sval)) cfg.ptt_cmd_off = sval;
        else if (parseBoolField(l, "vox_enabled", bval)) cfg.vox_enabled = bval;
        else if (parseIntField(l, "vox_threshold", ival)) cfg.vox_threshold = ival;
        else if (parseIntField(l, "input_gain", ival))    cfg.input_gain  = ival;
        else if (parseIntField(l, "output_gain", ival))   cfg.output_gain = ival;
		else if (parseIntField(l, "roger_sound", ival)) cfg.roger_sound = ival;
#ifdef OPUS
		else if (parseBoolField(l, "use_opus", bval)) cfg.use_opus = bval;
#endif
    }

#ifdef OPUS
	if (cfg.use_opus) {
		cfg.sample_rate       = 48000;
		cfg.frames_per_buffer = 480;
		cfg.channels          = 1;
	}
#endif

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
    f << "  \"vox_enabled\": " << (cfg.vox_enabled ? "true" : "false") << ",\n";
    f << "  \"vox_threshold\": " << cfg.vox_threshold << ",\n";
    f << "  \"input_gain\": " << cfg.input_gain << ",\n";
    f << "  \"output_gain\": " << cfg.output_gain << ",\n";
	f << "  \"roger_sound\": " << cfg.roger_sound << ",\n";
    f << "  \"ptt_cmd_on\": \""  << cfg.ptt_cmd_on  << "\",\n";
    f << "  \"ptt_cmd_off\": \"" << cfg.ptt_cmd_off << "\"\n";
#ifdef OPUS
    f << "  \"use_opus\": " << (cfg.use_opus ? "true" : "false") << "\n";
#endif
    f << "}\n";

    return true;
}

PaStream* g_inputStream = NULL;
PaStream* g_outputStream = NULL;
int g_sampleRate = 48000;
unsigned long g_framesPerBuffer = 480;
int g_channels = 1;

static bool g_pttUseShell = false;
static std::string g_pttCmdOn;
static std::string g_pttCmdOff;

static bool         g_pttUseCm108 = false;
static std::string  g_cm108Dev;
static int          g_cm108Pin    = 0;

extern ClientConfig g_cfg;

extern std::atomic<float> g_inputGain;
extern std::atomic<float> g_outputGain;

#ifdef OPUS
#ifdef _WIN32
#include <opus.h>
#else
#include <opus/opus.h>
#endif

static OpusEncoder* g_opusEnc = nullptr;
static OpusDecoder* g_opusDec = nullptr;
static int          g_opusFrameSize = 0;
static const int    OPUS_MAX_PACKET_BYTES = 1500;

#ifdef _WIN32
static HMODULE g_opusModule = NULL;

typedef OpusEncoder* (*opus_encoder_create_t)(opus_int32 Fs, int channels,
                                              int application, int *error);
typedef void (*opus_encoder_destroy_t)(OpusEncoder *st);
typedef OpusDecoder* (*opus_decoder_create_t)(opus_int32 Fs, int channels,
                                              int *error);
typedef void (*opus_decoder_destroy_t)(OpusDecoder *st);
typedef int (*opus_encode_t)(OpusEncoder *st, const opus_int16 *pcm,
                             int frame_size, unsigned char *data,
                             opus_int32 max_data_bytes);
typedef int (*opus_decode_t)(OpusDecoder *st, const unsigned char *data,
                             opus_int32 len, opus_int16 *pcm,
                             int frame_size, int decode_fec);
typedef const char* (*opus_strerror_t)(int error);

static opus_encoder_create_t  p_opus_encoder_create  = nullptr;
static opus_encoder_destroy_t p_opus_encoder_destroy = nullptr;
static opus_decoder_create_t  p_opus_decoder_create  = nullptr;
static opus_decoder_destroy_t p_opus_decoder_destroy = nullptr;
static opus_encode_t          p_opus_encode          = nullptr;
static opus_decode_t          p_opus_decode          = nullptr;
static opus_strerror_t        p_opus_strerror        = nullptr;

static bool loadOpusDll()
{
    if (g_opusModule)
        return true;

    g_opusModule = LoadLibraryA("opus.dll");
    if (!g_opusModule) {
        std::cerr << "Failed to load opus.dll\n";
        return false;
    }

    auto loadSym = [](HMODULE mod, const char* name) -> FARPROC {
        FARPROC p = GetProcAddress(mod, name);
        if (!p)
            std::cerr << "Missing symbol in opus.dll: " << name << "\n";
        return p;
    };

    p_opus_encoder_create  = (opus_encoder_create_t)  loadSym(g_opusModule, "opus_encoder_create");
    p_opus_encoder_destroy = (opus_encoder_destroy_t) loadSym(g_opusModule, "opus_encoder_destroy");
    p_opus_decoder_create  = (opus_decoder_create_t)  loadSym(g_opusModule, "opus_decoder_create");
    p_opus_decoder_destroy = (opus_decoder_destroy_t) loadSym(g_opusModule, "opus_decoder_destroy");
    p_opus_encode          = (opus_encode_t)          loadSym(g_opusModule, "opus_encode");
    p_opus_decode          = (opus_decode_t)          loadSym(g_opusModule, "opus_decode");
    p_opus_strerror        = (opus_strerror_t)        loadSym(g_opusModule, "opus_strerror");

    if (!p_opus_encoder_create || !p_opus_encoder_destroy ||
        !p_opus_decoder_create || !p_opus_decoder_destroy ||
        !p_opus_encode || !p_opus_decode || !p_opus_strerror)
    {
        std::cerr << "opus.dll missing required functions\n";
        FreeLibrary(g_opusModule);
        g_opusModule = NULL;
        return false;
    }

    return true;
}

static void unloadOpusDll()
{
    if (g_opusModule) {
        FreeLibrary(g_opusModule);
        g_opusModule = NULL;
    }
}
#else
static bool loadOpusDll()     { return true; }
static void unloadOpusDll()   {}
#endif

static bool initOpus(const ClientConfig& cfg)
{
    if (!cfg.use_opus)
        return true;

    if (!loadOpusDll()) {
        std::cerr << "Opus DLL load failed\n";
        return false;
    }

    int err = 0;
    int sampleRate = cfg.sample_rate;
    int channels   = cfg.channels;

    g_opusFrameSize = (int)cfg.frames_per_buffer;

    g_opusEnc = p_opus_encoder_create(sampleRate, channels,
                                      OPUS_APPLICATION_VOIP, &err);
    if (err != OPUS_OK || !g_opusEnc) {
        std::cerr << "Opus encoder create failed: "
                  << (p_opus_strerror ? p_opus_strerror(err) : "unknown") << "\n";
        g_opusEnc = nullptr;
        return false;
    }

    g_opusDec = p_opus_decoder_create(sampleRate, channels, &err);
    if (err != OPUS_OK || !g_opusDec) {
        std::cerr << "Opus decoder create failed: "
                  << (p_opus_strerror ? p_opus_strerror(err) : "unknown") << "\n";
        if (g_opusEnc) {
            p_opus_encoder_destroy(g_opusEnc);
            g_opusEnc = nullptr;
        }
        g_opusDec = nullptr;
        return false;
    }

    return true;
}

static void shutdownOpus()
{
    if (g_opusEnc) {
        if (p_opus_encoder_destroy)
            p_opus_encoder_destroy(g_opusEnc);
        g_opusEnc = nullptr;
    }
    if (g_opusDec) {
        if (p_opus_decoder_destroy)
            p_opus_decoder_destroy(g_opusDec);
        g_opusDec = nullptr;
    }
    unloadOpusDll();
}

static std::vector<char> encodeOpusFrame(const std::vector<char>& pcmBytes)
{
	if (!g_cfg.use_opus || !g_opusEnc || !p_opus_encode) {
		std::cerr << "encodeOpusFrame: Opus not initialized, cannot encode.\n";
		return std::vector<char>();
	}

    if (pcmBytes.empty()) {
        return std::vector<char>();
    }

    size_t samplesTotal    = pcmBytes.size() / sizeof(opus_int16);
    size_t samplesPerFrame = (size_t)g_opusFrameSize * g_channels;

    if (samplesTotal != samplesPerFrame) {
        std::cerr << "encodeOpusFrame: unexpected frame size: "
                  << samplesTotal << " samples, expected "
                  << samplesPerFrame << "\n";
        return std::vector<char>();
    }

    const opus_int16* pcm = reinterpret_cast<const opus_int16*>(pcmBytes.data());
    std::vector<unsigned char> pkt(OPUS_MAX_PACKET_BYTES);

    int nbytes = p_opus_encode(g_opusEnc,
                               pcm,
                               g_opusFrameSize,
                               pkt.data(),
                               (opus_int32)pkt.size());

    if (nbytes < 0) {
        std::cerr << "Opus encode failed: "
                  << (p_opus_strerror ? p_opus_strerror(nbytes) : "error") << "\n";
        return std::vector<char>();
    }

    return std::vector<char>((char*)pkt.data(), (char*)pkt.data() + nbytes);
}

static std::vector<char> decodeOpusFrame(const std::vector<char>& pktBytes)
{
    if (!g_cfg.use_opus || !g_opusDec || !p_opus_decode) {
        return pktBytes;
    }

    if (pktBytes.empty()) {
        return std::vector<char>();
    }

    std::vector<opus_int16> pcm((size_t)g_opusFrameSize * g_channels);

    int nsamples = p_opus_decode(g_opusDec,
                                 (const unsigned char*)pktBytes.data(),
                                 (opus_int32)pktBytes.size(),
                                 pcm.data(),
                                 g_opusFrameSize,
                                 0 /* no FEC */);

    if (nsamples < 0) {
        std::cerr << "Opus decode failed: "
                  << (p_opus_strerror ? p_opus_strerror(nsamples) : "error") << "\n";
        return std::vector<char>();
    }

    if (nsamples == 0) {
        return std::vector<char>();
    }

    size_t totalSamples = (size_t)nsamples * g_channels;
    std::vector<char> out(totalSamples * sizeof(opus_int16));
    std::memcpy(out.data(), pcm.data(), out.size());

    return out;
}
#endif

static void ParseCm108Command(const std::string& cmd, std::string& hiddev, int& pinOut)
{
    hiddev.clear();
    pinOut = 0;

    std::istringstream iss(cmd);
    std::string tok;
    while (iss >> tok) {
        if (tok == "-H") {
            iss >> hiddev;
        } else if (tok == "-P") {
            std::string sval;
            if (iss >> sval) {
                pinOut = std::atoi(sval.c_str());
            }
        }
    }

#ifdef __linux__
    if (hiddev.empty()) {
        hiddev = "/dev/hidraw0";
    }
#else
    (void)hiddev;
#endif

    if (pinOut <= 0 || pinOut > 8) {
        pinOut = 3;
    }
}

#ifdef __linux__
#include <sys/stat.h>
#include <fcntl.h>

static int  g_gpioPin        = -1;
static bool g_gpioActiveHigh = true;
static bool g_gpioConfigured = false;

bool gpioExport(int pin) {
    std::ofstream ofs("/sys/class/gpio/export");
    if (!ofs.is_open()) return false;
    ofs << pin;
    return true;
}

bool gpioUnexport(int pin) {
    std::ofstream ofs("/sys/class/gpio/unexport");
    if (!ofs.is_open()) return false;
    ofs << pin;
    return true;
}

bool gpioSetDirection(int pin, const std::string& dir) {
    std::ostringstream path;
    path << "/sys/class/gpio/gpio" << pin << "/direction";
    std::ofstream ofs(path.str().c_str());
    if (!ofs.is_open()) return false;
    ofs << dir;
    return true;
}

bool gpioSetValue(int pin, int value) {
    std::ostringstream path;
    path << "/sys/class/gpio/gpio" << pin << "/value";
    std::ofstream ofs(path.str().c_str());
    if (!ofs.is_open()) return false;
    ofs << value;
    return true;
}

bool initGpioPtt(const ClientConfig& cfg) {
    if (!cfg.gpio_ptt_enabled)
        return true;

    g_pttCmdOn.clear();
    g_pttCmdOff.clear();
    g_pttUseShell = false;
    g_pttUseCm108 = false;
    g_cm108Dev.clear();
    g_cm108Pin = 0;

    if (!cfg.ptt_cmd_on.empty() &&
        cfg.ptt_cmd_on.find("cm108") != std::string::npos)
    {
        ParseCm108Command(cfg.ptt_cmd_on, g_cm108Dev, g_cm108Pin);

		LOG_INFO("PTT: using built-in CM108, dev=%s pin=%d\n",g_cm108Dev.c_str(), g_cm108Pin);

        g_pttUseCm108 = true;
        return true;
    }

    if (!cfg.ptt_cmd_on.empty() || !cfg.ptt_cmd_off.empty()) {
        g_pttCmdOn  = cfg.ptt_cmd_on;
        g_pttCmdOff = cfg.ptt_cmd_off;
        g_pttUseShell = true;

        LOG_INFO("PTT: using shell commands: ON=\"%s\" OFF=\"%s\"\n", g_pttCmdOn.c_str(), g_pttCmdOff.c_str());

        return true;
    }

    g_gpioPin        = cfg.gpio_ptt_pin;
    g_gpioActiveHigh = cfg.gpio_ptt_active_high;

    gpioExport(g_gpioPin);
    if (!gpioSetDirection(g_gpioPin, "out")) {
        LOG_ERROR("Failed to set GPIO direction (need root or udev rules).\n");
        return false;
    }

    gpioSetValue(g_gpioPin, g_gpioActiveHigh ? 0 : 1);
    g_gpioConfigured = true;
    LOG_INFO("GPIO PTT on pin %d (active_%s)\n",g_gpioPin, g_gpioActiveHigh ? "high" : "low");
    return true;
}

void setPtt(bool on)
{
    if (!g_cfg.gpio_ptt_enabled)
        return;

    if (g_pttUseCm108) {
        const char* dev = g_cm108Dev.empty() ? nullptr : g_cm108Dev.c_str();
        int state = on ? 1 : 0;
        int rc = cm108_set_gpio_pin((char*)dev, g_cm108Pin, state);
        if (rc != 0) {
            LOG_WARN("PTT: cm108_set_gpio_pin failed (rc=%d, dev=%s, pin=%d)\n",rc, (dev ? dev : "auto"), g_cm108Pin);
        }
        return;
    }

    if (g_pttUseShell) {
        const std::string& cmd = on ? g_pttCmdOn : g_pttCmdOff;
        if (!cmd.empty()) {
            LOG_INFO("PTT: executing \"%s\"\n", cmd.c_str());
            system(cmd.c_str());
        }
        return;
    }

    int v = (g_gpioActiveHigh ? (on ? 1 : 0) : (on ? 0 : 1));
    gpioSetValue(g_gpioPin, v);
}

void shutdownGpioPtt() {
    if (!g_gpioConfigured) return;

    setPtt(false);

    if (!g_pttUseShell) {
        gpioUnexport(g_gpioPin);
    }

    g_gpioConfigured = false;
    g_pttUseShell = false;
    g_pttCmdOn.clear();
    g_pttCmdOff.clear();
}

#else

static HANDLE g_gpioHandle     = INVALID_HANDLE_VALUE;
static bool   g_gpioConfigured = false;
static bool   g_gpioActiveHigh = true;

bool initGpioPtt(const ClientConfig& cfg)
{
    if (!cfg.gpio_ptt_enabled)
        return true;

    g_pttCmdOn.clear();
    g_pttCmdOff.clear();
    g_pttUseShell = false;
    g_pttUseCm108 = false;
    g_cm108Dev.clear();
    g_cm108Pin = 0;

    if (!cfg.ptt_cmd_on.empty() &&
        cfg.ptt_cmd_on.find("cm108") != std::string::npos)
    {
        ParseCm108Command(cfg.ptt_cmd_on, g_cm108Dev, g_cm108Pin);

        LOG_INFO("PTT: using built-in CM108 (Windows), pin=%d\n", g_cm108Pin);

        g_pttUseCm108 = true;
        return true;
    }

    if (!cfg.ptt_cmd_on.empty() || !cfg.ptt_cmd_off.empty()) {
        g_pttCmdOn  = cfg.ptt_cmd_on;
        g_pttCmdOff = cfg.ptt_cmd_off;
        g_pttUseShell = true;

        LOG_INFO("PTT: using shell commands: ON=\"%s\" OFF=\"%s\"\n",g_pttCmdOn.c_str(), g_pttCmdOff.c_str());

        return true;
    }

    return true;
}

void setPtt(bool on)
{
    if (!g_cfg.gpio_ptt_enabled)
        return;

    if (g_pttUseCm108) {
        int state = on ? 1 : 0;
        int rc = cm108_set_gpio_pin(nullptr, g_cm108Pin, state);
        if (rc != 0) {
            LOG_WARN("PTT: cm108_set_gpio_pin (Windows) failed, rc=%d, pin=%d\n",rc, g_cm108Pin);
        }
        return;
    }

    if (g_pttUseShell) {
        const std::string& cmd = on ? g_pttCmdOn : g_pttCmdOff;
        if (!cmd.empty()) {
            int rc = std::system(cmd.c_str());
            (void)rc;
        }
        return;
    }
}

void shutdownGpioPtt() {
    setPtt(false);
    g_pttUseShell = false;
    g_pttCmdOn.clear();
    g_pttCmdOff.clear();
}
#endif

std::atomic<bool> g_pttAutoEnabled(false);
std::atomic<bool> g_pttState(false);
std::atomic<std::chrono::steady_clock::time_point> g_lastRxAudioTime;
std::atomic<int> g_pttHoldMs(250);

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
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f.is_open()) {
        LOG_WARN("Roger WAV open failed: %s\n", path.c_str());
        return false;
    }

    WavHeader h;
    f.read(reinterpret_cast<char*>(&h), sizeof(h));
    if (!f.good()) {
        LOG_WARN("Failed to read WAV header for roger.wav\n");
        return false;
    }

    if (std::strncmp(h.riff, "RIFF", 4) != 0 ||
        std::strncmp(h.wave, "WAVE", 4) != 0 ||
        std::strncmp(h.fmt,  "fmt ", 4)  != 0 ||
        std::strncmp(h.dataId, "data", 4) != 0) {
        LOG_WARN("Roger.wav is not a simple PCM WAV\n");
        return false;
    }

    if (h.audioFormat != 1 || h.numChannels != 1 || h.bitsPerSample != 16) {
        LOG_WARN("Roger.wav must be PCM, mono, 16-bit\n");
        return false;
    }

    outSampleRate = h.sampleRate;
    size_t numSamples = h.dataSize / sizeof(int16_t);
    outPcm.resize(numSamples);
    f.read(reinterpret_cast<char*>(outPcm.data()), h.dataSize);
    if (!f.good()) {
        LOG_WARN("Failed to read roger.wav samples\n");
        return false;
    }
    return true;
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
        default:
            wav = "roger.wav";
            break;
    }

    loadRogerSound(wav);
}

void playMicFreeSound() {
    if (g_outputStream && !g_rogerSamples.empty()) {
        std::vector<int16_t> out;
        if (g_channels == 1) {
            out = g_rogerSamples;
        } else {
            out.resize(g_rogerSamples.size() * g_channels);
            for (size_t i = 0; i < g_rogerSamples.size(); ++i) {
                for (int ch = 0; ch < g_channels; ++ch) {
                    out[i * g_channels + ch] = g_rogerSamples[i];
                }
            }
        }
        unsigned long frames = (unsigned long)(out.size() / g_channels);
        PaError err = Pa_WriteStream(g_outputStream, out.data(), frames);
        if (err != paNoError && err != paOutputUnderflowed) {
            LOG_WARN("Failed to play roger.wav: %s\n", Pa_GetErrorText(err));
        }
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

bool initPortAudio(const ClientConfig& cfg) {
    PaError err = Pa_Initialize();
    if (err != paNoError) {
        LOG_ERROR("PortAudio init error: %s\n", Pa_GetErrorText(err));
        return false;
    }

    logPaDevices();

    g_sampleRate      = cfg.sample_rate;
    g_framesPerBuffer = cfg.frames_per_buffer;

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

    unsigned long outFramesPerBuffer = g_framesPerBuffer * 3;

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


void shutdownPortAudio() {
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

void playAudioFrame(const std::vector<char>& frame) {
    if (frame.empty()) return;
    size_t sampleCount = frame.size() / sizeof(int16_t);
    unsigned long frames = (unsigned long)(sampleCount / g_channels);
    if (frames == 0) return;

    const int16_t* inSamples = reinterpret_cast<const int16_t*>(frame.data());

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

    PaError err = Pa_WriteStream(g_outputStream, outSamples.data(), frames);

    static int underflowWarnCount = 0;

    if (err == paOutputUnderflowed) {
        if (underflowWarnCount < 5) {
            LOG_WARN("Warning: output underflow (audio may glitch)\n");
            underflowWarnCount++;
        }
    } else if (err != paNoError) {
        LOG_ERROR("Pa_WriteStream fatal error: %s\n", Pa_GetErrorText(err));
    }

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

std::atomic<bool> g_running(true);
std::atomic<bool> g_canTalk(false);
std::atomic<int>  g_maxTalkMs(0);
ClientConfig g_cfg;

std::atomic<float> g_inputGain(1.0f);
std::atomic<float> g_outputGain(1.0f);

std::mutex g_speakerMutex;
std::string g_currentSpeaker;

std::mutex g_tgListMutex;
std::vector<std::string> g_serverTalkgroups;

#ifdef GUI
extern std::vector<std::string> g_tgComboItems;
extern int ui_tg_index;
extern std::string ui_talkgroup;
#endif

static const int VOX_TRIGGER_FRAMES_NEEDED  = 6;
static const int VOX_SILENCE_FRAMES_NEEDED  = 100;
static const int VOX_SPEAK_GRANT_TIMEOUT_MS = 50;

static const int VOX_CALIB_FRAMES        = 40;
static const int VOX_MIN_THRESHOLD_PEAK  = 1000;
static const int VOX_MAX_THRESHOLD_PEAK  = 25000;

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
#ifdef OPUS
            std::ostringstream oss;
			std::vector<char> frame = captureAudioFrame();
			std::vector<char> payload;
			std::string audioCmd;

			if (g_cfg.use_opus) {
				payload = encodeOpusFrame(frame);

				if (payload.empty()) {
					payload  = std::move(frame);
					audioCmd = "AUDIO";
				} else {
					audioCmd = "AUDIO_OPUS";
				}
			} else {
				payload = std::move(frame);
				audioCmd = "AUDIO";
			}

			oss << audioCmd << " " << payload.size() << "\n";
			std::string header = oss.str();

			if (!sendAll(sock, header.data(), header.size())) {
				std::cout << "Failed to send AUDIO header (ending talk session).\n";
				break;
			}
			if (!sendAll(sock, payload.data(), payload.size())) {
				std::cout << "Failed to send AUDIO data (ending talk session).\n";
				break;
			}
#else
            std::ostringstream oss;
            oss << "AUDIO " << frame.size() << "\n";
            std::string header = oss.str();

            if (!sendAll(sock, header.data(), header.size())) {
                std::cerr << "Failed to send AUDIO header\n";
                g_running = false;
                break;
            }
            if (!sendAll(sock, frame.data(), frame.size())) {
                std::cerr << "Failed to send AUDIO data\n";
                g_running = false;
                break;
            }
#endif
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


void receiverLoop(SOCKET sock) {
    while (g_running) {
        std::string line;
        if (!recvLine(sock, line)) {
            LOG_WARN("Disconnected from server.\n");
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
#ifdef OPUS
		else if (cmd == "AUDIO_FROM" || cmd == "AUDIO_FROM_OPUS") {
			std::string user;
			size_t size;
			iss >> user >> size;
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
			g_lastRxAudioTime = std::chrono::steady_clock::now();

			std::vector<char> pcm;
			if (cmd == "AUDIO_FROM_OPUS" && g_cfg.use_opus) {
				pcm = decodeOpusFrame(buf);
			} else {
				pcm = std::move(buf);
			}

			if (!pcm.empty()) {
				playAudioFrame(pcm);
			}
#else
		else if (cmd == "AUDIO_FROM") {
			std::string user;
			size_t size;
			iss >> user >> size;
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
			g_lastRxAudioTime = std::chrono::steady_clock::now();
			playAudioFrame(buf);
#endif
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

        std::ostringstream oss;
        oss << "AUDIO " << frame.size() << "\n";
        std::string header = oss.str();

        if (!sendAll(sock, header.data(), header.size())) {
            std::cout << "Failed to send AUDIO header (ending talk session).\n";
            break;
        }
        if (!sendAll(sock, frame.data(), frame.size())) {
            std::cout << "Failed to send AUDIO data (ending talk session).\n";
            break;
        }
    }

    if (!voxMode && stopThread.joinable()) {
        stopThread.join();
    }

    std::string endCmd = "END_SPEAK\n";
    sendAll(sock, endCmd.data(), endCmd.size());
    g_canTalk = false;
    std::cout << "Stopped talking.\n";
}

void doParrotSession(bool usePtt) {
    const bool voxMode = g_cfg.vox_enabled;

    std::cout << "Parrot test: recording mic, then replaying.\n";
    if (voxMode) {
        std::cout << "VOX is ENABLED (threshold=" << g_cfg.vox_threshold
                  << "). Talk to record; staying silent will automatically stop and start playback.\n";
    } else {
        std::cout << "VOX is DISABLED. Press ENTER to stop recording and hear the playback.\n";
    }

    if (usePtt) {
        setPtt(true);
    }

    const int silenceFramesNeeded = 50;
    int  silenceFrames = 0;
    bool hadVoice      = false;

    std::vector<std::vector<char>> recordedFrames;

    if (voxMode) {
        while (true) {
            std::vector<char> frame = captureAudioFrame();
            if (frame.empty()) {
                continue;
            }

            bool above = frameAboveVoxThreshold(frame, g_cfg.vox_threshold);

            if (above) {
                hadVoice = true;
                silenceFrames = 0;
                recordedFrames.push_back(std::move(frame));
            } else {
                if (hadVoice) {
                    ++silenceFrames;
                    if (silenceFrames >= silenceFramesNeeded) {
                        std::cout << "[PARROT] VOX: silence detected, stopping recording.\n";
                        break;
                    }
                }
            }
        }
    } else {
        std::atomic<bool> stop(false);
        std::thread stopThread([&]() {
            std::string s;
            std::getline(std::cin, s);
            stop = true;
        });

        while (!stop) {
            std::vector<char> frame = captureAudioFrame();
            if (frame.empty()) {
                continue;
            }
            recordedFrames.push_back(std::move(frame));
        }

        if (stopThread.joinable()) {
            stopThread.join();
        }
    }

    if (usePtt) {
        setPtt(false);
    }

    if (recordedFrames.empty()) {
        std::cout << "Parrot: nothing recorded.\n";
        std::cout << "Parrot session ended.\n";
        return;
    }

    std::cout << "Parrot: playing back your recording (" << recordedFrames.size()
              << " frames)...\n";

    for (auto &f : recordedFrames) {
        playAudioFrame(f);
    }

    std::cout << "Parrot session ended.\n";
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
#ifdef OPUS
	if (g_cfg.use_opus) {
		if (!initOpus(g_cfg)) {
			std::cerr << "Opus init failed, falling back to PCM.\n";
			g_cfg.use_opus = false;
		}
	}
#endif
	loadRogerFromConfig();
    if (!initGpioPtt(g_cfg)) {
        std::cerr << "GPIO PTT init failed.\n";
    }
	g_pttHoldMs = g_cfg.gpio_ptt_hold_ms;
	if (g_cfg.gpio_ptt_enabled && !g_cfg.vox_enabled) {
		std::thread(pttManagerThreadFunc).detach();
	}

    if (g_cfg.mode == "parrot") {
        parrotLoop(g_cfg);
        shutdownPortAudio();
#ifdef OPUS
		shutdownOpus();
#endif
        shutdownGpioPtt();
        return 0;
    }

    initSockets();
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Failed to create socket\n";
        cleanupSockets();
        shutdownPortAudio();
#ifdef OPUS
		shutdownOpus();
#endif
        shutdownGpioPtt();
        return 1;
    }

	struct addrinfo hints;
	std::memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_INET;
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
#ifdef OPUS
		shutdownOpus();
#endif
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
#ifdef OPUS
		shutdownOpus();
#endif
		shutdownGpioPtt();
		return 1;
	}

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(g_cfg.server_port);
    if (inet_pton(AF_INET, g_cfg.server_ip.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "Invalid server IP\n";
        closeSocket(sock);
        cleanupSockets();
        shutdownPortAudio();
#ifdef OPUS
		shutdownOpus();
#endif
        shutdownGpioPtt();
        return 1;
    }

	if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
#ifdef _WIN32
		int err = WSAGetLastError();
		if (err != WSAEISCONN) {
			std::cerr << "Connect failed to " << g_cfg.server_ip << ":" << g_cfg.server_port
					  << " (WSA error " << err << ")\n";
			closeSocket(sock);
			cleanupSockets();
			shutdownPortAudio();
#ifdef OPUS
			shutdownOpus();
#endif
			shutdownGpioPtt();
			return 1;
		}
#else
		std::cerr << "Connect failed to " << g_cfg.server_ip << ":" << g_cfg.server_port << "\n";
		closeSocket(sock);
		cleanupSockets();
		shutdownPortAudio();
#ifdef OPUS
		shutdownOpus();
#endif
		shutdownGpioPtt();
		return 1;
#endif
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
#ifdef OPUS
			shutdownOpus();
#endif
            shutdownGpioPtt();
            return 1;
        }
        std::string line;
        if (!recvLine(sock, line)) {
            LOG_ERROR("AUTH response failed\n");
            closeSocket(sock);
            cleanupSockets();
            shutdownPortAudio();
#ifdef OPUS
			shutdownOpus();
#endif
            shutdownGpioPtt();
            return 1;
        }
        if (line != "AUTH_OK") {
            LOG_ERROR("Auth failed: %s\n", line.c_str());
            closeSocket(sock);
            cleanupSockets();
            shutdownPortAudio();
#ifdef OPUS
			shutdownOpus();
#endif
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
#ifdef OPUS
			shutdownOpus();
#endif
            shutdownGpioPtt();
            return 1;
        }
        std::string line;
        if (!recvLine(sock, line)) {
            LOG_ERROR("JOIN response failed\n");
            closeSocket(sock);
            cleanupSockets();
            shutdownPortAudio();
#ifdef OPUS
			shutdownOpus();
#endif
            shutdownGpioPtt();
            return 1;
        }
        LOG_INFO("[SERVER] %s\n", line.c_str());
        if (line.find("JOIN_OK") != 0) {
            LOG_ERROR("Join failed.\n");
            closeSocket(sock);
            cleanupSockets();
            shutdownPortAudio();
#ifdef OPUS
			shutdownOpus();
#endif
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
    closeSocket(sock);
    if (recvThread.joinable()) recvThread.join();

    shutdownPortAudio();
#ifdef OPUS
	shutdownOpus();
#endif
    shutdownGpioPtt();
    cleanupSockets();
    return 0;
}
#endif
