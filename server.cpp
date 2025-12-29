#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <sstream>
#include <chrono>
#include <atomic>
#include <fstream>
#include <cstring>
#include <ctime>
#include <map>
#include <cstdlib>
#include <cctype>
#include <cmath>
#include <cstdarg>
#include <algorithm>
#include <cstdio>
#include <random>

#if USE_OPENSSL
  #include <openssl/ssl.h>
  #include <openssl/err.h>
#endif

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #define NOMINMAX
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <mstcpip.h>
  typedef int socklen_t;
  #pragma comment(lib, "Ws2_32.lib")
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <unistd.h>
  #include <netdb.h>
  #include <netinet/tcp.h>
  #include <sys/time.h>
  #define INVALID_SOCKET -1
  #define SOCKET_ERROR -1
  typedef int SOCKET;
#endif

#ifndef HAVE_STD_ROUND
inline double portable_round(double x)
{
    return (x >= 0.0) ? std::floor(x + 0.5) : std::ceil(x - 0.5);
}
#define round portable_round
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
    printf(CYAN "SERVER                          " RESET);
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

static void configureSocketKeepalive(SOCKET s)
{
    int opt = 1;
    if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt, sizeof(opt)) != 0) {
    }

#ifdef _WIN32
    tcp_keepalive ka;
    ka.onoff = 1;
    ka.keepalivetime = 30000;
    ka.keepaliveinterval = 10000;
    DWORD bytesReturned = 0;
    WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &bytesReturned, NULL, NULL);
#else
    #if defined(TCP_KEEPIDLE)
        int idle = 30;
        setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    #elif defined(TCP_KEEPALIVE)
        int idle = 30;
        setsockopt(s, IPPROTO_TCP, TCP_KEEPALIVE, &idle, sizeof(idle));
    #endif

    #if defined(TCP_KEEPINTVL)
        int intvl = 10;
        setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    #endif

    #if defined(TCP_KEEPCNT)
        int cnt = 3;
        setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
    #endif
#endif
}

static void configureSocketForRealtime(SOCKET s)
{
    int flag = 1;
    if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag)) != 0) {
    }
    configureSocketKeepalive(s);
}


static void shutdownSocket(SOCKET s) {
#ifdef _WIN32
    ::shutdown(s, SD_BOTH);
#else
    ::shutdown(s, SHUT_RDWR);
#endif
}

bool sendAll(SOCKET sock, const void* data, size_t len) {
    const char* p = static_cast<const char*>(data);
    size_t off = 0;

    while (off < len) {
        size_t want = len - off;

#ifdef _WIN32
        int n = ::send(sock, p + off, (int)want, 0);
        if (n == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e == WSAEINTR) continue;
            if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) return false;
            return false;
        }
#else
        ssize_t n = ::send(sock, p + off, want, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return false;
            return false;
        }
#endif
        if (n == 0) return false;
        off += (size_t)n;
    }
    return true;
}

bool recvAll(SOCKET sock, void* data, size_t len) {
    char* buf = static_cast<char*>(data);
    while (len > 0) {
        int r = recv(sock, buf, static_cast<int>(len), 0);
        if (r <= 0) return false;
        buf += r;
        len -= r;
    }
    return true;
}

static const size_t MAX_LINE_LEN = 4096;

bool recvLine(SOCKET sock, std::string& line) {
    line.clear();
    line.reserve(128);

    char c;
    while (true) {
        int r = recv(sock, &c, 1, 0);
        if (r <= 0) return false;

        if (c == '\n') break;

        if (c != '\r') {
            if (line.size() >= MAX_LINE_LEN) {
                return false;
            }
            line.push_back(c);
        }
    }
    return true;
}

static bool httpGet(const std::string& host, const std::string& path, std::string& outResponse)
{
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        return false;
    }
#endif

    outResponse.clear();

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = nullptr;
    int err = getaddrinfo(host.c_str(), "80", &hints, &res);
    if (err != 0 || !res) {
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    int sock = -1;
    struct addrinfo* rp = nullptr;

    for (rp = res; rp != nullptr; rp = rp->ai_next) {
#ifdef _WIN32
        sock = static_cast<int>(socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol));
        if (sock == INVALID_SOCKET) {
            continue;
        }
#else
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) {
            continue;
        }
#endif

        if (connect(sock, rp->ai_addr, static_cast<int>(rp->ai_addrlen)) == 0) {
            break;
        }

#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        sock = -1;
    }

    freeaddrinfo(res);

    if (sock < 0) {
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    std::ostringstream req;
    req << "GET " << path << " HTTP/1.1\r\n";
    req << "Host: " << host << "\r\n";
    req << "Connection: close\r\n";
    req << "\r\n";

    std::string data = req.str();
#ifdef _WIN32
    send(sock, data.c_str(), static_cast<int>(data.size()), 0);
#else
    send(sock, data.c_str(), data.size(), 0);
#endif

    char buffer[2048];
    int received = 0;

    while ((received = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
        outResponse.append(buffer, received);
    }

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif

    return !outResponse.empty();
}

enum class Role {
    USER = 0,
    OPERATOR = 1,
    ADMIN = 2
};

static inline const char* roleToStr(Role r) {
    switch (r) {
        case Role::ADMIN:    return "admin";
        case Role::OPERATOR: return "operator";
        default:             return "user";
    }
}

static inline Role roleFromStr(const std::string& s) {
    std::string x = s;
    for (auto& c : x) c = (char)std::tolower((unsigned char)c);
    if (x == "admin")    return Role::ADMIN;
    if (x == "operator") return Role::OPERATOR;
    return Role::USER;
}

static bool hasAtLeast(Role a, Role need);
static bool canOperatorActOn(Role actor, Role target);
static Role getUserRoleUnsafeNoLock(const std::string& cs);

struct User {
    std::string callsign;
    std::string password;
    std::unordered_set<std::string> talkgroups;
    Role role;
    std::unordered_set<std::string> permissions;
    bool muted;
    bool banned;
    std::string remoteIp;
    int priority;
};

extern std::atomic<bool> g_running;

static std::map<std::string, std::chrono::steady_clock::time_point> g_tgWaveLastUpdate;

static const size_t MAX_TX_QUEUE_BYTES = 512 * 1024;
static const size_t DROP_AUDIO_AFTER = 256 * 1024;

struct TxChunk {
    std::vector<char> data;
    size_t off;
    bool isAudio;
};

struct ClientTxState {
    std::mutex m;
    std::condition_variable cv;
    std::deque<TxChunk> q;
    size_t queuedBytes;
    std::atomic<bool> alive;

    ClientTxState() : queuedBytes(0), alive(true) {}
};

static bool enqueueToTx(const std::shared_ptr<ClientTxState>& tx,
                        const void* data,
                        size_t len,
                        bool isAudio)
{
    if (!tx || len == 0) return true;

    if (isAudio && tx->queuedBytes > DROP_AUDIO_AFTER) {
        return true;
    }

    std::unique_lock<std::mutex> lk(tx->m);
    if (!tx->alive.load()) return false;

    if (tx->queuedBytes + len > MAX_TX_QUEUE_BYTES) {
        return false;
    }

    TxChunk ch;
    ch.data.assign((const char*)data, (const char*)data + len);
    ch.off = 0;
    ch.isAudio = isAudio;

    tx->queuedBytes += len;
    tx->q.push_back(std::move(ch));
    lk.unlock();
    tx->cv.notify_one();
    return true;
}

static bool enqueueStrToTx(const std::shared_ptr<ClientTxState>& tx,
                           const std::string& s,
                           bool isAudio)
{
    return enqueueToTx(tx, s.data(), s.size(), isAudio);
}

static void clientSenderThreadFunc(SOCKET sock, std::shared_ptr<ClientTxState> tx)
{
    while (g_running) {
        TxChunk cur;

        {
            std::unique_lock<std::mutex> lk(tx->m);
            tx->cv.wait(lk, [&]{
                return !g_running || !tx->alive.load() || !tx->q.empty();
            });

            if (!g_running || !tx->alive.load()) break;

            cur = std::move(tx->q.front());
            tx->q.pop_front();
        }

        while (tx->alive.load() && cur.off < cur.data.size()) {
            const char* p = cur.data.data() + cur.off;
            size_t want = cur.data.size() - cur.off;

#ifdef _WIN32
            int n = ::send(sock, p, (int)want, 0);
            if (n == SOCKET_ERROR) {
                int e = WSAGetLastError();
                if (e == WSAEINTR) continue;
                break;
            }
#else
            ssize_t n = ::send(sock, p, want, MSG_NOSIGNAL);
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                break;
            }
#endif
            if (n <= 0) break;
            cur.off += (size_t)n;

            {
                std::lock_guard<std::mutex> lk(tx->m);
                tx->queuedBytes = (tx->queuedBytes >= (size_t)n) ? (tx->queuedBytes - (size_t)n) : 0;
            }
        }

        if (cur.off < cur.data.size()) {
            tx->alive.store(false);
            shutdownSocket(sock);
            break;
        }
    }
}

struct ClientInfo {
    SOCKET sock;
    std::string callsign;
    std::string talkgroup;
    bool authenticated;
    std::string remoteAddr;
    std::shared_ptr<ClientTxState> tx;
};

struct TalkgroupState {
    std::string name;
    std::string activeSpeaker;
    std::chrono::steady_clock::time_point speakStart;
    std::chrono::steady_clock::time_point lastAudio;
};

struct LastHeardInfo {
    std::string talkgroup;
    std::chrono::system_clock::time_point when;
};

std::mutex g_lastHeardMutex;
std::map<std::string, LastHeardInfo> g_lastHeard;

static bool clientIsSpeaking(const TalkgroupState& ts)
{
    if (ts.activeSpeaker.empty()) return false;
    if (ts.lastAudio.time_since_epoch().count() == 0) return false;

    auto now  = std::chrono::steady_clock::now();
    long long idle =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - ts.lastAudio).count();

    return (idle < 1500);
}

struct TimeAnnounceConfig {
    bool enabled;
    std::string folder;
    float volumeFactor;
};

struct TalkgroupAnnounceState {
    bool active;
    size_t posSamples;
    std::string key;
};

struct CachedWav {
    std::vector<int16_t> samples;
    uint32_t sampleRate;
};

std::mutex g_mutex;
std::unordered_map<std::string, User> g_users;

enum class TalkgroupMode {
    PUBLIC, HIDE, ADMIN
};

struct TalkgroupInfo {
    std::string name;
    TalkgroupMode mode;
};

std::unordered_map<std::string, TalkgroupInfo> g_knownTalkgroups;

std::unordered_map<SOCKET, ClientInfo> g_clients;
std::unordered_map<std::string, TalkgroupState> g_talkgroups;

std::atomic<bool> g_running(true);
int g_server_port = 26613;
int g_max_talk_ms = 600000;

std::string g_http_root = "dashboard";
int g_http_port = 8080;

int g_https_port = 8443;
std::string g_https_cert_file = "cert.pem";
std::string g_https_key_file  = "key.pem";

TimeAnnounceConfig g_timeCfg;

std::mutex g_announceMutex;
std::unordered_map<std::string, TalkgroupAnnounceState> g_tgAnnounce;

std::mutex g_timeCacheMutex;
std::map<std::string, CachedWav> g_wavCache;

std::atomic<bool> g_timeThreadRunning(false);
std::atomic<bool> g_announcePumpRunning(false);

std::mutex g_audioBufMutex;
std::map<std::string, std::vector<char> > g_tgAudioBuf;
std::map<std::string, std::vector<int16_t> > g_tgWaveHistory;

struct WeatherConfig {
    bool enabled;
	std::string weatherHostIp;
    std::string talkgroup;
    int intervalSec;
    std::string apiKey;
    std::string lat;
    std::string lon;
    std::string cityKey;
};

struct WeatherData {
    std::string iconCode;
    int tempC;
};

WeatherConfig g_weatherCfg = { false, "", "", 600, "", "", "", "" };
std::atomic<bool> g_weatherThreadRunning(false);

bool fetchWeatherFromOpenWeather(WeatherData& out);
bool buildCompositeWav(const std::vector<std::string>& keys,const std::string& compositeKey,CachedWav& out);
std::vector<std::string> buildWeatherSegmentKeys(const WeatherData& wd);

static bool canSeeTalkgroup(Role role, const TalkgroupInfo& tg)
{
    if (tg.mode == TalkgroupMode::PUBLIC) return true;
    if (tg.mode == TalkgroupMode::HIDE)   return (role >= Role::OPERATOR);
    if (tg.mode == TalkgroupMode::ADMIN)  return (role >= Role::ADMIN);
    return true;
}

static bool showInClientList(const TalkgroupInfo& tg, const User* user)
{
    Role r = user ? user->role : Role::USER;
    return canSeeTalkgroup(r, tg);
}

static void sendTalkgroupListForUser(SOCKET sock, const std::string& callsign)
{
    std::ostringstream oss;
    oss << "TGLIST ";
    bool first = true;

    {
        std::lock_guard<std::mutex> lock(g_mutex);

        Role role = Role::USER;
        auto uit = g_users.find(callsign);
        if (uit != g_users.end()) role = uit->second.role;

        for (const auto& kv : g_knownTalkgroups) {
            const TalkgroupInfo& tg = kv.second;
            if (!canSeeTalkgroup(role, tg)) continue;

            if (!first) oss << ",";
            first = false;
            oss << tg.name;
        }
    }

    oss << "\n";
    std::string msg = oss.str();
    sendAll(sock, msg.c_str(), msg.size());
}

static std::unordered_map<std::string, std::vector<std::string>> g_linkedTalkgroups;

static std::vector<std::string> getLinkedFanout(const std::string& tg) {
    std::vector<std::string> result;
    if (tg.empty()) return result;

    result.push_back(tg);

    auto it = g_linkedTalkgroups.find(tg);
    if (it != g_linkedTalkgroups.end()) {
        for (const auto& link : it->second) {
            if (!link.empty() &&
                std::find(result.begin(), result.end(), link) == result.end()) {
                result.push_back(link);
            }
        }
    }
    return result;
}

struct PeerRule {
    std::string localTg;
    std::string remoteTg;
    enum Dir { TX, RX, BOTH } dir;
};

struct PeerConfig {
    std::string name;
    std::string host;
    int         port;
    std::string secret;
    std::vector<std::string> ruleStr;
    std::vector<PeerRule> rules;

    PeerConfig() : port(0) {}
};

struct PeerConn {
    std::string peerName;
    SOCKET sock;
    std::mutex sendMutex;
    std::atomic<bool> running;
    std::thread th;

    PeerConn() : sock(INVALID_SOCKET), running(false) {}
};

static std::string g_serverName = "Server";
static std::string g_peerSecret;
static std::vector<PeerConfig> g_peerCfg;
static std::mutex g_peerMutex;
static std::unordered_map<std::string, PeerConn*> g_peerConns;

static std::mutex g_bridgeSeenMutex;
static std::unordered_map<std::string, std::chrono::steady_clock::time_point> g_bridgeSeen;
static const int PEER_HOP_MAX = 1;

static std::mutex g_bridgeIdMutex;
static std::unordered_map<std::string, std::string> g_activeBridgeIdByTg;
static std::atomic<uint64_t> g_bridgeSeq(0);


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
    size_t firstQuote = line.find('"', colon + 1);
    if (firstQuote == std::string::npos) return false;
    size_t secondQuote = line.find('"', firstQuote + 1);
    if (secondQuote == std::string::npos) return false;
    out = line.substr(firstQuote + 1, secondQuote - firstQuote - 1);
    return true;
}

static bool parseIntField(const std::string& line, const std::string& key, int& out) {
    std::string token = "\"" + key + "\"";
    if (line.find(token) == std::string::npos) return false;
    size_t colon = line.find(':', line.find(token));
    if (colon == std::string::npos) return false;
    std::string num = trim(line.substr(colon + 1));
    if (!num.empty() && num.back() == ',') num.pop_back();
    out = std::atoi(num.c_str());
    return true;
}

static bool parseBoolField(const std::string& line, const std::string& key, bool& out) {
    std::string token = "\"" + key + "\"";
    if (line.find(token) == std::string::npos) return false;
    size_t colon = line.find(':', line.find(token));
    if (colon == std::string::npos) return false;
    std::string val = trim(line.substr(colon + 1));
    if (!val.empty() && val.back() == ',') val.pop_back();
    if (val == "true")  { out = true; return true; }
    if (val == "false") { out = false; return true; }
    return false;
}

static bool parseFloatField(const std::string& line, const std::string& key, float& out) {
    std::string token = "\"" + key + "\"";
    if (line.find(token) == std::string::npos) return false;
    size_t colon = line.find(':', line.find(token));
    if (colon == std::string::npos) return false;
    std::string val = trim(line.substr(colon + 1));
    if (!val.empty() && val.back() == ',') val.pop_back();
    out = static_cast<float>(std::atof(val.c_str()));
    return true;
}

static bool parseStringArray(const std::string& line, const std::string& key, std::vector<std::string>& out) {
    std::string token = "\"" + key + "\"";
    if (line.find(token) == std::string::npos) return false;
    size_t lbr = line.find('[', line.find(token));
    size_t rbr = line.find(']', lbr);
    if (lbr == std::string::npos || rbr == std::string::npos) return false;
    std::string inside = line.substr(lbr + 1, rbr - lbr - 1);
    out.clear();
    size_t pos = 0;
    while (true) {
        size_t q1 = inside.find('"', pos);
        if (q1 == std::string::npos) break;
        size_t q2 = inside.find('"', q1 + 1);
        if (q2 == std::string::npos) break;
        out.push_back(inside.substr(q1 + 1, q2 - q1 - 1));
        pos = q2 + 1;
    }
    return true;
}

bool loadConfig(const std::string& path) {
    std::ifstream f(path.c_str());
    if (!f.is_open()) {
        LOG_ERROR("Failed to open config file: %s\n", path.c_str());
        return false;
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) {
        lines.push_back(line);
    }

    g_users.clear();
    g_knownTalkgroups.clear();
    g_talkgroups.clear();
    g_linkedTalkgroups.clear();

    bool inUsers      = false;
    bool inUserObject = false;
    bool inTalkgroups = false;
    bool inBridges    = false;
	bool inPeers 	  = false;

	PeerConfig currentPeer;
    User currentUser;
	TalkgroupInfo currentTg;

    for (size_t i = 0; i < lines.size(); ++i) {
        std::string l = trim(lines[i]);

        int val;
        if (parseIntField(l, "server_port", val)) {
            g_server_port = val;
            continue;
        }
        if (parseIntField(l, "max_talk_ms", val)) {
            g_max_talk_ms = val;
            continue;
        }

        bool bval;
        float fval;
        std::string sval;

        if (parseStringField(l, "server_name", sval)) {
            g_serverName = sval;
            continue;
        }
        if (parseStringField(l, "peer_secret", sval)) {
            g_peerSecret = sval;
            continue;
        }

        if (parseStringField(l, "http_root", sval)) {
            g_http_root = sval;
            continue;
        }
        if (parseIntField(l, "http_port", val)) {
            g_http_port = val;
            continue;
        }

        if (parseIntField(l, "https_port", val)) {
            g_https_port = val;
            continue;
        }
        if (parseStringField(l, "https_cert_file", sval)) {
            g_https_cert_file = sval;
            continue;
        }
        if (parseStringField(l, "https_key_file", sval)) {
            g_https_key_file = sval;
            continue;
        }

        if (parseBoolField(l, "enabled", bval) && l.find("\"time_announcement\"") == std::string::npos) {
            g_timeCfg.enabled = bval;
            continue;
        }
        if (parseStringField(l, "folder", sval)) {
            g_timeCfg.folder = sval;
            continue;
        }
        if (parseFloatField(l, "volume_factor", fval)) {
            g_timeCfg.volumeFactor = fval;
            continue;
        }

		if (parseStringField(l, "server_name", sval)) {
			g_serverName = sval;
			continue;
		}
		if (parseStringField(l, "peer_secret", sval)) {
			g_peerSecret = sval;
			continue;
		}

		if (l.find("\"users\"") != std::string::npos && l.find('[') != std::string::npos) {
			inUsers = true;
			continue;
		}
		if (inUsers) {
			if (l.find(']') != std::string::npos && l.find("\"talkgroups\"") == std::string::npos) {
				inUsers = false;
				continue;
			}

			if (l.find('{') != std::string::npos) {
				inUserObject = true;
				currentUser = User();
				currentUser.role = Role::USER;
				currentUser.muted   = false;
				currentUser.banned  = false;
				currentUser.priority = 0;
				currentUser.permissions.clear();
				continue;
			}
			if (l.find('}') != std::string::npos) {
				if (inUserObject && !currentUser.callsign.empty()) {
					g_users[currentUser.callsign] = currentUser;
				}
				inUserObject = false;
				continue;
			}
			if (inUserObject) {
				if (parseStringField(l, "callsign", sval)) {
					currentUser.callsign = sval;
					continue;
				}
				if (parseStringField(l, "password", sval)) {
					currentUser.password = sval;
					continue;
				}
				if (parseStringField(l, "role", sval)) {
					currentUser.role = roleFromStr(sval);
					continue;
				}
				if (parseBoolField(l, "is_admin", bval)) {
					if (bval) currentUser.role = Role::ADMIN;
					continue;
				}
				if (parseBoolField(l, "banned", bval)) {
					currentUser.banned = bval;
					continue;
				}
				if (parseIntField(l, "priority", val)) {
					currentUser.priority = val;
					continue;
				}
				std::vector<std::string> tgs;
				if (parseStringArray(l, "talkgroups", tgs)) {
					currentUser.talkgroups.clear();
					for (size_t k = 0; k < tgs.size(); ++k) {
						currentUser.talkgroups.insert(tgs[k]);
					}
					continue;
				}
				std::vector<std::string> perms;
				if (parseStringArray(l, "permissions", perms)) {
					currentUser.permissions.clear();
					for (size_t k = 0; k < perms.size(); ++k) {
						currentUser.permissions.insert(perms[k]);
					}
					continue;
				}
			}
		}

		if (l.find("\"talkgroups\"") != std::string::npos && l.find('[') != std::string::npos) {
			inTalkgroups = true;
			continue;
		}
		if (inTalkgroups) {
			if (l.find("{") != std::string::npos) {
				TalkgroupInfo tg;
				tg.mode = TalkgroupMode::PUBLIC;
				currentTg = tg;
			}

			std::string sval;
			if (parseStringField(l, "name", sval)) {
				currentTg.name = sval;
			}
			if (parseStringField(l, "mode", sval)) {
				if (sval == "hide")
					currentTg.mode = TalkgroupMode::HIDE;
				else if (sval == "admin")
					currentTg.mode = TalkgroupMode::ADMIN;
			}

			if (l.find("}") != std::string::npos) {
				g_knownTalkgroups[currentTg.name] = currentTg;
				g_talkgroups[currentTg.name] = TalkgroupState();
			}
		}

        if (l.find("\"bridges\"") != std::string::npos && l.find('{') != std::string::npos) {
            inBridges = true;
            continue;
        }
        if (inBridges) {
            if (l.find('}') != std::string::npos) {
                inBridges = false;
                continue;
            }

            size_t q1 = l.find('"');
            if (q1 == std::string::npos) continue;
            size_t q2 = l.find('"', q1 + 1);
            if (q2 == std::string::npos) continue;

            std::string tgKey = l.substr(q1 + 1, q2 - q1 - 1);

            std::vector<std::string> linked;
            if (parseStringArray(l, tgKey, linked)) {
                g_linkedTalkgroups[tgKey] = linked;
            }
            continue;
        }

		if (l.find("\"peers\"") != std::string::npos && l.find('[') != std::string::npos) {
			inPeers = true;
			continue;
		}

		if (inPeers) {
			if (l.find("{") != std::string::npos) {
				currentPeer = PeerConfig();
				continue;
			}

			if (parseStringField(l, "name", sval)) {
				currentPeer.name = sval;
				continue;
			}
			if (parseStringField(l, "host", sval)) {
				currentPeer.host = sval;
				continue;
			}
			if (parseStringField(l, "secret", sval)) {
				currentPeer.secret = sval;
				continue;
			}
			if (parseIntField(l, "port", val)) {
				currentPeer.port = val;
				continue;
			}

			std::vector<std::string> rules;
			if (parseStringArray(l, "rules", rules)) {
				currentPeer.ruleStr = rules;
				continue;
			}

			if (l.find("}") != std::string::npos) {
				if (!currentPeer.name.empty() &&
					!currentPeer.host.empty() &&
					currentPeer.port > 0) {
					g_peerCfg.push_back(currentPeer);
				}
				continue;
			}

			if (l.find("]") != std::string::npos) {
				inPeers = false;
				continue;
			}
		}

        if (parseBoolField(l, "weather_enabled", bval)) {
            g_weatherCfg.enabled = bval;
            continue;
        }
        if (parseStringField(l, "weather_host_ip", sval)) {
            g_weatherCfg.weatherHostIp = sval;
            continue;
        }
        if (parseStringField(l, "weather_talkgroup", sval)) {
            g_weatherCfg.talkgroup = sval;
            continue;
        }
        if (parseIntField(l, "weather_interval_sec", val)) {
            g_weatherCfg.intervalSec = val;
            continue;
        }
        if (parseStringField(l, "weather_api_key", sval)) {
            g_weatherCfg.apiKey = sval;
            continue;
        }
        if (parseStringField(l, "weather_lat", sval)) {
            g_weatherCfg.lat = sval;
            continue;
        }
        if (parseStringField(l, "weather_lon", sval)) {
            g_weatherCfg.lon = sval;
            continue;
        }
        if (parseStringField(l, "weather_city_key", sval)) {
            g_weatherCfg.cityKey = sval;
            continue;
        }
    }

    LOG_OK("Loaded config: %zu users, %zu talkgroups\n",g_users.size(),g_knownTalkgroups.size());

    return true;
}

static bool parsePeerRule(const std::string& s, PeerRule& out) {
    size_t eq = s.find('=');
    size_t col = s.find(':');
    if (eq == std::string::npos || col == std::string::npos || eq > col) return false;

    out.localTg  = s.substr(0, eq);
    out.remoteTg = s.substr(eq + 1, col - (eq + 1));
    std::string dir = s.substr(col + 1);

    if (dir == "tx") out.dir = PeerRule::TX;
    else if (dir == "rx") out.dir = PeerRule::RX;
    else out.dir = PeerRule::BOTH;

    return !out.localTg.empty() && !out.remoteTg.empty();
}

static void compilePeerRules() {
    for (auto& pc : g_peerCfg) {
        pc.rules.clear();
        for (const auto& rs : pc.ruleStr) {
            PeerRule r;
            if (parsePeerRule(rs, r)) pc.rules.push_back(r);
        }
    }
}

static std::string makeBridgeId() {
    uint64_t n = ++g_bridgeSeq;
    std::ostringstream oss;
    oss << g_serverName << "-" << (uint64_t)std::time(nullptr) << "-" << n;
    return oss.str();
}

static bool seenBridgeRecently(const std::string& id) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(g_bridgeSeenMutex);

    for (auto it = g_bridgeSeen.begin(); it != g_bridgeSeen.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
        if (age > 15) it = g_bridgeSeen.erase(it);
        else ++it;
    }

    auto it = g_bridgeSeen.find(id);
    if (it != g_bridgeSeen.end()) return true;
    g_bridgeSeen[id] = now;
    return false;
}

static bool peerSendLine(PeerConn* pc, const std::string& line) {
    std::lock_guard<std::mutex> lock(pc->sendMutex);
    return sendAll(pc->sock, line.data(), line.size());
}

static bool peerSendAud(PeerConn* pc,
                        const std::string& bridgeId,
                        int hop,
                        const std::string& remoteTg,
                        const std::vector<char>& pcm)
{
    std::ostringstream oss;
    oss << "PEER_AUD " << bridgeId << " " << hop << " " << remoteTg << " " << pcm.size() << "\n";
    std::string hdr = oss.str();

    std::lock_guard<std::mutex> lock(pc->sendMutex);
    if (!sendAll(pc->sock, hdr.data(), hdr.size())) return false;
    if (!pcm.empty() && !sendAll(pc->sock, pcm.data(), pcm.size())) return false;
    return true;
}


static const PeerConfig* getPeerCfgByName(const std::string& name)
{
    for (const auto& pc : g_peerCfg) {
        if (pc.name == name) return &pc;
    }
    return nullptr;
}

static void peerForwardSpeakerStart(const std::string& localTg,
                                    const std::string& fromUser,
                                    const std::string& bridgeId,
                                    int hop)
{
    std::lock_guard<std::mutex> lock(g_peerMutex);
    for (auto& kv : g_peerConns) {
        PeerConn* pc = kv.second;
        const PeerConfig* cfg = getPeerCfgByName(kv.first);
        if (!pc || !cfg || !pc->running) continue;

        for (const auto& r : cfg->rules) {
            if (r.localTg != localTg) continue;
            if (r.dir == PeerRule::RX) continue;
            std::ostringstream oss;
            oss << "PEER_SPK " << bridgeId << " " << hop << " " << r.remoteTg << " " << fromUser << "\n";
            peerSendLine(pc, oss.str());
        }
    }
}

static void peerForwardSpeakerEnd(const std::string& localTg,
                                  const std::string& bridgeId,
                                  int hop)
{
    std::lock_guard<std::mutex> lock(g_peerMutex);
    for (auto& kv : g_peerConns) {
        PeerConn* pc = kv.second;
        const PeerConfig* cfg = getPeerCfgByName(kv.first);
        if (!pc || !cfg || !pc->running) continue;

        for (const auto& r : cfg->rules) {
            if (r.localTg != localTg) continue;
            if (r.dir == PeerRule::RX) continue;
            std::ostringstream oss;
            oss << "PEER_END " << bridgeId << " " << hop << " " << r.remoteTg << "\n";
            peerSendLine(pc, oss.str());
        }
    }
}

static void peerForwardAudio(const std::string& localTg,
                             const std::vector<char>& pcm,
                             const std::string& bridgeId,
                             int hop)
{
    std::lock_guard<std::mutex> lock(g_peerMutex);
    for (auto& kv : g_peerConns) {
        PeerConn* pc = kv.second;
        const PeerConfig* cfg = getPeerCfgByName(kv.first);
        if (!pc || !cfg || !pc->running) continue;

        for (const auto& r : cfg->rules) {
            if (r.localTg != localTg) continue;
            if (r.dir == PeerRule::RX) continue;
            peerSendAud(pc, bridgeId, hop, r.remoteTg, pcm);
        }
    }
}

static std::string ensureBridgeIdForLocalTx(const std::string& tg)
{
    std::lock_guard<std::mutex> lock(g_bridgeIdMutex);
    auto it = g_activeBridgeIdByTg.find(tg);
    if (it != g_activeBridgeIdByTg.end() && !it->second.empty())
        return it->second;

    std::string id = makeBridgeId();
    g_activeBridgeIdByTg[tg] = id;
    return id;
}

static void clearBridgeIdForLocalTx(const std::string& tg)
{
    std::lock_guard<std::mutex> lock(g_bridgeIdMutex);
    g_activeBridgeIdByTg.erase(tg);
}


static void handlePeerLine(PeerConn* pc, const std::string& line);
static void broadcastToLinkedTalkgroups(const std::string& tg,const std::string& message,SOCKET exceptSock);
static void broadcastAudioToLinkedTalkgroups(const std::string& tg,const std::string& fromUser,const std::vector<char>& buf,SOCKET exceptSock);

static SOCKET connectTcp(const std::string& host, int port)
{
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char portStr[16];
#ifdef _WIN32
    _snprintf_s(portStr, sizeof(portStr), _TRUNCATE, "%d", port);
#else
    std::snprintf(portStr, sizeof(portStr), "%d", port);
#endif

    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), portStr, &hints, &res) != 0 || !res) {
        return INVALID_SOCKET;
    }

    SOCKET s = INVALID_SOCKET;
    for (struct addrinfo* rp = res; rp != nullptr; rp = rp->ai_next) {
#ifdef _WIN32
        SOCKET cs = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (cs == INVALID_SOCKET) continue;
#else
        int cs = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (cs < 0) continue;
#endif

        if (connect(cs, rp->ai_addr, (int)rp->ai_addrlen) == 0) {
            s = cs;
            break;
        }
        closeSocket(cs);
    }

    freeaddrinfo(res);

    if (s != INVALID_SOCKET) {
        int flag = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
    }
    return s;
}


static void peerOutboundThread(PeerConfig cfg)
{
    while (g_running) {
        SOCKET s = connectTcp(cfg.host, cfg.port);
        if (s == INVALID_SOCKET) { std::this_thread::sleep_for(std::chrono::seconds(2)); continue; }

        std::string sec = cfg.secret.empty() ? g_peerSecret : cfg.secret;
        std::ostringstream auth;
        auth << "PEER_AUTH " << g_serverName << " " << sec << "\n";
        if (!sendAll(s, auth.str().c_str(), auth.str().size())) { closeSocket(s); continue; }

        std::string line;
        if (!recvLine(s, line) || line != "PEER_OK") {
            closeSocket(s);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }

        PeerConn* pc = new PeerConn();
        pc->peerName = cfg.name;
        pc->sock = s;
        pc->running = true;

        {
            std::lock_guard<std::mutex> lock(g_peerMutex);
            auto it = g_peerConns.find(cfg.name);
            if (it != g_peerConns.end()) {
                closeSocket(s);
                delete pc;
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }
            g_peerConns[cfg.name] = pc;
        }

        LOG_OK("PEER connected outbound to %s (%s:%d)\n", cfg.name.c_str(), cfg.host.c_str(), cfg.port);

        while (g_running && pc->running) {
            std::string ln;
            if (!recvLine(s, ln)) break;
            handlePeerLine(pc, ln);
        }

        {
            std::lock_guard<std::mutex> lock(g_peerMutex);
            auto it = g_peerConns.find(cfg.name);
            if (it != g_peerConns.end() && it->second == pc) g_peerConns.erase(it);
        }
        closeSocket(s);
        delete pc;

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

static void setTalkgroupSpeakerRemote(const std::string& tg, const std::string& fromUser)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    TalkgroupState& ts = g_talkgroups[tg];
    auto now = std::chrono::steady_clock::now();
    ts.activeSpeaker = fromUser;
    ts.speakStart = now;
    ts.lastAudio  = now;
}

static void clearTalkgroupSpeakerIfMatches(const std::string& tg, const std::string& fromUser)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    TalkgroupState& ts = g_talkgroups[tg];
    if (ts.activeSpeaker == fromUser) ts.activeSpeaker.clear();
}

static bool startsWith(const std::string& s, const std::string& p);

static const size_t MAX_HTTP_REQ_LINE = 2048;
static const size_t MAX_HTTP_REL_PATH = 512;

static const size_t MAX_PEER_AUDIO_BYTES   = 4096 * 4;
static const size_t MAX_CLIENT_AUDIO_BYTES = 4096 * 4;

static inline std::string stripQueryAndFragment(const std::string& p) {
    size_t q = p.find('?');
    size_t h = p.find('#');
    size_t cut = std::min(q == std::string::npos ? p.size() : q,
                          h == std::string::npos ? p.size() : h);
    return p.substr(0, cut);
}

static bool sanitizeHttpRelPath(const std::string& rawPath, std::string& outRel) {
    outRel.clear();

    std::string path = stripQueryAndFragment(rawPath);

    if (path.empty() || path[0] != '/') return false;

    if (path == "/") path = "/index.html";

    std::string rel = path.substr(1);

    if (rel.empty()) rel = "index.html";
    if (rel.size() > MAX_HTTP_REL_PATH) return false;

    if (rel.find('\\') != std::string::npos) return false;
    if (rel.find(':')  != std::string::npos) return false;
    if (rel.find('\0') != std::string::npos) return false;

    if (rel == "..") return false;
    if (rel.size() >= 3 && rel.compare(0, 3, "../") == 0) return false;
    if (rel.size() >= 3 && rel.compare(rel.size() - 3, 3, "/..") == 0) return false;
    if (rel.find("/../") != std::string::npos) return false;

    if (rel.find("//") != std::string::npos) return false;

    outRel = rel;
    return true;
}

static void collectTalkgroupSockets(const std::string& tg,
                                    SOCKET exceptSock,
                                    std::vector<SOCKET>& out)
{
    out.clear();
    std::lock_guard<std::mutex> lock(g_mutex);
    out.reserve(g_clients.size());

    for (const auto& kv : g_clients) {
        SOCKET cs = kv.first;
        if (cs == exceptSock) continue;

        const ClientInfo& ci = kv.second;

        if (!ci.authenticated) continue;

        if (ci.talkgroup == tg) {
            out.push_back(cs);
        }
    }
}

static void handlePeerLine(PeerConn* pc, const std::string& line)
{
    std::istringstream iss(line);
    std::string cmd;
    iss >> cmd;

    if (cmd == "PEER_SPK") {
        std::string bridgeId, tg, from;
        int hop = 0;
        iss >> bridgeId >> hop >> tg >> from;

        if (bridgeId.empty() || tg.empty() || from.empty()) return;
        if (seenBridgeRecently(bridgeId) && hop >= 1) return;

        std::string who = pc->peerName + ":" + from;
        setTalkgroupSpeakerRemote(tg, who);

        std::string sMsg = "SPEAKER " + who + "\n";
        broadcastToLinkedTalkgroups(tg, sMsg, INVALID_SOCKET);

        if (hop < PEER_HOP_MAX) {
            peerForwardSpeakerStart(tg, from, bridgeId, hop + 1);
        }
        return;
    }

	if (cmd == "PEER_AUD") {
		std::string bridgeId, tg;
		int hop = 0;
		size_t bytes = 0;
		iss >> bridgeId >> hop >> tg >> bytes;

		if (bridgeId.empty() || tg.empty() || bytes == 0) return;

		if (bytes > MAX_PEER_AUDIO_BYTES) {
			LOG_WARN("PEER_AUD drop: too large (%zu bytes) from %s\n",
					 bytes, pc ? pc->peerName.c_str() : "peer");
			pc->running = false;
			return;
		}

		if (seenBridgeRecently(bridgeId) && hop > 0) return;

		std::vector<char> pcm(bytes);
		if (!recvAll(pc->sock, pcm.data(), bytes)) {
			pc->running = false;
			return;
		}

		int newHop = hop + 1;
		if (newHop > PEER_HOP_MAX) newHop = PEER_HOP_MAX;

		std::string who;
		{
			std::lock_guard<std::mutex> lock(g_mutex);
			who = g_talkgroups[tg].activeSpeaker;
			if (who.empty()) who = pc->peerName + ":remote";
			g_talkgroups[tg].lastAudio = std::chrono::steady_clock::now();
		}

		broadcastAudioToLinkedTalkgroups(tg, who, pcm, INVALID_SOCKET);

		if (hop < PEER_HOP_MAX) {
			peerForwardAudio(tg, pcm, bridgeId, hop + 1);
		}
		return;
	}

    if (cmd == "PEER_END") {
        std::string bridgeId, tg;
        int hop = 0;
        iss >> bridgeId >> hop >> tg;
        if (bridgeId.empty() || tg.empty()) return;
        if (seenBridgeRecently(bridgeId) && hop > 0) return;

        std::string curSpeaker;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            curSpeaker = g_talkgroups[tg].activeSpeaker;
        }

        const std::string peerPrefix = pc->peerName + ":";
        if (!curSpeaker.empty() && startsWith(curSpeaker, peerPrefix)) {
            clearTalkgroupSpeakerIfMatches(tg, curSpeaker);
        }

        broadcastToLinkedTalkgroups(tg, "MIC_FREE\\n", INVALID_SOCKET);
        broadcastToLinkedTalkgroups(tg, "SPEAKER_NONE\\n", INVALID_SOCKET);

        if (hop < PEER_HOP_MAX) {
            peerForwardSpeakerEnd(tg, bridgeId, hop + 1);
        }
        return;
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

bool loadWavMono16(const std::string& path, std::vector<int16_t>& outPcm, uint32_t& outSampleRate) {
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f.is_open()) {
        LOG_ERROR("Time-announcement WAV open failed: %s\n", path.c_str());
        return false;
    }

    WavHeader h;
    f.read(reinterpret_cast<char*>(&h), sizeof(h));
    if (!f.good()) {
        LOG_ERROR("Failed to read WAV header\n");
        return false;
    }

    if (std::strncmp(h.riff, "RIFF", 4) != 0 ||
        std::strncmp(h.wave, "WAVE", 4) != 0 ||
        std::strncmp(h.fmt,  "fmt ", 4)  != 0 ||
        std::strncmp(h.dataId, "data", 4) != 0) {
        LOG_ERROR("Not a simple PCM WAV\n");
        return false;
    }

    if (h.audioFormat != 1 || h.numChannels != 1 || h.bitsPerSample != 16) {
        LOG_ERROR("WAV must be PCM, mono, 16-bit\n");
        return false;
    }

    outSampleRate = h.sampleRate;
    size_t numSamples = h.dataSize / sizeof(int16_t);
    outPcm.resize(numSamples);
    f.read(reinterpret_cast<char*>(outPcm.data()), h.dataSize);
    if (!f.good()) {
        LOG_ERROR("Failed to read WAV data\n");
        return false;
    }
    return true;
}

bool getWav(const std::string& key, CachedWav& out) {
    std::lock_guard<std::mutex> lock(g_timeCacheMutex);
    std::map<std::string, CachedWav>::iterator it = g_wavCache.find(key);
    if (it != g_wavCache.end()) {
        out = it->second;
        return !out.samples.empty();
    }

#ifdef WIN32
    std::string path = g_timeCfg.folder + "\\" + key + ".wav";
#else
    std::string path = g_timeCfg.folder + "/" + key + ".wav";
#endif
    std::vector<int16_t> pcm;
    uint32_t sr = 0;
    if (!loadWavMono16(path, pcm, sr)) {
        return false;
    }

    CachedWav cw;
    cw.samples = pcm;
    cw.sampleRate = sr;
    g_wavCache[key] = cw;
    out = cw;
    return true;
}

bool getTimeWav(const std::string& key, CachedWav& out) {
    std::lock_guard<std::mutex> lock(g_timeCacheMutex);
    std::map<std::string, CachedWav>::iterator it = g_wavCache.find(key);
    if (it != g_wavCache.end()) {
        out = it->second;
        return !out.samples.empty();
    }

#ifdef WIN32
    std::string path = g_timeCfg.folder + "\\data\\" + key + ".wav";
#else
    std::string path = g_timeCfg.folder + "/data/" + key + ".wav";
#endif
    std::vector<int16_t> pcm;
    uint32_t sr = 0;
    if (!loadWavMono16(path, pcm, sr)) {
        return false;
    }

    CachedWav cw;
    cw.samples = pcm;
    cw.sampleRate = sr;
    g_wavCache[key] = cw;
    out = cw;
    return true;
}

bool getWavForTalkgroup(const std::string& tg,
                             const std::string& key,
                             CachedWav& out)
{
    std::string tgKey = key;

    {
        std::lock_guard<std::mutex> lock(g_timeCacheMutex);
        std::map<std::string, CachedWav>::iterator it = g_wavCache.find(tgKey);
        if (it != g_wavCache.end()) {
            out = it->second;
            return !out.samples.empty();
        }
    }

#ifdef WIN32
    std::string path = g_timeCfg.folder + "\\" + tgKey + ".wav";
#else
    std::string path = g_timeCfg.folder + "/" + tgKey + ".wav";
#endif
    std::vector<int16_t> pcm;
    uint32_t sr = 0;
    if (loadWavMono16(path, pcm, sr)) {
        CachedWav cw;
        cw.samples    = pcm;
        cw.sampleRate = sr;
        {
            std::lock_guard<std::mutex> lock(g_timeCacheMutex);
            g_wavCache[tgKey] = cw;
        }
        out = cw;
        return true;
    }

    return getWav(key, out);
}

bool getTimeWavForTalkgroup(const std::string& tg,
                             const std::string& key,
                             CachedWav& out)
{
    std::string tgKey = key;

    {
        std::lock_guard<std::mutex> lock(g_timeCacheMutex);
        std::map<std::string, CachedWav>::iterator it = g_wavCache.find(tgKey);
        if (it != g_wavCache.end()) {
            out = it->second;
            return !out.samples.empty();
        }
    }

#ifdef WIN32
    std::string path = g_timeCfg.folder + "\\data\\" + tgKey + ".wav";
#else
    std::string path = g_timeCfg.folder + "/data/" + tgKey + ".wav";
#endif
    std::vector<int16_t> pcm;
    uint32_t sr = 0;
    if (loadWavMono16(path, pcm, sr)) {
        CachedWav cw;
        cw.samples    = pcm;
        cw.sampleRate = sr;
        {
            std::lock_guard<std::mutex> lock(g_timeCacheMutex);
            g_wavCache[tgKey] = cw;
        }
        out = cw;
        return true;
    }

    return getTimeWav(key, out);
}

void triggerAnnouncementForTalkgroup(const std::string& tg,
                                     const std::string& key)
{
    if (!g_timeCfg.enabled) return;

    CachedWav dummy;
    if (!getWavForTalkgroup(tg, key, dummy)) {
        LOG_WARN("Announcement WAV not found for tg=%s key=%s\n",tg.c_str(), key.c_str());
        return;
    }

    std::lock_guard<std::mutex> lock(g_announceMutex);
    TalkgroupAnnounceState& st = g_tgAnnounce[tg];
    st.active     = true;
    st.posSamples = 0;
    st.key        = key;
}

void triggerTimeAnnouncementForAllTgs(const std::string& key) {
    if (!g_timeCfg.enabled) return;

    CachedWav dummy;
    if (!getTimeWav(key, dummy)) {
        LOG_WARN("Time announcement WAV not found for key %s\n", key.c_str());
        return;
    }

    std::lock_guard<std::mutex> lock(g_announceMutex);
    std::unordered_map<std::string, TalkgroupState>::iterator it;
    for (it = g_talkgroups.begin(); it != g_talkgroups.end(); ++it) {
        TalkgroupAnnounceState& st = g_tgAnnounce[it->first];
        st.active = true;
        st.posSamples = 0;
        st.key = key;
    }
    LOG_INFO("Time announcement scheduled for all talkgroups: %s.wav\n",key.c_str());
}

void triggerTimeAnnouncementForTalkgroup(const std::string& tg, const std::string& key) {
    if (!g_timeCfg.enabled) return;
    if (tg.empty() || key.empty()) return;

    CachedWav dummy;
    if (!getTimeWav(key, dummy)) {
        std::cerr << "Time announcement WAV not found for key " << key
                  << " (tg=" << tg << ")\n";
        return;
    }

    std::lock_guard<std::mutex> lock(g_announceMutex);
    TalkgroupAnnounceState& st = g_tgAnnounce[tg];
    st.active     = true;
    st.posSamples = 0;
    st.key        = key;
}

void timeAnnounceThreadFunc() {
    std::string lastKey;
    while (g_timeThreadRunning) {
        using namespace std::chrono;
        system_clock::time_point now = system_clock::now();
        std::time_t t = system_clock::to_time_t(now);

        std::tm local_tm;
#ifdef _WIN32
        localtime_s(&local_tm, &t);
#else
        local_tm = *std::localtime(&t);
#endif
        int hour = local_tm.tm_hour;
        int minute = local_tm.tm_min;

        bool onBoundary = (minute == 0 || minute == 30);
        char buf[6];
        std::sprintf(buf, "%02d_%02d", hour, minute);
        std::string key(buf);

        if (g_timeCfg.enabled && onBoundary && key != lastKey) {
            lastKey = key;
            triggerTimeAnnouncementForAllTgs(key);
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void weatherAnnounceThreadFunc() {
    const std::string compositeKey = "weather_auto";

    while (g_weatherThreadRunning && g_running) {
        if (g_weatherCfg.enabled &&
            !g_weatherCfg.talkgroup.empty()) {

            WeatherData wd;
            if (fetchWeatherFromOpenWeather(wd)) {
                auto keys = buildWeatherSegmentKeys(wd);
                CachedWav dummy;
                if (buildCompositeWav(keys, compositeKey, dummy)) {
                    triggerTimeAnnouncementForTalkgroup(
                        g_weatherCfg.talkgroup,
                        compositeKey
                    );
                    LOG_INFO("Weather announcement scheduled for TG %s\n",g_weatherCfg.talkgroup.c_str());
                } else {
                    LOG_WARN("Failed to build composite weather WAV.\n");
                }
            } else {
                LOG_WARN("Failed to fetch weather data.\n");
            }
        }

        int interval = g_weatherCfg.intervalSec;
        if (interval <= 0) interval = 600;

        for (int i = 0; i < interval && g_weatherThreadRunning && g_running; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

bool isRxOnlyTalkgroup(const std::string& tg) {
    if (g_weatherCfg.enabled && !g_weatherCfg.talkgroup.empty()) {
        if (tg == g_weatherCfg.talkgroup) return true;
    }
    return false;
}


static inline std::string baseCallsignFromSpeaker(const std::string& spk)
{
    size_t p = spk.rfind(':');
    if (p == std::string::npos) return spk;
    return spk.substr(p + 1);
}

static inline int computeUserRank(const std::string& callsign)
{
    auto it = g_users.find(callsign);
    if (it == g_users.end()) return 0;
    const User& u = it->second;
    return (int)u.role * 1000 + u.priority;
}

static inline bool userCanSpeakNow(const std::string& callsign, const std::string& tg, std::string& denyReason)
{
    denyReason.clear();

    auto uit = g_users.find(callsign);
    if (uit == g_users.end()) { denyReason = "unknown_user"; return false; }

    if (uit->second.banned) { denyReason = "banned"; return false; }
    if (uit->second.muted)  { denyReason = "muted";  return false; }

    if (tg.empty()) { denyReason = "no_tg"; return false; }
    if (isRxOnlyTalkgroup(tg)) { denyReason = "rx_only_tg"; return false; }

    if (uit->second.talkgroups.find(tg) == uit->second.talkgroups.end()) {
        denyReason = "not_in_talkgroup";
        return false;
    }

    return true;
}

static size_t curlWriteCb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    std::string* s = reinterpret_cast<std::string*>(userp);
    s->append(reinterpret_cast<const char*>(contents), total);
    return total;
}

static bool extractJsonString(const std::string& json, const std::string& key, std::string& out) {
    std::string token = "\"" + key + "\"";
    size_t pos = json.find(token);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return false;
    pos = json.find('"', pos);
    if (pos == std::string::npos) return false;
    size_t end = json.find('"', pos + 1);
    if (end == std::string::npos) return false;
    out = json.substr(pos + 1, end - (pos + 1));
    return true;
}

static bool extractJsonNumber(const std::string& json, const std::string& key, double& out) {
    std::string token = "\"" + key + "\"";
    size_t pos = json.find(token);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return false;
    size_t start = json.find_first_of("0123456789-+", pos);
    if (start == std::string::npos) return false;
    size_t end = start;
    while (end < json.size() && (std::isdigit(json[end]) || json[end]=='.' || json[end]=='-')) end++;
    try {
        out = std::stod(json.substr(start, end - start));
    } catch (...) {
        return false;
    }
    return true;
}

static std::string mapIconToWeatherInfo(const std::string& icon) {
    if (icon == "01d") return "clear";
    if (icon == "01n") return "cloudy";
    if (icon == "02d" || icon == "02n") return "cloudy";
    if (icon == "03d" || icon == "03n") return "cloudy";
    if (icon == "04d" || icon == "04n") return "cloudy";
    if (icon == "09d" || icon == "09n") return "stormy";
    if (icon == "10d" || icon == "10n") return "rainy";
    if (icon == "11d" || icon == "11n") return "thundery";
    if (icon == "13d" || icon == "13n") return "snow";
    if (icon == "50d" || icon == "50n") return "foggy";
    return "error";
}

bool fetchWeatherFromOpenWeather(WeatherData& out) {
    if (g_weatherCfg.apiKey.empty() ||
        g_weatherCfg.lat.empty() ||
        g_weatherCfg.lon.empty() ||
        g_weatherCfg.weatherHostIp.empty()) {
        return false;
    }

    std::ostringstream path;
    path << "/data/2.5/weather"
         << "?lat=" << g_weatherCfg.lat
         << "&lon=" << g_weatherCfg.lon
         << "&appid=" << g_weatherCfg.apiKey
         << "&units=metric";

    std::string resp;
    if (!httpGet(g_weatherCfg.weatherHostIp, path.str(), resp)) {
        LOG_WARN("Weather GET failed\n");
        return false;
    }

    size_t pos = resp.find("\r\n\r\n");
    if (pos == std::string::npos) return false;
    std::string json = resp.substr(pos + 4);

    std::string icon;
    if (!extractJsonString(json, "icon", icon)) return false;

    double tempD;
    if (!extractJsonNumber(json, "temp", tempD)) return false;

    out.iconCode = icon;
    out.tempC = static_cast<int>(round(tempD));
    return true;
}

bool buildCompositeWav(const std::vector<std::string>& keys,
                       const std::string& compositeKey,
                       CachedWav& out)
{
    std::vector<int16_t> all;
    uint32_t sampleRate = 0;

    for (const std::string& k : keys) {
        CachedWav seg;
        if (!getTimeWav(k, seg)) {
            LOG_WARN("Segment WAV not found for key %s\n", k.c_str());
            continue;
        }
        if (sampleRate == 0) {
            sampleRate = seg.sampleRate;
        } else if (sampleRate != seg.sampleRate) {
            LOG_WARN("Sample rate mismatch for key %s\n", k.c_str());
            continue;
        }
        all.insert(all.end(), seg.samples.begin(), seg.samples.end());
    }

    if (all.empty() || sampleRate == 0) {
        return false;
    }

    CachedWav cw;
    cw.samples    = std::move(all);
    cw.sampleRate = sampleRate;

    {
        std::lock_guard<std::mutex> lock(g_timeCacheMutex);
        g_wavCache[compositeKey] = cw;
    }
    out = cw;
    return true;
}

std::vector<std::string> buildWeatherSegmentKeys(const WeatherData& wd) {
    std::time_t t = std::time(nullptr);
    std::tm local_tm;
#ifdef _WIN32
    localtime_s(&local_tm, &t);
#else
    local_tm = *std::localtime(&t);
#endif

    char monthName[64];
    std::strftime(monthName, sizeof(monthName), "%B", &local_tm);
    char dayCount[4];
    std::strftime(dayCount, sizeof(dayCount), "%d", &local_tm);

    std::string weatherInfo = mapIconToWeatherInfo(wd.iconCode);

    std::string tempPrefix;
    if (wd.tempC <= 0) tempPrefix = "m";
    std::string tempNum = std::to_string(std::abs(wd.tempC));

    std::vector<std::string> keys;

    keys.push_back("date/info");
    keys.push_back(std::string("date/") + dayCount);
    keys.push_back(std::string("date/month/") + monthName);
    keys.push_back("weather/info");
    if (!g_weatherCfg.cityKey.empty()) {
        keys.push_back(std::string("city/") + g_weatherCfg.cityKey);
    }
    keys.push_back(std::string("weather/") + weatherInfo);
    keys.push_back("weather/info_temp");
    keys.push_back(std::string("weather/temp/") + tempPrefix + tempNum);

    return keys;
}

void broadcastToTalkgroup(const std::string& tg,
                          const std::string& message,
                          SOCKET exceptSock = INVALID_SOCKET)
{
    std::vector<std::pair<SOCKET, std::shared_ptr<ClientTxState>>> targets;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        targets.reserve(g_clients.size());

        for (const auto& kv : g_clients) {
            SOCKET cs = kv.first;
            if (cs == exceptSock) continue;

            const ClientInfo& ci = kv.second;
            if (!ci.authenticated) continue;
            if (ci.talkgroup != tg) continue;

            targets.emplace_back(cs, ci.tx);
        }
    }

    for (auto& t : targets) {
        SOCKET cs = t.first;
        auto& tx = t.second;
        if (!enqueueStrToTx(tx, message, false)) {
            shutdownSocket(cs);
        }
    }
}

void mixTimeAnnouncementIntoBuffer(const std::string& tg, std::vector<char>& buf) {
    if (!g_timeCfg.enabled) return;

    TalkgroupAnnounceState local;
    {
        std::lock_guard<std::mutex> lock(g_announceMutex);
        std::unordered_map<std::string, TalkgroupAnnounceState>::iterator it = g_tgAnnounce.find(tg);
        if (it == g_tgAnnounce.end() || !it->second.active || it->second.key.empty())
            return;
        local = it->second;
    }

    CachedWav wav;
    if (!getTimeWavForTalkgroup(tg, local.key, wav)) {
        std::lock_guard<std::mutex> lock(g_announceMutex);
        TalkgroupAnnounceState& shared = g_tgAnnounce[tg];
        shared.active = false;
        shared.posSamples = 0;
        shared.key.clear();
        return;
    }

    size_t numSamples = buf.size() / sizeof(int16_t);
    int16_t* samples = reinterpret_cast<int16_t*>(buf.data());
    float vol = g_timeCfg.volumeFactor;
    size_t pos = local.posSamples;

    for (size_t i = 0; i < numSamples; ++i) {
        int16_t user = samples[i];
        int16_t ann = 0;
        if (pos < wav.samples.size()) {
            ann = wav.samples[pos++];
        }
        int mixed = (int)user + (int)(ann * vol);
        if (mixed > 32767) mixed = 32767;
        if (mixed < -32768) mixed = -32768;
        samples[i] = (int16_t)mixed;
    }

	bool finished = (pos >= wav.samples.size());

    {
        std::lock_guard<std::mutex> lock(g_announceMutex);
        TalkgroupAnnounceState& shared = g_tgAnnounce[tg];
        if (finished) {
            shared.active     = false;
            shared.posSamples = 0;
            shared.key.clear();
        } else {
            shared.posSamples = pos;
            shared.key        = local.key;
        }
    }

    if (finished) {
        std::string msg1 = "MIC_FREE\n";
		broadcastToLinkedTalkgroups(tg, msg1, INVALID_SOCKET);

        std::string msg2 = "SPEAKER_NONE\n";
		broadcastToLinkedTalkgroups(tg, msg2, INVALID_SOCKET);
    }
}

static std::string escapeJson(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out.push_back(c); break;
        }
    }
    return out;
}

static bool saveConfig(const std::string& path)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    std::ofstream f(path.c_str());
    if (!f.is_open()) {
        LOG_ERROR("Failed to open config file for writing: %s\n", path.c_str());
        return false;
    }

    f << "{\n";
    f << "  \"server_name\": \"" << escapeJson(g_serverName) << "\",\n";
    f << "  \"peer_secret\": \"" << escapeJson(g_peerSecret) << "\",\n";
    f << "  \"server_port\": " << g_server_port << ",\n";
    f << "  \"max_talk_ms\": " << g_max_talk_ms << ",\n";
    f << "  \"http_root\": \"" << escapeJson(g_http_root) << "\",\n";
    f << "  \"http_port\": " << g_http_port << ",\n";

    f << "  \"https_port\": " << g_https_port << ",\n";
    f << "  \"https_cert_file\": \"" << escapeJson(g_https_cert_file) << "\",\n";
    f << "  \"https_key_file\": \"" << escapeJson(g_https_key_file) << "\",\n";

    f << "  \"time_announcement\": {\n";
    f << "    \"enabled\": " << (g_timeCfg.enabled ? "true" : "false") << ",\n";
    f << "    \"folder\": \"" << escapeJson(g_timeCfg.folder) << "\",\n";
    f << "    \"volume_factor\": " << g_timeCfg.volumeFactor << "\n";
    f << "  },\n";

    f << "  \"weather_enabled\": " << (g_weatherCfg.enabled ? "true" : "false") << ",\n";
    f << "  \"weather_host_ip\": \"" << escapeJson(g_weatherCfg.weatherHostIp) << "\",\n";
    f << "  \"weather_talkgroup\": \"" << escapeJson(g_weatherCfg.talkgroup) << "\",\n";
    f << "  \"weather_interval_sec\": " << g_weatherCfg.intervalSec << ",\n";
    f << "  \"weather_api_key\": \"" << escapeJson(g_weatherCfg.apiKey) << "\",\n";
    f << "  \"weather_lat\": \"" << escapeJson(g_weatherCfg.lat) << "\",\n";
    f << "  \"weather_lon\": \"" << escapeJson(g_weatherCfg.lon) << "\",\n";
    f << "  \"weather_city_key\": \"" << escapeJson(g_weatherCfg.cityKey) << "\",\n";

    f << "  \"users\": [\n";
    {
        bool firstUser = true;
        for (const auto& kv : g_users) {
            const User& u = kv.second;
            if (!firstUser) f << ",\n";
            firstUser = false;

            f << "    {\n";
            f << "      \"callsign\": \"" << escapeJson(u.callsign) << "\",\n";
            f << "      \"password\": \"" << escapeJson(u.password) << "\",\n";
			f << "      \"role\": \"" << roleToStr(u.role) << "\",\n";
            f << "      \"banned\": " << (u.banned ? "true" : "false") << ",\n";
			f << "      \"priority\": " << u.priority << ",\n";

			if (!u.permissions.empty()) {
				f << "      \"permissions\": [";
				bool firstP = true;
				for (const auto& p : u.permissions) {
					if (!firstP) f << ", ";
					firstP = false;
					f << "\"" << escapeJson(p) << "\"";
				}
				f << "],\n";
			}

            f << "      \"talkgroups\": [";
            bool firstTg = true;
            for (const auto& tg : u.talkgroups) {
                if (!firstTg) f << ", ";
                firstTg = false;
                f << "\"" << escapeJson(tg) << "\"";
            }
            f << "]\n";
            f << "    }";
        }
        f << "\n  ],\n";
    }

    f << "  \"talkgroups\": [\n";
    {
        bool firstTg = true;
		for (const auto& kv : g_knownTalkgroups) {
			const TalkgroupInfo& tg = kv.second;

			if (!firstTg) f << ",\n";
			firstTg = false;

			f << "    { \"name\": \"" << escapeJson(tg.name) << "\"";

			if (tg.mode == TalkgroupMode::HIDE)
				f << ", \"mode\": \"hide\"";
			else if (tg.mode == TalkgroupMode::ADMIN)
				f << ", \"mode\": \"admin\"";

			f << " }";
		}
        f << "\n  ],\n";
    }

    f << "  \"bridges\": {\n";
    {
        bool firstB = true;
        for (const auto& kv : g_linkedTalkgroups) {
            if (!firstB) f << ",\n";
            firstB = false;
            f << "    \"" << escapeJson(kv.first) << "\": [";
            for (size_t i = 0; i < kv.second.size(); ++i) {
                if (i) f << ", ";
                f << "\"" << escapeJson(kv.second[i]) << "\"";
            }
            f << "]";
        }
        f << "\n  },\n";
    }

    f << "  \"peers\": [\n";
    {
        bool firstP = true;
        std::lock_guard<std::mutex> plock(g_peerMutex);
        for (const auto& pc : g_peerCfg) {
            if (!firstP) f << ",\n";
            firstP = false;
            f << "    {\n";
            f << "      \"name\": \"" << escapeJson(pc.name) << "\",\n";
            f << "      \"host\": \"" << escapeJson(pc.host) << "\",\n";
            f << "      \"port\": " << pc.port << ",\n";
            if (!pc.secret.empty())
                f << "      \"secret\": \"" << escapeJson(pc.secret) << "\",\n";
            f << "      \"rules\": [";
            for (size_t i = 0; i < pc.ruleStr.size(); ++i) {
                if (i) f << ", ";
                f << "\"" << escapeJson(pc.ruleStr[i]) << "\"";
            }
            f << "]\n";
            f << "    }";
        }
        f << "\n  ]\n";
    }

    f << "}\n";

    LOG_OK("Saved server config to %s\n", path.c_str());
    return true;
}

static std::string getMimeType(const std::string& path) {
    size_t dot = path.find_last_of('.');
    if (dot == std::string::npos) return "text/plain";
    std::string ext = path.substr(dot + 1);
    if (ext == "html" || ext == "htm") return "text/html; charset=utf-8";
    if (ext == "css")  return "text/css; charset=utf-8";
    if (ext == "js")   return "application/javascript; charset=utf-8";
    if (ext == "json") return "application/json; charset=utf-8";
    if (ext == "png")  return "image/png";
    if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
    if (ext == "ico")  return "image/x-icon";
    return "application/octet-stream";
}

static bool loadFileToString(const std::string& fullPath, std::string& outData) {
    std::ifstream f(fullPath.c_str(), std::ios::binary);
    if (!f.is_open()) return false;
    f.seekg(0, std::ios::end);
    std::streamoff size = f.tellg();
    f.seekg(0, std::ios::beg);
    if (size <= 0) {
        outData.clear();
        return true;
    }
    outData.resize((size_t)size);
    f.read(&outData[0], size);
    return true;
}

static std::string formatTimeLocal(std::chrono::system_clock::time_point tp)
{
    std::time_t tt = std::chrono::system_clock::to_time_t(tp);
    char buf[64];

#ifdef _WIN32
    tm tmb;
    localtime_s(&tmb, &tt);
    std::strftime(buf, sizeof(buf), "%d.%m.%Y / %H:%M:%S", &tmb);
#else
    tm tmb;
    localtime_r(&tt, &tmb);
    std::strftime(buf, sizeof(buf), "%d.%m.%Y / %H:%M:%S", &tmb);
#endif

    return std::string(buf);
}

static void updateLastHeard(const std::string& user, const std::string& tg)
{
    if (user.empty() || tg.empty())
        return;

    using namespace std::chrono;
    auto now = system_clock::now();

    std::lock_guard<std::mutex> lock(g_lastHeardMutex);
    LastHeardInfo &info = g_lastHeard[user];
    info.talkgroup = tg;
    info.when      = now;
}

static bool showOnPublicDashboard(const std::string& tgName)
{
    auto it = g_knownTalkgroups.find(tgName);
    if (it == g_knownTalkgroups.end())
        return true;

    const TalkgroupInfo& tg = it->second;

    return (tg.mode == TalkgroupMode::PUBLIC);
}

static std::string buildStatusJson() {
    using namespace std::chrono;

    auto nowSys    = system_clock::now();
    auto nowSteady = steady_clock::now();

    std::time_t tt = system_clock::to_time_t(nowSys);
    char timebuf[64];
#ifdef _WIN32
    tm tmb;
    localtime_s(&tmb, &tt);
    std::strftime(timebuf, sizeof(timebuf), "%d.%m.%Y / %H:%M:%S", &tmb);
#else
    tm tmb;
    localtime_r(&tt, &tmb);
    std::strftime(timebuf, sizeof(timebuf), "%d.%m.%Y / %H:%M:%S", &tmb);
#endif

    int clientCount = 0;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        clientCount = (int)g_clients.size();
    }

    std::map<std::string, float> tgLevels;
    {
        std::lock_guard<std::mutex> lock(g_audioBufMutex);
        for (const auto &kv : g_tgWaveHistory) {
            const std::string &tgName = kv.first;
            const std::vector<int16_t> &wave = kv.second;
            if (wave.empty()) {
                tgLevels[tgName] = 0.0f;
                continue;
            }
            double sumSq = 0.0;
            for (size_t i = 0; i < wave.size(); ++i) {
                double v = wave[i] / 32768.0;
                sumSq += v * v;
            }
            double rms = 0.0;
            if (!wave.empty()) {
                rms = std::sqrt(sumSq / wave.size());
            }
            if (rms < 0.0) rms = 0.0;
            if (rms > 1.0) rms = 1.0;
            tgLevels[tgName] = static_cast<float>(rms);
        }
    }

    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"server_time_iso\": \"" << timebuf << "\",\n";

    if (g_weatherCfg.enabled && !g_weatherCfg.talkgroup.empty()) {
        oss << "  \"weather_talkgroup\": \"" << g_weatherCfg.talkgroup << "\",\n";
        oss << "  \"weather_rx_only\": true,\n";
    }

    oss << "  \"connected_clients\": " << clientCount << ",\n";

    oss << "  \"peers\": [\n";
    {
        std::lock_guard<std::mutex> lock(g_peerMutex);
        bool firstP = true;

        for (size_t i = 0; i < g_peerCfg.size(); ++i) {
            const PeerConfig& pc = g_peerCfg[i];

            bool connected = false;
            auto it = g_peerConns.find(pc.name);
            if (it != g_peerConns.end() && it->second) {
                PeerConn* c = it->second;
                connected = (c->sock != INVALID_SOCKET) && c->running.load();
            }

            if (!firstP) oss << ",\n";
            firstP = false;

            oss << "    {"
                << "\"name\":\"" << escapeJson(pc.name) << "\","
                << "\"host\":\"" << escapeJson(pc.host) << "\","
                << "\"port\":" << pc.port << ","
                << "\"connected\":" << (connected ? "true" : "false") << ","
                << "\"rules\":[";

            for (size_t r = 0; r < pc.ruleStr.size(); ++r) {
                if (r) oss << ",";
                oss << "\"" << escapeJson(pc.ruleStr[r]) << "\"";
            }

            oss << "]"
                << "}";
        }
    }
    oss << "\n  ],\n";

	oss << "  \"talkgroups\": [\n";
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		bool firstTg = true;
		for (const auto& kv : g_talkgroups) {
			const std::string& tgName = kv.first;
			const TalkgroupState& ts  = kv.second;

			if (!showOnPublicDashboard(tgName))
				continue;

			std::string activeSpeaker = ts.activeSpeaker;
			long long speakMs = 0;
			if (!activeSpeaker.empty() && clientIsSpeaking(ts)) {
				auto dur = nowSteady - ts.speakStart;
				speakMs  = duration_cast<std::chrono::milliseconds>(dur).count();
			} else {
				activeSpeaker.clear();
			}

			int listeners = 0;
			for (const auto& ck : g_clients) {
				const ClientInfo& ci = ck.second;
				if (!ci.authenticated) continue;
				if (ci.talkgroup == tgName) {
					++listeners;
				}
			}

			if (!firstTg) oss << ",\n";
			firstTg = false;

            std::string outName = ts.name.empty() ? tgName : ts.name;

            float audioLevel = 0.0f;
            {
                auto itLvl = tgLevels.find(tgName);
                if (itLvl != tgLevels.end())
                    audioLevel = itLvl->second;
            }

			std::vector<std::string> fanout = getLinkedFanout(tgName);
            fanout.erase(
				std::remove_if(
					fanout.begin(),
					fanout.end(),
					[](const std::string& name) {
						return !showOnPublicDashboard(name);
					}
				),
				fanout.end()
			);

            float activity = 0.0f;
            if (ts.lastAudio.time_since_epoch().count() != 0) {
                long long msSince =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        nowSteady - ts.lastAudio).count();
                const float windowMs = 30000.0f;
                if (msSince < windowMs) {
                    activity = 1.0f - static_cast<float>(msSince) / windowMs;
                    if (activity < 0.0f) activity = 0.0f;
                }
            }
			float speakActivity = 0.0f;
			if (speakMs > 0) {
				speakActivity = (float)speakMs / 30000.0f;
				if (speakActivity > 1.0f) speakActivity = 1.0f;
			}

            oss << "    {"
                << "\"name\":\""           << escapeJson(outName)       << "\","
                << "\"active_speaker\":\"" << escapeJson(activeSpeaker) << "\","
                << "\"speak_ms\":"         << speakMs                   << ","
                << "\"listeners\":"        << listeners                 << ","
                << "\"audio_level\":"      << audioLevel                << ","
                << "\"activity_score\":"   << activity                  << ","
                << "\"linked\":[";
            for (size_t i = 0; i < fanout.size(); ++i) {
                if (i) oss << ",";
                oss << "\"" << escapeJson(fanout[i]) << "\"";
            }
            oss << "]}";
		}
	}
    oss << "\n  ],\n";

	oss << "  \"entries\": [\n";
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		bool first = true;
		for (const auto& kv : g_clients) {
			const ClientInfo& ci = kv.second;
			if (!ci.authenticated) continue;

			if (!ci.talkgroup.empty() && !showOnPublicDashboard(ci.talkgroup))
				continue;

			bool       speaking = false;
			long long  speakMs  = 0;

			if (!ci.talkgroup.empty()) {
				auto tgIt = g_talkgroups.find(ci.talkgroup);
				if (tgIt != g_talkgroups.end()) {
					const TalkgroupState& ts = tgIt->second;

					if (ts.activeSpeaker == ci.callsign && clientIsSpeaking(ts)) {
						speaking = true;
						speakMs =
							std::chrono::duration_cast<std::chrono::milliseconds>(
								std::chrono::steady_clock::now() - ts.speakStart).count();
					}
				}
			}

            float entryLevel = 0.0f;
            if (speaking && !ci.talkgroup.empty()) {
                auto itLvl = tgLevels.find(ci.talkgroup);
                if (itLvl != tgLevels.end())
                    entryLevel = itLvl->second;
            }

            if (!first) oss << ",\n";
            first = false;

            oss << "    {"
                << "\"callsign\":\""  << escapeJson(ci.callsign)    << "\","
                << "\"talkgroup\":\"" << escapeJson(ci.talkgroup)   << "\","
                << "\"ip\":\""        << escapeJson(ci.remoteAddr)  << "\","
                << "\"speaking\":"    << (speaking ? "true" : "false") << ","
                << "\"speak_ms\":"    << speakMs                    << ","
                << "\"audio_level\":" << entryLevel
                << "}";
		}
	}
	oss << "\n  ]\n";

    {
        std::lock_guard<std::mutex> lhLock(g_lastHeardMutex);
        if (!g_lastHeard.empty()) {
            oss << ",\n  \"last_heard\": [\n";
            bool first = true;

            auto nowSysLocal = std::chrono::system_clock::now();

            for (const auto &kv : g_lastHeard) {
                const std::string &cs       = kv.first;
                const LastHeardInfo &info   = kv.second;

                if (!first) oss << ",\n";
                first = false;

                std::string tstr = formatTimeLocal(info.when);

                using namespace std::chrono;
                long long ageSec =
                    duration_cast<seconds>(nowSysLocal - info.when).count();
                if (ageSec < 0) ageSec = 0;

                oss << "    {"
                    << "\"callsign\":\""   << escapeJson(cs)              << "\","
                    << "\"talkgroup\":\""  << escapeJson(info.talkgroup)  << "\","
                    << "\"last_heard\":\"" << escapeJson(tstr)            << "\","
                    << "\"age_sec\":"      << ageSec
                    << "}";
            }
            oss << "\n  ]";
        }
    }

    oss << "\n}\n";
    return oss.str();
}

static void sendHttpResponse(SOCKET s,
                             const std::string& statusLine,
                             const std::string& contentType,
                             const std::string& body)
{
    std::ostringstream oss;
    oss << statusLine << "\r\n";
    if (!contentType.empty()) {
        oss << "Content-Type: " << contentType << "\r\n";
    }
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: close\r\n";
    oss << "Cache-Control: no-cache\r\n";
    oss << "\r\n";

    std::string header = oss.str();
    sendAll(s, header.data(), header.size());
    if (!body.empty()) {
        sendAll(s, body.data(), body.size());
    }
}

static void sendHttpResponseEx(SOCKET s,
                               const std::string& statusLine,
                               const std::string& contentType,
                               const std::vector<std::pair<std::string,std::string>>& extraHeaders,
                               const std::string& body)
{
    std::ostringstream oss;
    oss << statusLine << "\r\n";
    if (!contentType.empty()) {
        oss << "Content-Type: " << contentType << "\r\n";
    }
    for (const auto& kv : extraHeaders) {
        if (!kv.first.empty()) oss << kv.first << ": " << kv.second << "\r\n";
    }
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: close\r\n";
    oss << "Cache-Control: no-cache\r\n";
    oss << "\r\n";

    std::string header = oss.str();
    sendAll(s, header.data(), header.size());
    if (!body.empty()) sendAll(s, body.data(), body.size());
}

static const size_t MAX_HTTP_LINE = 4096;
static const size_t MAX_HTTP_PATH = 512;

static bool readHttpLine(SOCKET s, std::string& out) {
    out.clear();
    out.reserve(256);

    char c = 0;
    while (true) {
        int r = recv(s, &c, 1, 0);
        if (r <= 0) return false;

        if (c == '\n') break;
        if (c != '\r') {
            if (out.size() >= MAX_HTTP_LINE) return false;
            out.push_back(c);
        }
    }
    return true;
}

static bool isSafeRelPath(const std::string& rel) {
    if (rel.empty()) return true;
    if (rel.size() > MAX_HTTP_PATH) return false;
    if (rel.find('\\') != std::string::npos) return false;
    if (rel.find(':')  != std::string::npos) return false;
    if (rel.find('\0') != std::string::npos) return false;
    if (rel == "..") return false;
    if (rel.rfind("../", 0) == 0) return false;
    if (rel.size() >= 3 && rel.compare(rel.size()-3, 3, "/..") == 0) return false;
    if (rel.find("/../") != std::string::npos) return false;
    return true;
}

struct HttpSession {
    std::string token;
    std::string callsign;
    Role role;
    std::unordered_set<std::string> permissions;
    std::chrono::steady_clock::time_point expires;
};

static std::mutex g_httpSessMutex;
static std::unordered_map<std::string, HttpSession> g_httpSessions;

static std::string makeRandomToken(size_t nbytes = 24) {
    static const char* hexd = "0123456789abcdef";
    std::string out;
    out.reserve(nbytes * 2);
    std::random_device rd;
    for (size_t i = 0; i < nbytes; ++i) {
        unsigned char b = (unsigned char)(rd() & 0xFF);
        out.push_back(hexd[(b >> 4) & 0xF]);
        out.push_back(hexd[b & 0xF]);
    }
    return out;
}

static void purgeExpiredSessionsNoLock() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = g_httpSessions.begin(); it != g_httpSessions.end(); ) {
        if (it->second.expires <= now) it = g_httpSessions.erase(it);
        else ++it;
    }
}

static bool extractBearer(const std::unordered_map<std::string,std::string>& hdr,
                          std::string& tokenOut)
{
    tokenOut.clear();
    auto it = hdr.find("authorization");
    if (it == hdr.end()) return false;
    std::string v = it->second;
    v = trim(v);
    const std::string pfx = "Bearer ";
    if (v.size() <= pfx.size()) return false;
    if (v.compare(0, pfx.size(), pfx) != 0) return false;
    tokenOut = trim(v.substr(pfx.size()));
    return !tokenOut.empty();
}

static bool getSessionFromHeaders(const std::unordered_map<std::string,std::string>& hdr,
                                  HttpSession& out)
{
    std::string tok;
    if (!extractBearer(hdr, tok)) return false;
    std::lock_guard<std::mutex> lk(g_httpSessMutex);
    purgeExpiredSessionsNoLock();
    auto it = g_httpSessions.find(tok);
    if (it == g_httpSessions.end()) return false;
    out = it->second;
    it->second.expires = std::chrono::steady_clock::now() + std::chrono::minutes(30);
    return true;
}

static bool sessionHasPerm(const HttpSession& s, const std::string& perm) {
    if (s.role == Role::ADMIN) return true;
    if (perm.empty()) return false;

    if (s.role == Role::OPERATOR && s.permissions.empty() && perm == "config.read") return true;

    if (s.permissions.find(perm) != s.permissions.end()) return true;

    if (perm.size() > 6 && perm.compare(perm.size()-6, 6, ".write") == 0) {
        if (s.permissions.find("config.write") != s.permissions.end()) return true;
    }
    if (s.permissions.find("config.*") != s.permissions.end()) return true;
    return false;
}

static bool jsonFindString(const std::string& json, const std::string& key, std::string& out) {
    out.clear();
    std::string pat = "\"" + key + "\"";
    size_t p = json.find(pat);
    if (p == std::string::npos) return false;
    p = json.find(':', p + pat.size());
    if (p == std::string::npos) return false;
    p = json.find('"', p);
    if (p == std::string::npos) return false;
    size_t e = json.find('"', p + 1);
    if (e == std::string::npos) return false;
    out = json.substr(p + 1, e - (p + 1));
    return true;
}

static bool jsonFindBool(const std::string& json, const std::string& key, bool& out) {
    std::string pat = "\"" + key + "\"";
    size_t p = json.find(pat);
    if (p == std::string::npos) return false;
    p = json.find(':', p + pat.size());
    if (p == std::string::npos) return false;
    size_t t = json.find_first_not_of(" \t\r\n", p + 1);
    if (t == std::string::npos) return false;
    if (json.compare(t, 4, "true") == 0) { out = true; return true; }
    if (json.compare(t, 5, "false") == 0) { out = false; return true; }
    return false;
}

static bool jsonFindInt(const std::string& json, const std::string& key, int& out) {
    std::string pat = "\"" + key + "\"";
    size_t p = json.find(pat);
    if (p == std::string::npos) return false;
    p = json.find(':', p + pat.size());
    if (p == std::string::npos) return false;
    size_t t = json.find_first_of("-0123456789", p + 1);
    if (t == std::string::npos) return false;
    size_t e = t;
    while (e < json.size() && (json[e] == '-' || std::isdigit((unsigned char)json[e]))) ++e;
    try {
        out = std::stoi(json.substr(t, e - t));
        return true;
    } catch (...) { return false; }
}

static bool jsonFindStringArray(const std::string& json, const std::string& key, std::vector<std::string>& out) {
    out.clear();
    std::string pat = "\"" + key + "\"";
    size_t p = json.find(pat);
    if (p == std::string::npos) return false;
    p = json.find('[', p + pat.size());
    if (p == std::string::npos) return false;
    size_t e = json.find(']', p);
    if (e == std::string::npos) return false;
    std::string inside = json.substr(p + 1, e - (p + 1));
    size_t pos = 0;
    while (true) {
        size_t q1 = inside.find('"', pos);
        if (q1 == std::string::npos) break;
        size_t q2 = inside.find('"', q1 + 1);
        if (q2 == std::string::npos) break;
        out.push_back(inside.substr(q1 + 1, q2 - (q1 + 1)));
        pos = q2 + 1;
    }
    return true;
}

static std::string buildAdminConfigJson()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"server_name\": \"" << escapeJson(g_serverName) << "\",\n";
    oss << "  \"peer_secret\": \"" << escapeJson(g_peerSecret) << "\",\n";
    oss << "  \"server_port\": " << g_server_port << ",\n";
    oss << "  \"max_talk_ms\": " << g_max_talk_ms << ",\n";
    oss << "  \"http_root\": \"" << escapeJson(g_http_root) << "\",\n";
    oss << "  \"http_port\": " << g_http_port << ",\n";
    oss << "  \"https_port\": " << g_https_port << ",\n";
    oss << "  \"https_cert_file\": \"" << escapeJson(g_https_cert_file) << "\",\n";
    oss << "  \"https_key_file\": \"" << escapeJson(g_https_key_file) << "\",\n";

    oss << "  \"time_announcement\": {\n";
    oss << "    \"enabled\": " << (g_timeCfg.enabled ? "true" : "false") << ",\n";
    oss << "    \"folder\": \"" << escapeJson(g_timeCfg.folder) << "\",\n";
    oss << "    \"volume_factor\": " << g_timeCfg.volumeFactor << "\n";
    oss << "  },\n";

    oss << "  \"weather\": {\n";
    oss << "    \"enabled\": " << (g_weatherCfg.enabled ? "true" : "false") << ",\n";
    oss << "    \"weather_host_ip\": \"" << escapeJson(g_weatherCfg.weatherHostIp) << "\",\n";
    oss << "    \"talkgroup\": \"" << escapeJson(g_weatherCfg.talkgroup) << "\",\n";
    oss << "    \"interval_sec\": " << g_weatherCfg.intervalSec << ",\n";
    oss << "    \"api_key\": \"" << escapeJson(g_weatherCfg.apiKey) << "\",\n";
    oss << "    \"lat\": \"" << escapeJson(g_weatherCfg.lat) << "\",\n";
    oss << "    \"lon\": \"" << escapeJson(g_weatherCfg.lon) << "\",\n";
    oss << "    \"city_key\": \"" << escapeJson(g_weatherCfg.cityKey) << "\"\n";
    oss << "  },\n";

    oss << "  \"users\": [\n";
    bool firstU = true;
    for (const auto& kv : g_users) {
        const User& u = kv.second;
        if (!firstU) oss << ",\n";
        firstU = false;
        oss << "    {\"callsign\":\"" << escapeJson(u.callsign) << "\",\"password\":\"" << escapeJson(u.password)
            << "\",\"role\":\"" << roleToStr(u.role) << "\",\"banned\":" << (u.banned ? "true" : "false")
            << ",\"priority\":" << u.priority;
        if (!u.permissions.empty()) {
            oss << ",\"permissions\":[";
            bool fp = true;
            for (const auto& p : u.permissions) {
                if (!fp) oss << ",";
                fp = false;
                oss << "\"" << escapeJson(p) << "\"";
            }
            oss << "]";
        }
        oss << ",\"talkgroups\":[";
        bool ft = true;
        for (const auto& tg : u.talkgroups) {
            if (!ft) oss << ",";
            ft = false;
            oss << "\"" << escapeJson(tg) << "\"";
        }
        oss << "]}";
    }
    oss << "\n  ],\n";

    oss << "  \"talkgroups\": [\n";
    bool firstTg = true;
    for (const auto& kv : g_knownTalkgroups) {
        const TalkgroupInfo& tg = kv.second;
        if (!firstTg) oss << ",\n";
        firstTg = false;
        oss << "    {\"name\":\"" << escapeJson(tg.name) << "\",\"mode\":\"";
        if (tg.mode == TalkgroupMode::HIDE) oss << "hide";
        else if (tg.mode == TalkgroupMode::ADMIN) oss << "admin";
        else oss << "public";
        oss << "\"}";
    }
    oss << "\n  ],\n";

    oss << "  \"bridges\": {\n";
    bool firstB = true;
    for (const auto& kv : g_linkedTalkgroups) {
        if (!firstB) oss << ",\n";
        firstB = false;
        oss << "    \"" << escapeJson(kv.first) << "\":[";
        for (size_t i = 0; i < kv.second.size(); ++i) {
            if (i) oss << ",";
            oss << "\"" << escapeJson(kv.second[i]) << "\"";
        }
        oss << "]";
    }
    oss << "\n  },\n";

    oss << "  \"peers\": [\n";
    {
        std::lock_guard<std::mutex> plock(g_peerMutex);
        bool firstP = true;
        for (const auto& pc : g_peerCfg) {
            if (!firstP) oss << ",\n";
            firstP = false;
            oss << "    {\"name\":\"" << escapeJson(pc.name) << "\",\"host\":\"" << escapeJson(pc.host)
                << "\",\"port\":" << pc.port;
            if (!pc.secret.empty()) oss << ",\"secret\":\"" << escapeJson(pc.secret) << "\"";
            oss << ",\"rules\":[";
            for (size_t i = 0; i < pc.ruleStr.size(); ++i) {
                if (i) oss << ",";
                oss << "\"" << escapeJson(pc.ruleStr[i]) << "\"";
            }
            oss << "]}";
        }
    }
    oss << "\n  ]\n";
    oss << "}\n";
    return oss.str();
}

struct HttpConn {
    SOCKET sock;
#if USE_OPENSSL
    SSL* ssl;
#endif
    bool tls;
};

static void httpConnClose(HttpConn& c) {
#if USE_OPENSSL
    if (c.tls && c.ssl) {
        SSL_shutdown(c.ssl);
        SSL_free(c.ssl);
        c.ssl = nullptr;
    }
#endif
    if (c.sock != INVALID_SOCKET) {
        closeSocket(c.sock);
        c.sock = INVALID_SOCKET;
    }
}

static int httpConnRecv(HttpConn& c, char* buf, int len) {
#if USE_OPENSSL
    if (c.tls && c.ssl) {
        return SSL_read(c.ssl, buf, len);
    }
#endif
    return (int)recv(c.sock, buf, len, 0);
}

static int httpConnSend(HttpConn& c, const char* buf, int len) {
#if USE_OPENSSL
    if (c.tls && c.ssl) {
        return SSL_write(c.ssl, buf, len);
    }
#endif
    return (int)send(c.sock, buf, len, 0);
}

static bool httpConnSendAll(HttpConn& c, const void* data, size_t len) {
    const char* p = (const char*)data;
    size_t sent = 0;
    while (sent < len) {
        int n = httpConnSend(c, p + sent, (int)std::min<size_t>(len - sent, 1u << 20));
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

static bool httpConnRecvAll(HttpConn& c, void* data, size_t len) {
    char* p = (char*)data;
    size_t got = 0;
    while (got < len) {
        int n = httpConnRecv(c, p + got, (int)std::min<size_t>(len - got, 1u << 20));
        if (n <= 0) return false;
        got += (size_t)n;
    }
    return true;
}

static bool readHttpLine(HttpConn& c, std::string& out) {
    out.clear();
    out.reserve(256);
    char ch = 0;
    bool gotCR = false;
    while (true) {
        int n = httpConnRecv(c, &ch, 1);
        if (n <= 0) return false;

        if (ch == '\r') {
            gotCR = true;
            continue;
        }
        if (ch == '\n') {
            break;
        }
        if (gotCR) {
            gotCR = false;
        }
        out.push_back(ch);
        if (out.size() > MAX_HTTP_LINE) return false;
    }
    return true;
}

static void sendHttpResponse(HttpConn& c, const std::string& statusLine,
                             const std::string& contentType,
                             const std::string& body)
{
    std::ostringstream oss;
    oss << statusLine << "\r\n";
    oss << "Server: zFM\r\n";
    oss << "Connection: close\r\n";
    oss << "Content-Type: " << contentType << "\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Cache-Control: no-cache\r\n";
    oss << "\r\n";

    const std::string hdr = oss.str();
    httpConnSendAll(c, hdr.data(), hdr.size());
    if (!body.empty()) httpConnSendAll(c, body.data(), body.size());
}

#if USE_OPENSSL
static SSL_CTX* g_https_ctx = nullptr;

static void sslLogLastError(const char* where) {
    unsigned long e = ERR_get_error();
    if (!e) return;
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    LOG_WARN("HTTPS: %s: %s\n", where, buf);
}

static bool initHttpsContextIfEnabled() {
    if (g_https_port <= 0) return false;

    {
        std::ifstream fc(g_https_cert_file.c_str());
        std::ifstream fk(g_https_key_file.c_str());
        if (!fc.good() || !fk.good()) {
            LOG_WARN("HTTPS disabled: missing cert/key (cert=%s, key=%s)\n",
                     g_https_cert_file.c_str(), g_https_key_file.c_str());
            return false;
        }
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* method = TLS_server_method();
    g_https_ctx = SSL_CTX_new(method);
    if (!g_https_ctx) {
        sslLogLastError("SSL_CTX_new");
        return false;
    }

    SSL_CTX_set_min_proto_version(g_https_ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(g_https_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    if (SSL_CTX_use_certificate_chain_file(g_https_ctx, g_https_cert_file.c_str()) != 1) {
        sslLogLastError("use_certificate_chain_file");
        SSL_CTX_free(g_https_ctx);
        g_https_ctx = nullptr;
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(g_https_ctx, g_https_key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        sslLogLastError("use_PrivateKey_file");
        SSL_CTX_free(g_https_ctx);
        g_https_ctx = nullptr;
        return false;
    }
    if (SSL_CTX_check_private_key(g_https_ctx) != 1) {
        sslLogLastError("check_private_key");
        SSL_CTX_free(g_https_ctx);
        g_https_ctx = nullptr;
        return false;
    }

    return true;
}
#endif

static void handleHttpClientConn(HttpConn& c) {
    std::string line;
    if (!readHttpLine(c, line)) {
        httpConnClose(c);
        return;
    }

    std::unordered_map<std::string,std::string> headers;
    for (;;) {
        std::string h;
        if (!readHttpLine(c, h)) break;
        if (h.empty()) break;

        size_t colon = h.find(':');
        if (colon == std::string::npos) continue;
        std::string k = h.substr(0, colon);
        std::string v = h.substr(colon + 1);
        k = trim(k);
        v = trim(v);
        for (auto& ch : k) ch = (char)std::tolower((unsigned char)ch);
        headers[k] = v;
    }

    std::istringstream iss(line);
    std::string method, url, ver;
    iss >> method >> url >> ver;

    std::string bodyIn;
    if (method == "POST") {
        int contentLen = 0;
        auto itCL = headers.find("content-length");
        if (itCL != headers.end()) {
            try { contentLen = std::stoi(itCL->second); } catch (...) { contentLen = 0; }
        }
        if (contentLen < 0 || contentLen > 1024*1024) {
            sendHttpResponse(c, "HTTP/1.1 413 Payload Too Large", "text/plain", "Payload too large");
            httpConnClose(c);
            return;
        }
        if (contentLen > 0) {
            bodyIn.resize((size_t)contentLen);
            if (!httpConnRecvAll(c, &bodyIn[0], (size_t)contentLen)) {
                httpConnClose(c);
                return;
            }
        }
    } else if (method != "GET") {
        sendHttpResponse(c, "HTTP/1.1 405 Method Not Allowed", "text/plain", "Method Not Allowed");
        httpConnClose(c);
        return;
    }

    if (url.empty()) url = "/";

    std::string pathOnly = url;
    size_t qpos = pathOnly.find('?');
    if (qpos != std::string::npos) pathOnly = pathOnly.substr(0, qpos);

    if (pathOnly == "/api/status") {
        std::string json = buildStatusJson();
        sendHttpResponse(c, "HTTP/1.1 200 OK",
                         "application/json; charset=utf-8", json);
        httpConnClose(c);
        return;
    }

    if (pathOnly == "/api/login" && method == "POST") {
        std::string cs, pw;
        jsonFindString(bodyIn, "callsign", cs);
        jsonFindString(bodyIn, "password", pw);
        if (cs.empty() || pw.empty()) {
            sendHttpResponse(c, "HTTP/1.1 400 Bad Request", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"missing_credentials\"}");
            httpConnClose(c);
            return;
        }

        Role r = Role::USER;
        std::unordered_set<std::string> perms;
        bool ok = false;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            auto it = g_users.find(cs);
            if (it != g_users.end() && !it->second.banned && it->second.password == pw) {
                ok = true;
                r = it->second.role;
                perms = it->second.permissions;
            }
        }

        if (!ok) {
            sendHttpResponse(c, "HTTP/1.1 401 Unauthorized", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"invalid_login\"}");
            httpConnClose(c);
            return;
        }

        HttpSession sess;
        sess.token = makeRandomToken();
        sess.callsign = cs;
        sess.role = r;
        sess.permissions = perms;
        sess.expires = std::chrono::steady_clock::now() + std::chrono::minutes(30);
        {
            std::lock_guard<std::mutex> lk(g_httpSessMutex);
            purgeExpiredSessionsNoLock();
            g_httpSessions[sess.token] = sess;
        }

        std::ostringstream out;
        out << "{\"ok\":true,\"token\":\"" << escapeJson(sess.token)
            << "\",\"callsign\":\"" << escapeJson(cs)
            << "\",\"role\":\"" << roleToStr(r) << "\"";
        if (!perms.empty()) {
            out << ",\"permissions\":[";
            bool first = true;
            for (const auto& p : perms) {
                if (!first) out << ",";
                first = false;
                out << "\"" << escapeJson(p) << "\"";
            }
            out << "]";
        }
        out << "}";

        sendHttpResponse(c, "HTTP/1.1 200 OK", "application/json; charset=utf-8", out.str());
        httpConnClose(c);
        return;
    }

    if (pathOnly == "/api/logout" && method == "POST") {
        std::string tok;
        if (extractBearer(headers, tok)) {
            std::lock_guard<std::mutex> lk(g_httpSessMutex);
            g_httpSessions.erase(tok);
        }
        sendHttpResponse(c, "HTTP/1.1 200 OK", "application/json; charset=utf-8", "{\"ok\":true}");
        httpConnClose(c);
        return;
    }

    if (pathOnly == "/api/admin/config") {
        HttpSession sess;
        if (!getSessionFromHeaders(headers, sess) || !hasAtLeast(sess.role, Role::OPERATOR) || !sessionHasPerm(sess, "config.read")) {
            sendHttpResponse(c, "HTTP/1.1 403 Forbidden", "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"forbidden\"}");
            httpConnClose(c);
            return;
        }

        std::string json = buildAdminConfigJson();
        sendHttpResponse(c, "HTTP/1.1 200 OK", "application/json; charset=utf-8", json);
        httpConnClose(c);
        return;
    }

    auto requireWrite = [&](const std::string& perm, HttpSession& sessOut) -> bool {
        if (!getSessionFromHeaders(headers, sessOut)) return false;
        if (!hasAtLeast(sessOut.role, Role::OPERATOR)) return false;
        return sessionHasPerm(sessOut, perm);
    };

    if (pathOnly == "/api/admin/users" && method == "POST") {
        HttpSession sess;
        if (!requireWrite("users.write", sess)) {
            sendHttpResponse(c, "HTTP/1.1 403 Forbidden", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"forbidden\"}");
            httpConnClose(c);
            return;
        }

        std::string op;
        jsonFindString(bodyIn, "op", op);
        for (auto& c : op) c = (char)std::tolower((unsigned char)c);

        if (op == "delete") {
            std::string target;
            jsonFindString(bodyIn, "callsign", target);
            if (target.empty()) {
                sendHttpResponse(c, "HTTP/1.1 400 Bad Request", "application/json; charset=utf-8",
                                 "{\"ok\":false,\"error\":\"missing_callsign\"}");
                httpConnClose(c);
                return;
            }

            Role targetRole;
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                targetRole = getUserRoleUnsafeNoLock(target);
            }
            if (!canOperatorActOn(sess.role, targetRole)) {
                sendHttpResponse(c, "HTTP/1.1 403 Forbidden", "application/json; charset=utf-8",
                                 "{\"ok\":false,\"error\":\"insufficient_privilege\"}");
                httpConnClose(c);
                return;
            }

            bool ok = false;
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                auto it = g_users.find(target);
                if (it != g_users.end()) {
                    g_users.erase(it);
                    ok = true;
                }
            }
            if (ok) saveConfig("server.json");
            sendHttpResponse(c, "HTTP/1.1 200 OK", "application/json; charset=utf-8",
                             ok ? "{\"ok\":true}" : "{\"ok\":false,\"error\":\"not_found\"}");
            httpConnClose(c);
            return;
        }

        std::string cs, pw, roleS;
        bool banned = false;
        int pri = 0;
        jsonFindString(bodyIn, "callsign", cs);
        jsonFindString(bodyIn, "password", pw);
        jsonFindString(bodyIn, "role", roleS);
        jsonFindBool(bodyIn, "banned", banned);
        jsonFindInt(bodyIn, "priority", pri);
        std::vector<std::string> tgs;
        jsonFindStringArray(bodyIn, "talkgroups", tgs);
        std::vector<std::string> perms;
        jsonFindStringArray(bodyIn, "permissions", perms);

        if (cs.empty()) {
            sendHttpResponse(c, "HTTP/1.1 400 Bad Request", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"missing_callsign\"}");
            httpConnClose(c);
            return;
        }

        Role newRole = roleFromStr(roleS);
        if (newRole == Role::ADMIN && sess.role != Role::ADMIN) {
            sendHttpResponse(c, "HTTP/1.1 403 Forbidden", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"insufficient_privilege\"}");
            httpConnClose(c);
            return;
        }

        Role targetRole;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            targetRole = getUserRoleUnsafeNoLock(cs);
        }
        if (!canOperatorActOn(sess.role, targetRole)) {
            sendHttpResponse(c, "HTTP/1.1 403 Forbidden", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"insufficient_privilege\"}");
            httpConnClose(c);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            User& u = g_users[cs];
            u.callsign = cs;
            if (!pw.empty()) u.password = pw;
            u.role = newRole;
            u.banned = banned;
            u.priority = pri;
            u.talkgroups.clear();
            for (const auto& tg : tgs) u.talkgroups.insert(tg);
            u.permissions.clear();
            for (const auto& p : perms) u.permissions.insert(p);

            for (const auto& tg : tgs) {
                if (g_knownTalkgroups.find(tg) == g_knownTalkgroups.end()) {
                    TalkgroupInfo info; info.name = tg; info.mode = TalkgroupMode::PUBLIC;
                    g_knownTalkgroups[tg] = info;
                }
                if (g_talkgroups.find(tg) == g_talkgroups.end()) g_talkgroups[tg] = TalkgroupState();
            }
        }
        saveConfig("server.json");
        sendHttpResponse(c, "HTTP/1.1 200 OK", "application/json; charset=utf-8", "{\"ok\":true}");
        httpConnClose(c);
        return;
    }

    if (pathOnly == "/api/admin/talkgroups" && method == "POST") {
        HttpSession sess;
        if (!requireWrite("talkgroups.write", sess)) {
            sendHttpResponse(c, "HTTP/1.1 403 Forbidden", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"forbidden\"}");
            httpConnClose(c);
            return;
        }
        std::string op;
        jsonFindString(bodyIn, "op", op);
        for (auto& c : op) c = (char)std::tolower((unsigned char)c);
        if (op == "delete") {
            std::string name;
            jsonFindString(bodyIn, "name", name);
            if (name.empty()) {
                sendHttpResponse(c, "HTTP/1.1 400 Bad Request", "application/json; charset=utf-8",
                                 "{\"ok\":false,\"error\":\"missing_name\"}");
                httpConnClose(c);
                return;
            }
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                g_knownTalkgroups.erase(name);
                g_talkgroups.erase(name);
                g_linkedTalkgroups.erase(name);
            }
            saveConfig("server.json");
            sendHttpResponse(c, "HTTP/1.1 200 OK", "application/json; charset=utf-8", "{\"ok\":true}");
            httpConnClose(c);
            return;
        }

        std::string name, mode;
        jsonFindString(bodyIn, "name", name);
        jsonFindString(bodyIn, "mode", mode);
        if (name.empty()) {
            sendHttpResponse(c, "HTTP/1.1 400 Bad Request", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"missing_name\"}");
            httpConnClose(c);
            return;
        }
        TalkgroupMode m = TalkgroupMode::PUBLIC;
        for (auto& c : mode) c = (char)std::tolower((unsigned char)c);
        if (mode == "hide") m = TalkgroupMode::HIDE;
        else if (mode == "admin") m = TalkgroupMode::ADMIN;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            TalkgroupInfo& t = g_knownTalkgroups[name];
            t.name = name;
            t.mode = m;
            if (g_talkgroups.find(name) == g_talkgroups.end()) g_talkgroups[name] = TalkgroupState();
        }
        saveConfig("server.json");
        sendHttpResponse(c, "HTTP/1.1 200 OK", "application/json; charset=utf-8", "{\"ok\":true}");
        httpConnClose(c);
        return;
    }

    if (pathOnly == "/api/admin/bridges" && method == "POST") {
        HttpSession sess;
        if (!requireWrite("bridges.write", sess)) {
            sendHttpResponse(c, "HTTP/1.1 403 Forbidden", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"forbidden\"}");
            httpConnClose(c);
            return;
        }
        std::string tg;
        jsonFindString(bodyIn, "talkgroup", tg);
        std::vector<std::string> linked;
        jsonFindStringArray(bodyIn, "linked", linked);
        if (tg.empty()) {
            sendHttpResponse(c, "HTTP/1.1 400 Bad Request", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"missing_talkgroup\"}");
            httpConnClose(c);
            return;
        }
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_linkedTalkgroups[tg] = linked;
        }
        saveConfig("server.json");
        sendHttpResponse(c, "HTTP/1.1 200 OK", "application/json; charset=utf-8", "{\"ok\":true}");
        httpConnClose(c);
        return;
    }

    if (pathOnly == "/api/admin/peers" && method == "POST") {
        HttpSession sess;
        if (!requireWrite("peers.write", sess)) {
            sendHttpResponse(c, "HTTP/1.1 403 Forbidden", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"forbidden\"}");
            httpConnClose(c);
            return;
        }

        std::string op;
        jsonFindString(bodyIn, "op", op);
        for (auto& c : op) c = (char)std::tolower((unsigned char)c);
        if (op == "delete") {
            std::string name;
            jsonFindString(bodyIn, "name", name);
            if (name.empty()) {
                sendHttpResponse(c, "HTTP/1.1 400 Bad Request", "application/json; charset=utf-8",
                                 "{\"ok\":false,\"error\":\"missing_name\"}");
                httpConnClose(c);
                return;
            }
            {
                std::lock_guard<std::mutex> lock(g_peerMutex);
                for (auto it = g_peerCfg.begin(); it != g_peerCfg.end(); ++it) {
                    if (it->name == name) { g_peerCfg.erase(it); break; }
                }
            }
            saveConfig("server.json");
            compilePeerRules();
            sendHttpResponse(c, "HTTP/1.1 200 OK", "application/json; charset=utf-8", "{\"ok\":true}");
            httpConnClose(c);
            return;
        }

        std::string name, host, secret;
        int port = 0;
        jsonFindString(bodyIn, "name", name);
        jsonFindString(bodyIn, "host", host);
        jsonFindString(bodyIn, "secret", secret);
        jsonFindInt(bodyIn, "port", port);
        std::vector<std::string> rules;
        jsonFindStringArray(bodyIn, "rules", rules);
        if (name.empty() || host.empty() || port <= 0) {
            sendHttpResponse(c, "HTTP/1.1 400 Bad Request", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"missing_fields\"}");
            httpConnClose(c);
            return;
        }
        {
            std::lock_guard<std::mutex> lock(g_peerMutex);
            bool found = false;
            for (auto& pc : g_peerCfg) {
                if (pc.name == name) {
                    pc.host = host;
                    pc.port = port;
                    pc.secret = secret;
                    pc.ruleStr = rules;
                    found = true;
                    break;
                }
            }
            if (!found) {
                PeerConfig pc;
                pc.name = name;
                pc.host = host;
                pc.port = port;
                pc.secret = secret;
                pc.ruleStr = rules;
                g_peerCfg.push_back(pc);
            }
        }
        saveConfig("server.json");
        compilePeerRules();
        sendHttpResponse(c, "HTTP/1.1 200 OK", "application/json; charset=utf-8", "{\"ok\":true}");
        httpConnClose(c);
        return;
    }

    if (pathOnly == "/api/admin/time_announcement" && method == "POST") {
        HttpSession sess;
        if (!requireWrite("time_announcement.write", sess)) {
            sendHttpResponse(c, "HTTP/1.1 403 Forbidden", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"forbidden\"}");
            httpConnClose(c);
            return;
        }
        bool enabled = g_timeCfg.enabled;
        std::string folder = g_timeCfg.folder;
        int volPermil = (int)(g_timeCfg.volumeFactor * 1000.0f);
        jsonFindBool(bodyIn, "enabled", enabled);
        jsonFindString(bodyIn, "folder", folder);
        jsonFindInt(bodyIn, "volume_factor_permil", volPermil);
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_timeCfg.enabled = enabled;
            g_timeCfg.folder = folder;
            g_timeCfg.volumeFactor = (float)volPermil / 1000.0f;
        }
        saveConfig("server.json");
        sendHttpResponse(c, "HTTP/1.1 200 OK", "application/json; charset=utf-8", "{\"ok\":true}");
        httpConnClose(c);
        return;
    }

    if (pathOnly == "/api/admin/weather" && method == "POST") {
        HttpSession sess;
        if (!requireWrite("weather.write", sess)) {
            sendHttpResponse(c, "HTTP/1.1 403 Forbidden", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"forbidden\"}");
            httpConnClose(c);
            return;
        }
        bool enabled = g_weatherCfg.enabled;
        std::string hostIp = g_weatherCfg.weatherHostIp;
        std::string tg = g_weatherCfg.talkgroup;
        int interval = g_weatherCfg.intervalSec;
        std::string apiKey = g_weatherCfg.apiKey;
        std::string lat = g_weatherCfg.lat;
        std::string lon = g_weatherCfg.lon;
        std::string cityKey = g_weatherCfg.cityKey;

        jsonFindBool(bodyIn, "enabled", enabled);
        jsonFindString(bodyIn, "weather_host_ip", hostIp);
        jsonFindString(bodyIn, "talkgroup", tg);
        jsonFindInt(bodyIn, "interval_sec", interval);
        jsonFindString(bodyIn, "api_key", apiKey);
        jsonFindString(bodyIn, "lat", lat);
        jsonFindString(bodyIn, "lon", lon);
        jsonFindString(bodyIn, "city_key", cityKey);

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_weatherCfg.enabled = enabled;
            g_weatherCfg.weatherHostIp = hostIp;
            g_weatherCfg.talkgroup = tg;
            g_weatherCfg.intervalSec = interval;
            g_weatherCfg.apiKey = apiKey;
            g_weatherCfg.lat = lat;
            g_weatherCfg.lon = lon;
            g_weatherCfg.cityKey = cityKey;
        }
        saveConfig("server.json");
        sendHttpResponse(c, "HTTP/1.1 200 OK", "application/json; charset=utf-8", "{\"ok\":true}");
        httpConnClose(c);
        return;
    }

    if (pathOnly == "/api/admin/server" && method == "POST") {
        HttpSession sess;
        if (!requireWrite("server.write", sess)) {
            sendHttpResponse(c, "HTTP/1.1 403 Forbidden", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"forbidden\"}");
            httpConnClose(c);
            return;
        }
        std::string sname = g_serverName;
        std::string psec  = g_peerSecret;
        int port = g_server_port;
        int maxms = g_max_talk_ms;
        std::string hroot = g_http_root;
        int hport = g_http_port;
        int hsport = g_https_port;
        std::string hcert = g_https_cert_file;
        std::string hkey  = g_https_key_file;
        jsonFindString(bodyIn, "server_name", sname);
        jsonFindString(bodyIn, "peer_secret", psec);
        jsonFindInt(bodyIn, "server_port", port);
        jsonFindInt(bodyIn, "max_talk_ms", maxms);
        jsonFindString(bodyIn, "http_root", hroot);
        jsonFindInt(bodyIn, "http_port", hport);
        jsonFindInt(bodyIn, "https_port", hsport);
        jsonFindString(bodyIn, "https_cert_file", hcert);
        jsonFindString(bodyIn, "https_key_file", hkey);
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_serverName = sname;
            g_peerSecret = psec;
            g_server_port = port;
            g_max_talk_ms = maxms;
            g_http_root = hroot;
            g_http_port = hport;
            g_https_port = hsport;
            g_https_cert_file = hcert;
            g_https_key_file  = hkey;
        }
        saveConfig("server.json");
        sendHttpResponse(c, "HTTP/1.1 200 OK", "application/json; charset=utf-8", "{\"ok\":true,\"note\":\"server needs restart for port/http/https changes\"}");
        httpConnClose(c);
        return;
    }

	if (pathOnly.rfind("/api/waveform", 0) == 0) {
		auto urlDecode = [](const std::string& in) -> std::string {
			std::string out;
			out.reserve(in.size());
			for (size_t i = 0; i < in.size(); ++i) {
				char c = in[i];
				if (c == '+') {
					out.push_back(' ');
				} else if (c == '%' && i + 2 < in.size()) {
					auto hex = [](char h) -> int {
						if (h >= '0' && h <= '9') return h - '0';
						if (h >= 'a' && h <= 'f') return 10 + (h - 'a');
						if (h >= 'A' && h <= 'F') return 10 + (h - 'A');
						return -1;
					};
					int hi = hex(in[i + 1]);
					int lo = hex(in[i + 2]);
					if (hi >= 0 && lo >= 0) {
						out.push_back(static_cast<char>((hi << 4) | lo));
						i += 2;
					} else {
						out.push_back(c);
					}
				} else {
					out.push_back(c);
				}
			}
			return out;
		};

		std::string tg;

		size_t q = url.find('?');
		if (q != std::string::npos) {
			std::string qs = url.substr(q + 1);
			std::string key = "tg=";
			size_t kpos = qs.find(key);
			if (kpos != std::string::npos) {
				size_t vpos = kpos + key.size();
				size_t amp  = qs.find('&', vpos);
				if (amp == std::string::npos) tg = qs.substr(vpos);
				else tg = qs.substr(vpos, amp - vpos);
			}
		}

		tg = urlDecode(tg);

		if (tg.empty()) {
			sendHttpResponse(c,
							 "HTTP/1.1 400 Bad Request",
							 "application/json; charset=utf-8",
							 "{\"error\":\"missing tg param\"}");
			httpConnClose(c);
			return;
		}

		std::string tgUsed = tg;
		std::vector<int16_t> samples;

		{
			std::lock_guard<std::mutex> lock(g_audioBufMutex);

			auto it = g_tgWaveHistory.find(tg);
			if (it == g_tgWaveHistory.end() || it->second.empty()) {
				for (auto it2 = g_tgWaveHistory.begin(); it2 != g_tgWaveHistory.end(); ++it2) {
					if (!it2->second.empty()) {
						it = it2;
						tgUsed = it2->first;
						break;
					}
				}
			}

			if (it == g_tgWaveHistory.end() || it->second.empty()) {
				const size_t ZERO_SAMPLES = 1024;
				samples.assign(ZERO_SAMPLES, 0);
			} else {
				auto now = std::chrono::steady_clock::now();
				const int STALE_MS = 400;

				bool stale = true;
				auto itT = g_tgWaveLastUpdate.find(tgUsed);
				if (itT != g_tgWaveLastUpdate.end()) {
					int age = (int)std::chrono::duration_cast<std::chrono::milliseconds>(now - itT->second).count();
					stale = (age > STALE_MS);
				}

				if (stale) {
					const size_t ZERO_SAMPLES = 1024;
					samples.assign(ZERO_SAMPLES, 0);
				} else {
					const std::vector<int16_t>& wave = it->second;
					const size_t maxSamples = 1024;
					if (wave.size() <= maxSamples) {
						samples = wave;
					} else {
						samples.assign(wave.end() - maxSamples, wave.end());
					}
				}
			}
		}

		std::ostringstream body;
		body << "{ \"talkgroup\": \"" << escapeJson(tgUsed) << "\", \"samples\": [";
		for (size_t i = 0; i < samples.size(); ++i) {
			if (i) body << ",";
			body << samples[i];
		}
		body << "] }";

		sendHttpResponse(c,
						 "HTTP/1.1 200 OK",
						 "application/json; charset=utf-8",
						 body.str());
		httpConnClose(c);
		return;
	}

    std::string rel = pathOnly;
    if (!rel.empty() && rel[0] == '/') rel.erase(0, 1);
    if (rel.empty()) rel = "index.html";

    if (!isSafeRelPath(rel)) {
        sendHttpResponse(c, "HTTP/1.1 403 Forbidden", "text/plain", "Forbidden");
        httpConnClose(c);
        return;
    }

#ifdef _WIN32
    std::string full = g_http_root + "\\" + rel;
#else
    std::string full = g_http_root + "/" + rel;
#endif

    std::string body;
    if (!loadFileToString(full, body)) {
        sendHttpResponse(c, "HTTP/1.1 404 Not Found", "text/plain", "404 Not Found");
        httpConnClose(c);
        return;
    }

    std::string mime = getMimeType(rel);
    sendHttpResponse(c, "HTTP/1.1 200 OK", mime, body);
    httpConnClose(c);
}

static void handleHttpClient(SOCKET s) {
    HttpConn c;
    c.sock = s;
    c.tls = false;
    handleHttpClientConn(c);
}

#if USE_OPENSSL
static void httpsServerThread() {
    if (!g_https_ctx || g_https_port <= 0) {
        return;
    }

    SOCKET ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls == INVALID_SOCKET) {
        LOG_ERROR("HTTPS: socket() failed\n");
        return;
    }

    int opt = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    int flag = 1;
    setsockopt(ls, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)g_https_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(ls, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        LOG_ERROR("HTTPS: bind() failed\n");
        closeSocket(ls);
        return;
    }
    if (listen(ls, 16) == SOCKET_ERROR) {
        LOG_ERROR("HTTPS: listen() failed\n");
        closeSocket(ls);
        return;
    }

    LOG_OK("HTTPS dashboard listening on port %d (root: %s)\n", g_https_port, g_http_root.c_str());

    while (g_running) {
        sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        SOCKET cs = accept(ls, (sockaddr*)&caddr, &clen);
        if (cs == INVALID_SOCKET) {
            if (!g_running) break;
            continue;
        }

        int flag2 = 1;
        setsockopt(cs, IPPROTO_TCP, TCP_NODELAY, (char*)&flag2, sizeof(flag2));

        std::thread([cs]() {
            HttpConn conn;
            conn.sock = cs;
            conn.tls = true;

            SSL* ssl = SSL_new(g_https_ctx);
            if (!ssl) {
                closeSocket(cs);
                return;
            }
            SSL_set_fd(ssl, (int)cs);
            if (SSL_accept(ssl) != 1) {
                SSL_free(ssl);
                closeSocket(cs);
                return;
            }
            conn.ssl = ssl;
            handleHttpClientConn(conn);
        }).detach();
    }

    closeSocket(ls);
}
#endif

static void httpServerThread() {
    SOCKET ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls == INVALID_SOCKET) {
        LOG_ERROR("HTTP: socket() failed\n");
        return;
    }

    int opt = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

	int flag = 1;
	setsockopt(ls, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)g_http_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(ls, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        LOG_ERROR("HTTP: bind() failed\n");
        closeSocket(ls);
        return;
    }

    if (listen(ls, 16) == SOCKET_ERROR) {
        LOG_ERROR("HTTP: listen() failed\n");
        closeSocket(ls);
        return;
    }

	LOG_OK("HTTP dashboard listening on port %d (root: %s)\n",g_http_port,g_http_root.c_str());

    while (g_running) {
        sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
		SOCKET cs = accept(ls, (sockaddr*)&caddr, &clen);
		if (cs == INVALID_SOCKET) {
			if (!g_running) break;
			continue;
		}

		int flag = 1;
		setsockopt(cs, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));

		std::thread t(handleHttpClient, cs);
		t.detach();
    }

    closeSocket(ls);
}

static void flushAudioJitterForTalkgroup(const std::string& tg,const std::string& fromUser,SOCKET exceptSock)
{
    std::vector<char> remaining;

    {
        std::lock_guard<std::mutex> lock(g_audioBufMutex);
        std::map<std::string, std::vector<char> >::iterator it = g_tgAudioBuf.find(tg);
        if (it == g_tgAudioBuf.end() || it->second.empty())
            return;
        remaining.swap(it->second);
    }

    if (remaining.empty())
        return;

    std::ostringstream oss;
    oss << "AUDIO_FROM " << fromUser << " " << remaining.size() << "\n";
    std::string header = oss.str();

    std::vector<std::pair<SOCKET, std::shared_ptr<ClientTxState>>> targets;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        targets.reserve(g_clients.size());
        for (const auto& kv : g_clients) {
            SOCKET cs = kv.first;
            if (cs == exceptSock) continue;
            const ClientInfo& ci = kv.second;
            if (!ci.authenticated) continue;
            if (ci.talkgroup != tg) continue;
            targets.emplace_back(cs, ci.tx);
        }
    }

    for (auto& t : targets) {
        SOCKET cs = t.first;
        auto& tx = t.second;
        if (!enqueueStrToTx(tx, header, false)) { shutdownSocket(cs); continue; }
        if (!enqueueToTx(tx, remaining.data(), remaining.size(), /*isAudio=*/true)) { shutdownSocket(cs); continue; }
    }
}

void broadcastAudioToTalkgroup(const std::string& tg,
                               const std::string& fromUser,
                               const std::vector<char>& audio,
                               SOCKET exceptSock)
{
    auto sendPcm = [&](const std::vector<char>& pcm) {
        std::ostringstream oss;
        oss << "AUDIO_FROM " << fromUser << " " << pcm.size() << "\n";
        std::string header = oss.str();

        std::vector<SOCKET> targets;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            targets.reserve(g_clients.size());
            for (const auto& kv : g_clients) {
                SOCKET cs = kv.first;
                if (cs == exceptSock) continue;
                const ClientInfo& ci = kv.second;
                if (!ci.authenticated) continue;
                if (ci.talkgroup != tg) continue;
                targets.push_back(cs);
            }
        }

        for (SOCKET cs : targets) {
            std::shared_ptr<ClientTxState> tx;
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                auto it = g_clients.find(cs);
                if (it != g_clients.end()) tx = it->second.tx;
            }
            if (!enqueueStrToTx(tx, header, /*isAudio=*/false)) { shutdownSocket(cs); continue; }
            if (!enqueueToTx(tx, pcm.data(), pcm.size(), /*isAudio=*/true)) { shutdownSocket(cs); continue; }
        }
    };

    if (fromUser == "SERVER" || fromUser == "Weather Forecast" || fromUser == "Weather") {
        sendPcm(audio);
        return;
    }

    updateLastHeard(fromUser, tg);

    const size_t JITTER_TARGET_BYTES = 640;
    std::vector<char> toSend;

    {
        std::lock_guard<std::mutex> lock(g_audioBufMutex);

        {
            std::vector<int16_t>& wave = g_tgWaveHistory[tg];
            const int16_t* pcm = reinterpret_cast<const int16_t*>(audio.data());
            size_t sampleCount = audio.size() / sizeof(int16_t);
			wave.insert(wave.end(), pcm, pcm + sampleCount);
			g_tgWaveLastUpdate[tg] = std::chrono::steady_clock::now();

            const size_t maxWaveSamples = 2048;
            if (wave.size() > maxWaveSamples) {
                wave.erase(wave.begin(), wave.end() - maxWaveSamples);
            }
        }

        std::vector<char>& buf = g_tgAudioBuf[tg];
        buf.insert(buf.end(), audio.begin(), audio.end());

        if (buf.size() < JITTER_TARGET_BYTES) {
            return;
        }

        toSend.swap(buf);
    }

    if (!toSend.empty()) {
        sendPcm(toSend);
    }
}

static void broadcastToLinkedTalkgroups(const std::string& tg,const std::string& message,SOCKET exceptSock = INVALID_SOCKET) {
    auto tgs = getLinkedFanout(tg);
    for (const auto& name : tgs) {
        broadcastToTalkgroup(name, message, exceptSock);
    }
}

static void broadcastAdpcmToTalkgroup(const std::string& tg,
                                      const std::string& fromUser,
                                      uint32_t seq,
                                      uint16_t rate,
                                      const std::vector<char>& payload,
                                      SOCKET excludeSock)
{
    std::ostringstream oss;
    oss << "AUDIO_ADPCM_FROM " << fromUser << " " << seq << " " << rate << " " << payload.size() << "\n";
    std::string header = oss.str();

    std::vector<SOCKET> targets;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        targets.reserve(g_clients.size());
        for (const auto& kv : g_clients) {
            SOCKET cs = kv.first;
            if (cs == excludeSock) continue;
            const ClientInfo& ci = kv.second;
            if (!ci.authenticated) continue;
            if (ci.talkgroup != tg) continue;
            targets.push_back(cs);
        }
    }

    for (SOCKET cs : targets) {
        if (!sendAll(cs, header.data(), header.size())) continue;
        if (!payload.empty()) {
            sendAll(cs, payload.data(), payload.size());
        }
    }
}

static void broadcastAdpcmToLinkedTalkgroups(const std::string& baseTg,
                                            const std::string& fromUser,
                                            uint32_t seq,
                                            uint16_t rate,
                                            const std::vector<char>& payload,
                                            SOCKET excludeSock)
{
    const std::vector<std::string> fanout = getLinkedFanout(baseTg);
    for (const auto& tg : fanout) {
        if (tg.empty()) continue;
        broadcastAdpcmToTalkgroup(tg, fromUser, seq, rate, payload, excludeSock);
    }
}

void broadcastAudioToLinkedTalkgroups(const std::string& tg,const std::string& fromUser,const std::vector<char>& buf,SOCKET exceptSock) {
    auto tgs = getLinkedFanout(tg);
    for (const auto& name : tgs) {
        broadcastAudioToTalkgroup(name, fromUser, buf, exceptSock);
    }
}

void announcePumpThreadFunc() {
    const int frameMs = 20;

    auto nextTick = std::chrono::steady_clock::now();

    while (g_announcePumpRunning && g_running) {
        std::vector<std::pair<std::string, std::string> > active;
        {
            std::lock_guard<std::mutex> lock(g_announceMutex);
            for (std::unordered_map<std::string, TalkgroupAnnounceState>::const_iterator it = g_tgAnnounce.begin();
                 it != g_tgAnnounce.end(); ++it) {
                if (it->second.active && !it->second.key.empty()) {
                    active.push_back(std::make_pair(it->first, it->second.key));
                }
            }
        }

        for (size_t i = 0; i < active.size(); ++i) {
            const std::string& tg  = active[i].first;
            const std::string& key = active[i].second;

            CachedWav wav;
            if (!getTimeWavForTalkgroup(tg, key, wav) ||
                wav.sampleRate == 0 || wav.samples.empty()) {
                continue;
            }

            uint32_t samplesPerFrame =
                (uint32_t)((uint64_t)wav.sampleRate * (uint64_t)frameMs / 1000ULL);
            if (samplesPerFrame == 0) samplesPerFrame = wav.sampleRate;

            std::vector<char> buf(samplesPerFrame * sizeof(int16_t));
            std::memset(buf.data(), 0, buf.size());

            mixTimeAnnouncementIntoBuffer(tg, buf);

            bool nonZero = false;
            int16_t* s = reinterpret_cast<int16_t*>(buf.data());
            for (uint32_t n = 0; n < samplesPerFrame; ++n) {
                if (s[n] != 0) {
                    nonZero = true;
                    break;
                }
            }
            if (!nonZero) {
                continue;
            }

            std::string talker = "SERVER";
            if (key == "weather_auto") {
                talker = "Weather";
            }

			broadcastAudioToLinkedTalkgroups(tg, talker, buf, INVALID_SOCKET);
        }

        nextTick += std::chrono::milliseconds(frameMs);
        std::this_thread::sleep_until(nextTick);
    }
}


SOCKET findClientByCallsign(const std::string& callsign) {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::unordered_map<SOCKET, ClientInfo>::iterator it;
    for (it = g_clients.begin(); it != g_clients.end(); ++it) {
        if (it->second.callsign == callsign) return it->first;
    }
    return INVALID_SOCKET;
}

void cleanupClient(SOCKET sock) {
    std::string tg;
    std::string user;

    bool speakerCleared = false;

    std::shared_ptr<ClientTxState> tx;

    {
        std::lock_guard<std::mutex> lock(g_mutex);

        auto it = g_clients.find(sock);
        if (it == g_clients.end()) return;

        tg   = it->second.talkgroup;
        user = it->second.callsign;

        if (!tg.empty()) {
            TalkgroupState& ts = g_talkgroups[tg];
            if (ts.activeSpeaker == user) {
                ts.activeSpeaker.clear();
                speakerCleared = true;
            }
        }

        tx = it->second.tx;
        g_clients.erase(it);
    }

    if (tx) {
        {
            std::lock_guard<std::mutex> lk(tx->m);
            tx->alive.store(false);
        }
        tx->cv.notify_all();
    }

    if (!tg.empty()) {
        if (speakerCleared) {
            std::string msg1 = "MIC_FREE\n";
            std::string msg2 = "SPEAKER_NONE\n";
            broadcastToTalkgroup(tg, msg1, sock);
            broadcastToTalkgroup(tg, msg2, sock);
        }

        triggerAnnouncementForTalkgroup(tg, "tg_leave");
    }
}

static bool startsWith(const std::string& s, const std::string& p)
{
    return s.size() >= p.size() && std::equal(p.begin(), p.end(), s.begin());
}

static bool checkPeerAuth(const std::string& peerName, const std::string& secret)
{
    for (const auto& pc : g_peerCfg) {
        if (pc.name != peerName) continue;
        std::string expected = pc.secret.empty() ? g_peerSecret : pc.secret;
        return !expected.empty() && secret == expected;
    }
    return false;
}

static void handlePeerSession(SOCKET sock, const std::string& firstLine)
{
    std::istringstream iss(firstLine);
    std::string cmd, remoteName, secret;
    iss >> cmd >> remoteName >> secret;

    if (cmd != "PEER_AUTH" || remoteName.empty() || secret.empty() || !checkPeerAuth(remoteName, secret)) {
        const char* fail = "PEER_FAIL\n";
        sendAll(sock, fail, std::strlen(fail));
        closeSocket(sock);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_peerMutex);
        if (g_peerConns.find(remoteName) != g_peerConns.end()) {
            const char* busy = "PEER_BUSY\n";
            sendAll(sock, busy, std::strlen(busy));
            closeSocket(sock);
            return;
        }
    }

    const char* ok = "PEER_OK\n";
    if (!sendAll(sock, ok, std::strlen(ok))) {
        closeSocket(sock);
        return;
    }

    PeerConn* pc = new PeerConn();
    pc->peerName = remoteName;
    pc->sock = sock;
    pc->running = true;

    {
        std::lock_guard<std::mutex> lock(g_peerMutex);
        g_peerConns[remoteName] = pc;
    }

    LOG_OK("PEER connected inbound from %s\n", remoteName.c_str());

    while (g_running && pc->running) {
        std::string ln;
        if (!recvLine(sock, ln)) break;
        handlePeerLine(pc, ln);
    }

    {
        std::lock_guard<std::mutex> lock(g_peerMutex);
        auto it = g_peerConns.find(remoteName);
        if (it != g_peerConns.end() && it->second == pc) g_peerConns.erase(it);
    }

    closeSocket(sock);
    delete pc;
}

static bool hasAtLeast(Role a, Role need) { return (int)a >= (int)need; }

static bool canOperatorActOn(Role actor, Role target)
{
    if (actor == Role::ADMIN) return true;
    if (actor == Role::OPERATOR) {
        return (target == Role::USER);
    }
    return false;
}

static Role getUserRoleUnsafeNoLock(const std::string& cs) {
	auto it = g_users.find(cs);
	if (it == g_users.end()) return Role::USER;
	return it->second.role;
}

void handleClient(SOCKET sock) {
    auto tx = std::make_shared<ClientTxState>();
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        ClientInfo ci;
        ci.sock = sock;
        ci.callsign.clear();
        ci.talkgroup.clear();
        ci.authenticated = false;
        ci.remoteAddr = "unknown";
        ci.tx = tx;

        sockaddr_in addr;
        socklen_t len = sizeof(addr);
        if (getpeername(sock, (sockaddr*)&addr, &len) == 0) {
            char host[64] = {0};
            if (inet_ntop(AF_INET, &addr.sin_addr, host, sizeof(host))) {
                ci.remoteAddr = host;
            }
        }

        g_clients[sock] = ci;
    }

    std::thread(clientSenderThreadFunc, sock, tx).detach();

    std::string line;

    if (!recvLine(sock, line)) {
        cleanupClient(sock);
        closeSocket(sock);
        return;
    }

    if (startsWith(line, "PEER_AUTH")) {
        cleanupClient(sock);
        handlePeerSession(sock, line);
        return;
    }

    bool haveBufferedLine = true;

    while (g_running) {
        if (!haveBufferedLine) {
            if (!recvLine(sock, line)) {
                break;
            }
        } else {
            haveBufferedLine = false;
        }

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "PING") {
            static const char kPong[] = "PONG\n";
            sendAll(sock, kPong, sizeof(kPong) - 1);
            continue;
        }

		if (cmd == "AUTH") {
			std::string user, pass;
			iss >> user >> pass;

			bool ok = false;
			std::string reason = "bad_credentials";

			{
				std::lock_guard<std::mutex> lock(g_mutex);

				std::unordered_map<std::string, User>::iterator it = g_users.find(user);
				if (it != g_users.end() && it->second.password == pass) {
					if (it->second.banned) {
						ok = false;
						reason = "banned";
					} else {
						bool alreadyLoggedIn = false;
						std::unordered_map<SOCKET, ClientInfo>::iterator cit;
						for (cit = g_clients.begin(); cit != g_clients.end(); ++cit) {
							if (cit->first == sock) continue;
							if (cit->second.authenticated && cit->second.callsign == user) {
								alreadyLoggedIn = true;
								break;
							}
						}

						if (alreadyLoggedIn) {
							ok = false;
							reason = "already_logged_in";
						} else {
							g_clients[sock].authenticated = true;
							g_clients[sock].callsign = user;
							ok = true;
						}
					}
				}
			}

			std::string resp;
			if (ok) {
				resp = "AUTH_OK\n";
			} else {
				resp = "AUTH_FAIL " + reason + "\n";
			}

            sendAll(sock, resp.c_str(), resp.size());

			if (ok) {
				sockaddr_in addr;
				socklen_t alen = sizeof(addr);
				char ipbuf[64] = {0};
				if (getpeername(sock, (sockaddr*)&addr, &alen) == 0) {
#ifdef _WIN32
					inet_ntop(AF_INET, &addr.sin_addr, ipbuf, sizeof(ipbuf));
#else
					inet_ntop(AF_INET, &addr.sin_addr, ipbuf, sizeof(ipbuf));
#endif
				}
				LOG_INFO("[AUTH] user=%s from=%s\n", user.c_str(), ipbuf);
			}

            if (!ok) {
                break;
            }
		}
		else if (cmd == "JOIN") {
			std::string requestedTg;
			iss >> requestedTg;

			static const std::string SCANNER_TG = "SCANNER";

			bool ok = false;
			std::string err;
			std::string prevTg;
			std::string callsign;

			std::string effectiveTg = requestedTg;

			bool redirected = false;

			{
				std::lock_guard<std::mutex> lock(g_mutex);
				auto it = g_clients.find(sock);
				if (it == g_clients.end()) {
					err = "unknown_client";
				} else {
					ClientInfo &ci = it->second;
					callsign = ci.callsign;
					prevTg   = ci.talkgroup;

					if (!ci.authenticated) {
						err = "not_authenticated";
					} else {
						auto uit = g_users.find(ci.callsign);
						if (uit == g_users.end()) {
							err = "unknown_user";
						} else {
							User &user = uit->second;

							auto pickFallback = [&]() -> std::string {
								std::string best;
								for (const auto &tg : user.talkgroups) {
									if (g_knownTalkgroups.find(tg) == g_knownTalkgroups.end())
										continue;
									if (best.empty() || tg < best)
										best = tg;
								}
								return best;
							};

							const bool requestedIsScanner = (requestedTg == SCANNER_TG);

							bool requestedKnown = (g_knownTalkgroups.find(requestedTg) != g_knownTalkgroups.end());
							bool requestedAllowed = (user.talkgroups.find(requestedTg) != user.talkgroups.end());

							if (requestedIsScanner || !requestedKnown || !requestedAllowed) {
								std::string fallback = pickFallback();
								if (!fallback.empty()) {
									effectiveTg = fallback;
									redirected = true;
								} else {
									err = "no_allowed_talkgroup";
								}
							}

							if (err.empty()) {
								ci.talkgroup = effectiveTg;
								if (g_talkgroups.find(effectiveTg) == g_talkgroups.end()) {
									g_talkgroups[effectiveTg];
								}
								ok = true;
							} else {
								ok = false;
							}
						}
					}
				}
			}

			if (ok) {
				std::string resp = "JOIN_OK " + effectiveTg + "\n";
				sendAll(sock, resp.c_str(), resp.size());

				if (redirected) {
					if (requestedTg == SCANNER_TG) {
						std::string info = "INFO join_scanner " + effectiveTg + "\n";
						sendAll(sock, info.c_str(), info.size());
					} else if (requestedTg != effectiveTg) {
						std::string info = "INFO join_redirect " + requestedTg + " " + effectiveTg + "\n";
						sendAll(sock, info.c_str(), info.size());
					}
				}

				sendTalkgroupListForUser(sock, callsign);

				if (!prevTg.empty() && prevTg != effectiveTg) {
					triggerAnnouncementForTalkgroup(prevTg, "tg_leave");
				}
				triggerAnnouncementForTalkgroup(effectiveTg, "tg_join");
			} else {
				std::string resp = "JOIN_FAIL " + err + "\n";
				sendAll(sock, resp.c_str(), resp.size());
			}
		}
		else if (cmd == "REQ_SPEAK") {
			std::string tg;
			std::string user;

			bool granted   = false;
			bool preempted = false;

			std::string prevSpeaker;
			std::string denyReason;

			{
				std::lock_guard<std::mutex> lock(g_mutex);

				auto itc = g_clients.find(sock);
				if (itc == g_clients.end() || !itc->second.authenticated) {
					denyReason = "not_authenticated";
				} else {
					ClientInfo &ci = itc->second;
					tg   = ci.talkgroup;
					user = ci.callsign;

					if (!userCanSpeakNow(user, tg, denyReason)) {

					} else {
						TalkgroupState &ts = g_talkgroups[tg];
						auto now = std::chrono::steady_clock::now();

						if (!ts.activeSpeaker.empty() && ts.lastAudio.time_since_epoch().count() != 0) {
							long long idleMs =
								std::chrono::duration_cast<std::chrono::milliseconds>(now - ts.lastAudio).count();
							if (idleMs > 2000) {
								ts.activeSpeaker.clear();
							}
						}

						if (ts.activeSpeaker.empty()) {
							ts.activeSpeaker = user;
							ts.speakStart    = now;
							ts.lastAudio     = now;
							granted = true;
						} else if (ts.activeSpeaker == user) {
							ts.lastAudio = now;
							granted = true;
						} else {
							prevSpeaker = ts.activeSpeaker;

							int reqRank  = computeUserRank(user);
							int curRank  = computeUserRank(baseCallsignFromSpeaker(prevSpeaker));

							if (reqRank > curRank) {
								ts.activeSpeaker = user;
								ts.speakStart    = now;
								ts.lastAudio     = now;
								granted   = true;
								preempted = true;
							} else {
								denyReason = "busy";
							}
						}
					}
				}
			}

			if (!granted) {
				std::string resp = "SPEAK_DENIED " + (denyReason.empty() ? "busy_or_no_tg" : denyReason) + "\n";
				sendAll(sock, resp.c_str(), resp.size());
			} else {
				std::ostringstream oss;
				oss << "SPEAK_GRANTED " << g_max_talk_ms << "\n";
				std::string resp = oss.str();
				sendAll(sock, resp.c_str(), resp.size());

				if (!tg.empty()) {
					std::string sMsg = "SPEAKER " + user + "\n";
					broadcastToLinkedTalkgroups(tg, sMsg, INVALID_SOCKET);
				}

				if (!tg.empty()) {
					std::string bridgeId = ensureBridgeIdForLocalTx(tg);
					peerForwardSpeakerStart(tg, user, bridgeId, 0);
				}

				if (preempted && !prevSpeaker.empty()) {
					std::string prevBase = baseCallsignFromSpeaker(prevSpeaker);

					SOCKET prevSock = INVALID_SOCKET;
					{
						std::lock_guard<std::mutex> lock(g_mutex);
						for (const auto& kv : g_clients) {
							const ClientInfo& ci2 = kv.second;
							if (!ci2.authenticated) continue;
							if (ci2.callsign == prevBase && ci2.talkgroup == tg) {
								prevSock = kv.first;
								break;
							}
						}
					}
					if (prevSock != INVALID_SOCKET) {
						const char* msg = "SPEAK_REVOKED preempted\nMIC_FREE\n";
						sendAll(prevSock, msg, std::strlen(msg));
					}
				}

				LOG_INFO("SPEAK granted for %s on TG %s%s\n",
						 user.c_str(), tg.c_str(),
						 preempted ? " (preempted previous)" : "");
			}
		}
		else if (cmd == "END_SPEAK") {
			std::string tg;
			std::string user;
			bool freed = false;

			{
				std::lock_guard<std::mutex> lock(g_mutex);
				std::unordered_map<SOCKET, ClientInfo>::iterator it = g_clients.find(sock);
				if (it != g_clients.end()) {
					tg = it->second.talkgroup;
					user = it->second.callsign;
					if (!tg.empty()) {
						TalkgroupState& ts = g_talkgroups[tg];
						if (ts.activeSpeaker == user) {
							ts.activeSpeaker.clear();
							freed = true;
						}
					}
				}
			}

			if (freed) {
				flushAudioJitterForTalkgroup(tg, user, sock);

				std::string msg  = "MIC_FREE\n";
				std::string sMsg = "SPEAKER_NONE\n";

				broadcastToLinkedTalkgroups(tg, msg);
				broadcastToLinkedTalkgroups(tg, sMsg, INVALID_SOCKET);

				std::string bridgeId;
				{
					std::lock_guard<std::mutex> lock(g_bridgeIdMutex);
					auto it = g_activeBridgeIdByTg.find(tg);
					if (it != g_activeBridgeIdByTg.end()) bridgeId = it->second;
				}
				if (!bridgeId.empty()) {
					peerForwardSpeakerEnd(tg, bridgeId, 0);
				}
				clearBridgeIdForLocalTx(tg);

				std::cout << "[TG " << tg << "] Mic freed by " << user << "\n";
			}
        }
		else if (cmd == "AUDIO_ADPCM") {
			uint32_t seq = 0;
			uint16_t rate = 0;
			size_t size = 0;
			iss >> seq >> rate >> size;

			if (size == 0) continue;

			if (size > MAX_CLIENT_AUDIO_BYTES) {
				LOG_WARN("Client sent oversized AUDIO_ADPCM frame: %zu bytes (disconnecting)\n", size);
				break;
			}

			std::vector<char> buf(size);
			if (!recvAll(sock, buf.data(), size)) {
				break;
			}

            std::string tg;
            std::string user;
            bool allowed = false;
            bool timeOut = false;

            {
                std::lock_guard<std::mutex> lock(g_mutex);
                auto it = g_clients.find(sock);
                if (it == g_clients.end()) continue;

                tg   = it->second.talkgroup;
                user = it->second.callsign;

                if (!tg.empty()) {
                    TalkgroupState &ts = g_talkgroups[tg];
                    auto uit = g_users.find(user);
                    if (uit != g_users.end() && !uit->second.muted && ts.activeSpeaker == user) {
                        auto now = std::chrono::steady_clock::now();
                        long long elapsed =
                            std::chrono::duration_cast<std::chrono::milliseconds>(now - ts.speakStart).count();
                        if (elapsed <= g_max_talk_ms) {
                            allowed      = true;
                            ts.lastAudio = now;
                        } else {
                            ts.activeSpeaker.clear();
                            timeOut = true;
                        }
                    }
                }
            }

            if (allowed) {
                broadcastAdpcmToLinkedTalkgroups(tg, user, seq, rate, buf, sock);
            } else if (timeOut) {
                flushAudioJitterForTalkgroup(tg, user, sock);

                std::string msg = "SPEAK_REVOKED TIME_LIMIT\nMIC_FREE\n";
                sendAll(sock, msg.c_str(), msg.size());
                if (!tg.empty()) {
                    std::string bmsg = "MIC_FREE\n";
                    broadcastToTalkgroup(tg, bmsg, sock);

                    std::string sMsg = "SPEAKER_NONE\n";
                    broadcastToTalkgroup(tg, sMsg, sock);
                }
                LOG_INFO("[TG %s] Time limit reached for %s\n", tg.c_str(), user.c_str());
            }
        }
		else if (cmd == "AUDIO") {
			size_t size = 0;
			iss >> size;

			if (size == 0) continue;

			if (size > MAX_CLIENT_AUDIO_BYTES) {
				LOG_WARN("Client sent oversized %s frame: %zu bytes (disconnecting)\n",
						 cmd.c_str(), size);
				break;
			}

			std::vector<char> buf(size);
			if (!recvAll(sock, buf.data(), size)) {
				break;
			}

            std::string tg;
            std::string user;
            bool allowed = false;
            bool timeOut = false;
            std::vector<char> decodedPcm;

            {
                std::lock_guard<std::mutex> lock(g_mutex);
                auto it = g_clients.find(sock);
                if (it == g_clients.end()) continue;

                tg   = it->second.talkgroup;
                user = it->second.callsign;

                if (!tg.empty()) {
                    TalkgroupState &ts = g_talkgroups[tg];
                    auto uit = g_users.find(user);
                    if (uit != g_users.end() && !uit->second.muted && ts.activeSpeaker == user) {
                        auto now = std::chrono::steady_clock::now();
                        long long elapsed =
                            std::chrono::duration_cast<std::chrono::milliseconds>(now - ts.speakStart).count();
                        if (elapsed <= g_max_talk_ms) {
                            allowed      = true;
                            ts.lastAudio = now;
                        } else {
                            ts.activeSpeaker.clear();
                            timeOut = true;
                        }
                    }
                }
            }

			if (allowed) {
				broadcastAudioToLinkedTalkgroups(tg, user, buf, sock);
				{
					std::string bridgeId = ensureBridgeIdForLocalTx(tg);
					peerForwardAudio(tg, buf, bridgeId, 0);
				}
            } else if (timeOut) {
                flushAudioJitterForTalkgroup(tg, user, sock);

                std::string msg = "SPEAK_REVOKED TIME_LIMIT\nMIC_FREE\n";
                sendAll(sock, msg.c_str(), msg.size());
                if (!tg.empty()) {
                    std::string bmsg = "MIC_FREE\n";
                    broadcastToTalkgroup(tg, bmsg, sock);

                    std::string sMsg = "SPEAKER_NONE\n";
                    broadcastToTalkgroup(tg, sMsg, sock);
                }
                LOG_INFO("[TG %s] Time limit reached for %s\n", tg.c_str(), user.c_str());
            }
        }
		else if (cmd == "ADMIN") {
			std::string sub;
			iss >> sub;

			std::string myUser;
			{
				std::lock_guard<std::mutex> lock(g_mutex);
				std::unordered_map<SOCKET, ClientInfo>::iterator it = g_clients.find(sock);
				if (it == g_clients.end() || !it->second.authenticated) {
					std::string resp = "ADMIN_FAIL not_authenticated\n";
					sendAll(sock, resp.c_str(), resp.size());
					continue;
				}
				myUser = it->second.callsign;
			}

			auto uit = g_users.find(myUser);
			if (uit == g_users.end()) {
				std::string resp = "ADMIN_FAIL no_user\n";
				sendAll(sock, resp.c_str(), resp.size());
				continue;
			}

			Role myRole = uit->second.role;
			if (!hasAtLeast(myRole, Role::OPERATOR)) {
				std::string resp = "ADMIN_FAIL not_operator\n";
				sendAll(sock, resp.c_str(), resp.size());
				continue;
			}

			if (sub == "set_admin" || sub == "set_pass" || sub == "add_tg" || sub == "drop_tg" || sub == "list_tgs") {
				if (myRole != Role::ADMIN) {
					std::string resp = "ADMIN_FAIL admin_only\n";
					sendAll(sock, resp.c_str(), resp.size());
					continue;
				}
			}

			if (sub == "kick") {
				std::string targetUser;
				iss >> targetUser;

				Role targetRole;
				{
					std::lock_guard<std::mutex> lock(g_mutex);
					targetRole = getUserRoleUnsafeNoLock(targetUser);
				}

				if (!canOperatorActOn(myRole, targetRole)) {
					std::string resp = "ADMIN_FAIL insufficient_privilege\n";
					sendAll(sock, resp.c_str(), resp.size());
					continue;
				}

                SOCKET targetSock = findClientByCallsign(targetUser);
                if (targetSock == INVALID_SOCKET) {
                    std::string resp = "ADMIN_FAIL kick_user_not_found\n";
                    sendAll(sock, resp.c_str(), resp.size());
                } else {
                    std::string msg = "ADMIN_INFO kicked_by_admin\n";
                    sendAll(targetSock, msg.c_str(), msg.size());
                    closeSocket(targetSock);
                    cleanupClient(targetSock);

                    std::string resp = "ADMIN_OK kick\n";
                    sendAll(sock, resp.c_str(), resp.size());
                }
            }
            else if (sub == "mute") {
				std::string targetUser;
				iss >> targetUser;

				Role targetRole;
				{
					std::lock_guard<std::mutex> lock(g_mutex);
					targetRole = getUserRoleUnsafeNoLock(targetUser);
				}

				if (!canOperatorActOn(myRole, targetRole)) {
					std::string resp = "ADMIN_FAIL insufficient_privilege\n";
					sendAll(sock, resp.c_str(), resp.size());
					continue;
				}

                std::unordered_map<std::string, User>::iterator it2 = g_users.find(targetUser);
                if (it2 == g_users.end()) {
                    std::string resp = "ADMIN_FAIL mute_user_not_found\n";
                    sendAll(sock, resp.c_str(), resp.size());
                } else {
                    it2->second.muted = true;
                    std::string resp = "ADMIN_OK mute\n";
                    sendAll(sock, resp.c_str(), resp.size());
                }
            }
            else if (sub == "unmute") {
				std::string targetUser;
				iss >> targetUser;

				Role targetRole;
				{
					std::lock_guard<std::mutex> lock(g_mutex);
					targetRole = getUserRoleUnsafeNoLock(targetUser);
				}

				if (!canOperatorActOn(myRole, targetRole)) {
					std::string resp = "ADMIN_FAIL insufficient_privilege\n";
					sendAll(sock, resp.c_str(), resp.size());
					continue;
				}

                std::unordered_map<std::string, User>::iterator it2 = g_users.find(targetUser);
                if (it2 == g_users.end()) {
                    std::string resp = "ADMIN_FAIL unmute_user_not_found\n";
                    sendAll(sock, resp.c_str(), resp.size());
                } else {
                    it2->second.muted = false;
                    std::string resp = "ADMIN_OK unmute\n";
                    sendAll(sock, resp.c_str(), resp.size());
                }
            }
			else if (sub == "ban") {
				std::string targetUser;
				iss >> targetUser;

				Role targetRole;
				{
					std::lock_guard<std::mutex> lock(g_mutex);
					targetRole = getUserRoleUnsafeNoLock(targetUser);
				}

				if (!canOperatorActOn(myRole, targetRole)) {
					std::string resp = "ADMIN_FAIL insufficient_privilege\n";
					sendAll(sock, resp.c_str(), resp.size());
					continue;
				}

				std::unordered_map<std::string, User>::iterator it2 = g_users.find(targetUser);
				if (it2 == g_users.end()) {
					std::string resp = "ADMIN_FAIL ban_user_not_found\n";
					sendAll(sock, resp.c_str(), resp.size());
				} else {
					it2->second.banned = true;

					SOCKET targetSock = findClientByCallsign(targetUser);
					if (targetSock != INVALID_SOCKET) {
						std::string msg = "ADMIN_INFO banned_by_admin\n";
						sendAll(targetSock, msg.c_str(), msg.size());
						closeSocket(targetSock);
						cleanupClient(targetSock);
					}

					std::string resp = "ADMIN_OK ban\n";
					sendAll(sock, resp.c_str(), resp.size());
				}
			}
			else if (sub == "unban") {
				std::string targetUser;
				iss >> targetUser;

				Role targetRole;
				{
					std::lock_guard<std::mutex> lock(g_mutex);
					targetRole = getUserRoleUnsafeNoLock(targetUser);
				}

				if (!canOperatorActOn(myRole, targetRole)) {
					std::string resp = "ADMIN_FAIL insufficient_privilege\n";
					sendAll(sock, resp.c_str(), resp.size());
					continue;
				}

				std::unordered_map<std::string, User>::iterator it2 = g_users.find(targetUser);
				if (it2 == g_users.end()) {
					std::string resp = "ADMIN_FAIL unban_user_not_found\n";
					sendAll(sock, resp.c_str(), resp.size());
				} else {
					it2->second.banned = false;
					std::string resp = "ADMIN_OK unban\n";
					sendAll(sock, resp.c_str(), resp.size());
				}
			}
			else if (sub == "add_user") {
				std::string newUser, newPass;
				iss >> newUser >> newPass;

				if (newUser.empty() || newPass.empty()) {
					std::string resp = "ADMIN_FAIL add_user_missing_args\n";
					sendAll(sock, resp.c_str(), resp.size());
				} else {
					bool ok = false;

					{
						std::lock_guard<std::mutex> lock(g_mutex);

						if (g_users.find(newUser) != g_users.end()) {
							std::string resp = "ADMIN_FAIL add_user_exists\n";
							sendAll(sock, resp.c_str(), resp.size());
						} else {
							User u;
							u.callsign = newUser;
							u.password = newPass;
							u.muted    = false;
							u.banned   = false;
							u.priority = 0;

							g_users[newUser] = u;

							std::string resp = "ADMIN_OK add_user\n";
							sendAll(sock, resp.c_str(), resp.size());
							ok = true;
						}
					}

					if (ok) {
						saveConfig("server.json");
					}
				}
			} else if (sub == "remove_user") {
				std::string target;
				iss >> target;

				if (target.empty()) {
					std::string resp = "ADMIN_FAIL remove_user_missing_args\n";
					sendAll(sock, resp.c_str(), resp.size());
				} else {
					bool ok = false;

					{
						std::lock_guard<std::mutex> lock(g_mutex);

						auto it = g_users.find(target);
						if (it == g_users.end()) {
							std::string resp = "ADMIN_FAIL remove_user_not_found\n";
							sendAll(sock, resp.c_str(), resp.size());
						} else {
							SOCKET s = findClientByCallsign(target);
							if (s != INVALID_SOCKET) {
								std::string msg = "ADMIN_INFO removed_by_admin\n";
								sendAll(s, msg.c_str(), msg.size());
								closeSocket(s);
								cleanupClient(s);
							}

							g_users.erase(it);

							std::string resp = "ADMIN_OK remove_user\n";
							sendAll(sock, resp.c_str(), resp.size());
							ok = true;
						}
					}

					if (ok) {
						saveConfig("server.json");
					}
				}
			} else if (sub == "set_admin") {
				std::string targetUser;
				int flag = 0;
				iss >> targetUser >> flag;

				if (targetUser.empty()) {
					std::string resp = "ADMIN_FAIL set_admin_missing_args\n";
					sendAll(sock, resp.c_str(), resp.size());
				} else {
					bool ok = false;

					{
						std::lock_guard<std::mutex> lock(g_mutex);
						std::unordered_map<std::string, User>::iterator it2 = g_users.find(targetUser);
						if (it2 == g_users.end()) {
							std::string resp = "ADMIN_FAIL set_admin_user_not_found\n";
							sendAll(sock, resp.c_str(), resp.size());
						} else {
							std::string resp = "ADMIN_OK set_admin\n";
							sendAll(sock, resp.c_str(), resp.size());
							ok = true;
						}
					}

					if (ok) {
						saveConfig("server.json");
					}
				}
			} else if (sub == "set_pass") {
				std::string targetUser;
				std::string newPass;
				iss >> targetUser >> newPass;

				if (targetUser.empty() || newPass.empty()) {
					std::string resp = "ADMIN_FAIL set_pass_missing_args\n";
					sendAll(sock, resp.c_str(), resp.size());
				} else {
					bool ok = false;

					{
						std::lock_guard<std::mutex> lock(g_mutex);
						std::unordered_map<std::string, User>::iterator it2 = g_users.find(targetUser);
						if (it2 == g_users.end()) {
							std::string resp = "ADMIN_FAIL set_pass_user_not_found\n";
							sendAll(sock, resp.c_str(), resp.size());
						} else {
							it2->second.password = newPass;
							std::string resp = "ADMIN_OK set_pass\n";
							sendAll(sock, resp.c_str(), resp.size());
							ok = true;
						}
					}

					if (ok) {
						saveConfig("server.json");
					}
				}
			} else if (sub == "add_tg") {
				std::string targetUser;
				std::string tg;
				iss >> targetUser >> tg;

				if (targetUser.empty() || tg.empty()) {
					std::string resp = "ADMIN_FAIL add_tg_missing_args\n";
					sendAll(sock, resp.c_str(), resp.size());
				} else {
					bool ok = false;

					{
						std::lock_guard<std::mutex> lock(g_mutex);
						std::unordered_map<std::string, User>::iterator it2 = g_users.find(targetUser);
						if (it2 == g_users.end()) {
							std::string resp = "ADMIN_FAIL add_tg_user_not_found\n";
							sendAll(sock, resp.c_str(), resp.size());
						} else {
							it2->second.talkgroups.insert(tg);

							TalkgroupInfo info;
							info.name = tg;
							info.mode = TalkgroupMode::PUBLIC;
							g_knownTalkgroups[tg] = info;

							g_talkgroups[tg] = TalkgroupState();

							std::string resp = "ADMIN_OK add_talkgroup\n";
							sendAll(sock, resp.c_str(), resp.size());
							ok = true;
						}
					}

					if (ok) {
						saveConfig("server.json");
					}
				}
			} else if (sub == "drop_tg") {
				std::string targetUser;
				std::string tg;
				iss >> targetUser >> tg;

				if (targetUser.empty() || tg.empty()) {
					std::string resp = "ADMIN_FAIL drop_tg_missing_args\n";
					sendAll(sock, resp.c_str(), resp.size());
				} else {
					bool ok = false;

					{
						std::lock_guard<std::mutex> lock(g_mutex);
						std::unordered_map<std::string, User>::iterator it2 = g_users.find(targetUser);
						if (it2 == g_users.end()) {
							std::string resp = "ADMIN_FAIL drop_tg_user_not_found\n";
							sendAll(sock, resp.c_str(), resp.size());
						} else {
							std::unordered_set<std::string>::iterator tgIt =
								it2->second.talkgroups.find(tg);
							if (tgIt == it2->second.talkgroups.end()) {
								std::string resp = "ADMIN_FAIL drop_tg_not_in_user\n";
								sendAll(sock, resp.c_str(), resp.size());
							} else {
								it2->second.talkgroups.erase(tgIt);
								std::string resp = "ADMIN_OK drop_talkgroup\n";
								sendAll(sock, resp.c_str(), resp.size());
								ok = true;
							}
						}
					}

					if (ok) {
						saveConfig("server.json");
					}
				}
			} else if (sub == "list_users") {
                std::ostringstream oss;
                oss << "ADMIN_USERS ";
                bool first = true;
                {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    std::unordered_map<std::string, User>::iterator it;
                    for (it = g_users.begin(); it != g_users.end(); ++it) {
                        if (!first) oss << ",";
                        first = false;
						oss << it->first;
						if (it->second.muted)   oss << "(muted)";
						if (it->second.banned)  oss << "(banned)";
                    }
                }
                oss << "\n";
                std::string resp = oss.str();
                sendAll(sock, resp.c_str(), resp.size());
            }
            else if (sub == "list_tgs") {
                std::ostringstream oss;
                oss << "ADMIN_TGS ";
                bool first = true;
                {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    std::unordered_set<std::string>::iterator it;
					for (const auto& kv : g_knownTalkgroups) {
						if (!first) oss << ",";
						first = false;
						oss << kv.second.name;
					}
                }
                oss << "\n";
                std::string resp = oss.str();
                sendAll(sock, resp.c_str(), resp.size());
            } else if (sub == "last_heard") {
                std::ostringstream oss;
                oss << "ADMIN_LASTHEARD ";

                {
                    std::lock_guard<std::mutex> lhLock(g_lastHeardMutex);
                    bool first = true;
                    for (const auto &kv : g_lastHeard) {
                        const std::string &cs       = kv.first;
                        const LastHeardInfo &info   = kv.second;
                        std::string tstr = formatTimeLocal(info.when);

                        if (!first) oss << ",";
                        first = false;

                        oss << cs << "@" << info.talkgroup << ":" << tstr;
                    }
                }

                oss << "\n";
                std::string resp = oss.str();
                sendAll(sock, resp.c_str(), resp.size());
            } else {
                std::string resp = "ADMIN_FAIL unknown_subcommand\n";
                sendAll(sock, resp.c_str(), resp.size());
            }
        }
        else {
            LOG_WARN("Unknown command from client: %s\n", line.c_str());
        }
    }

    cleanupClient(sock);
    closeSocket(sock);
}

int main() {
	title();

    if (!loadConfig("server.json")) {
        LOG_ERROR("Config load failed, exiting.\n");
        return 1;
    }

	compilePeerRules();
	for (const auto& pcfg : g_peerCfg) {
		std::thread(peerOutboundThread, pcfg).detach();
	}

    initSockets();

#if USE_OPENSSL
	initHttpsContextIfEnabled();
#endif

    SOCKET serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock == INVALID_SOCKET) {
        LOG_ERROR("Failed to create socket\n");
        cleanupSockets();
        return 1;
    }

    int opt = 1;
    setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

	int flag = 1;
	setsockopt(serverSock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_server_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        LOG_ERROR("Bind failed\n");
        closeSocket(serverSock);
        cleanupSockets();
        return 1;
    }

    if (listen(serverSock, 16) == SOCKET_ERROR) {
        LOG_ERROR("Listen failed\n");
        closeSocket(serverSock);
        cleanupSockets();
        return 1;
    }

    LOG_OK("Server listening on port %d\n", g_server_port);

	std::thread timeThread;
	std::thread announceThread;
	std::thread weatherThread;

	bool needAnnouncePump = g_timeCfg.enabled || g_weatherCfg.enabled;

	if (g_timeCfg.enabled) {
		g_timeThreadRunning = true;
		timeThread = std::thread(timeAnnounceThreadFunc);
	}

	if (g_weatherCfg.enabled) {
		g_weatherThreadRunning = true;
		weatherThread = std::thread(weatherAnnounceThreadFunc);
	}

	if (needAnnouncePump) {
		g_announcePumpRunning = true;
		announceThread = std::thread(announcePumpThreadFunc);
	}

    std::vector<std::thread> threads;

    std::thread httpThread(httpServerThread);
    httpThread.detach();

#if USE_OPENSSL
	if (g_https_ctx && g_https_port > 0) {
		std::thread httpsThread(httpsServerThread);
		httpsThread.detach();
	}
#endif

	while (g_running) {
		sockaddr_in clientAddr;
		socklen_t clen = sizeof(clientAddr);
		SOCKET clientSock = accept(serverSock, (sockaddr*)&clientAddr, &clen);
		if (clientSock == INVALID_SOCKET) {
			break;
		}

		int flag = 1;
		setsockopt(clientSock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));

		threads.push_back(std::thread(handleClient, clientSock));
	}

    g_running = false;
    for (size_t i = 0; i < threads.size(); ++i) {
        if (threads[i].joinable()) threads[i].join();
    }

	g_timeThreadRunning    = false;
	g_weatherThreadRunning = false;
	g_announcePumpRunning  = false;

	if (timeThread.joinable())     timeThread.join();
	if (weatherThread.joinable())  weatherThread.join();
	if (announceThread.joinable()) announceThread.join();

    closeSocket(serverSock);

#if USE_OPENSSL
	if (g_https_ctx) {
		SSL_CTX_free(g_https_ctx);
		g_https_ctx = nullptr;
	}
#endif

    cleanupSockets();
    return 0;
}
