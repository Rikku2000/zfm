#pragma once

#include <string>

struct ClientConfig;

bool initGpioPtt(const ClientConfig& cfg);
void setPtt(bool on);
void shutdownGpioPtt();

#ifdef PTT_HAL_IMPLEMENTATION

#include <cstdlib>
#include <cstring>
#include <sstream>
#include <fstream>
#include <cctype>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #define NOMINMAX
  #include <windows.h>
#else
  #include <unistd.h>
#endif

extern "C" int cm108_set_gpio_pin(char *name, int num, int state);

extern ClientConfig g_cfg;

#ifndef LOG_WARN
  #include <cstdio>
  #define LOG_WARN(...)  std::printf(__VA_ARGS__)
#endif
#ifndef LOG_INFO
  #include <cstdio>
  #define LOG_INFO(...)  std::printf(__VA_ARGS__)
#endif

#if !defined(_WIN32) && defined(__linux__)
  #define ZFM_LINUX 1
#else
  #define ZFM_LINUX 0
#endif

class IPttBackend {
public:
    virtual ~IPttBackend() {}
    virtual bool init(const ClientConfig& cfg, std::string& err) = 0;
    virtual void set(bool on) = 0;
    virtual void shutdown() = 0;
    virtual const char* name() const = 0;
};

static IPttBackend* g_pttBackend = 0;

static inline std::string _ptt_ltrim(const std::string& s) {
    size_t i = 0;
    while (i < s.size() && (s[i]==' ' || s[i]=='\t' || s[i]=='\r' || s[i]=='\n')) ++i;
    return s.substr(i);
}
static inline std::string _ptt_tolower(std::string s) {
    for (size_t i = 0; i < s.size(); ++i) {
        s[i] = (char)::tolower((unsigned char)s[i]);
    }
    return s;
}

static void _ptt_ParseCm108Command(const std::string& cmd, std::string& hiddev, int& pinOut)
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
            if (iss >> sval) pinOut = std::atoi(sval.c_str());
        }
    }

#if ZFM_LINUX
    if (hiddev.empty()) hiddev = "/dev/hidraw0";
#endif

    if (pinOut <= 0 || pinOut > 8) pinOut = 3;
}

static bool _ptt_ParseSerialCommand(const std::string& cmd,
                                   std::string& outPort,
                                   bool& outUseRts,
                                   bool& outActiveHigh)
{
    outPort.clear();
    outUseRts = true;
    outActiveHigh = true;

    std::string s = _ptt_ltrim(cmd);
    std::string sl = _ptt_tolower(s);
    if (sl.size() < 6) return false;
    if (sl.compare(0, 6, "serial") != 0) return false;

    std::istringstream iss(s);
    std::string head;
    iss >> head;

    std::string port;
    std::string line;
    iss >> port;
    iss >> line;

    if (!port.empty()) outPort = port;

    if (!line.empty()) {
        std::string ll = _ptt_tolower(line);
        if (ll == "dtr") outUseRts = false;
        else outUseRts = true;
    }

    std::string opt;
    while (iss >> opt) {
        std::string ol = _ptt_tolower(opt);
        if (ol == "active_low" || ol == "activelow" || ol == "invert" || ol == "inverted") {
            outActiveHigh = false;
        }
    }

    return true;
}

class PttShellBackend : public IPttBackend {
public:
    std::string onCmd, offCmd;

    bool init(const ClientConfig& cfg, std::string& err);
    void set(bool on) {
        const std::string& cmd = on ? onCmd : offCmd;
        if (!cmd.empty()) {
            int rc = std::system(cmd.c_str());
            (void)rc;
        }
    }
    void shutdown() {}
    const char* name() const { return "shell"; }
};

class PttCm108Backend : public IPttBackend {
public:
    std::string dev;
    int pin;

    PttCm108Backend() : pin(3) {}

    bool init(const ClientConfig& cfg, std::string& err);
    void set(bool on) {
        int state = on ? 1 : 0;
#if ZFM_LINUX
        const char* d = dev.empty() ? 0 : dev.c_str();
        int rc = cm108_set_gpio_pin((char*)d, pin, state);
        if (rc != 0) {
            LOG_WARN("PTT: cm108_set_gpio_pin failed (rc=%d, dev=%s, pin=%d)\n",
                     rc, (d ? d : "auto"), pin);
        }
#else
        int rc = cm108_set_gpio_pin(0, pin, state);
        if (rc != 0) {
            LOG_WARN("PTT: cm108_set_gpio_pin failed (rc=%d, pin=%d)\n", rc, pin);
        }
#endif
    }
    void shutdown() {}
    const char* name() const { return "cm108"; }
};

#ifdef _WIN32
class PttSerialWinBackend : public IPttBackend {
public:
    HANDLE hComm;
    bool useRTS;
    bool activeHigh;

    PttSerialWinBackend() : hComm(INVALID_HANDLE_VALUE), useRTS(true), activeHigh(true) {}

    bool init(const ClientConfig& cfg, std::string& err);
    void set(bool on) {
        if (hComm == INVALID_HANDLE_VALUE) return;
        bool effective = activeHigh ? on : !on;
        if (useRTS) EscapeCommFunction(hComm, effective ? SETRTS : CLRRTS);
        else        EscapeCommFunction(hComm, effective ? SETDTR : CLRDTR);
    }
    void shutdown() {
        if (hComm != INVALID_HANDLE_VALUE) {
            set(false);
            CloseHandle(hComm);
            hComm = INVALID_HANDLE_VALUE;
        }
    }
    const char* name() const { return "serial_rtsdtr_win"; }
};
#endif

#if ZFM_LINUX
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>

class PttSerialLinuxBackend : public IPttBackend {
public:
    int fd;
    bool useRTS;
    bool activeHigh;

    PttSerialLinuxBackend() : fd(-1), useRTS(true), activeHigh(true) {}

    bool init(const ClientConfig& cfg, std::string& err);
    void set(bool on) {
        if (fd < 0) return;

        bool effective = activeHigh ? on : !on;

        int status = 0;
        if (ioctl(fd, TIOCMGET, &status) != 0) return;

        if (useRTS) {
            if (effective) status |= TIOCM_RTS;
            else           status &= ~TIOCM_RTS;
        } else {
            if (effective) status |= TIOCM_DTR;
            else           status &= ~TIOCM_DTR;
        }

        ioctl(fd, TIOCMSET, &status);
    }
    void shutdown() {
        if (fd >= 0) {
            set(false);
            close(fd);
            fd = -1;
        }
    }
    const char* name() const { return "serial_rtsdtr_linux"; }
};

static bool _ptt_gpioExport(int pin) {
    std::ofstream ofs("/sys/class/gpio/export");
    if (!ofs.is_open()) return false;
    ofs << pin;
    return true;
}
static bool _ptt_gpioUnexport(int pin) {
    std::ofstream ofs("/sys/class/gpio/unexport");
    if (!ofs.is_open()) return false;
    ofs << pin;
    return true;
}
static bool _ptt_gpioSetDirection(int pin, const std::string& dir) {
    std::ostringstream path;
    path << "/sys/class/gpio/gpio" << pin << "/direction";
    std::ofstream ofs(path.str().c_str());
    if (!ofs.is_open()) return false;
    ofs << dir;
    return true;
}
static bool _ptt_gpioSetValue(int pin, int value) {
    std::ostringstream path;
    path << "/sys/class/gpio/gpio" << pin << "/value";
    std::ofstream ofs(path.str().c_str());
    if (!ofs.is_open()) return false;
    ofs << value;
    return true;
}

class PttGpioSysfsBackend : public IPttBackend {
public:
    int  pin;
    bool activeHigh;
    bool configured;

    PttGpioSysfsBackend() : pin(-1), activeHigh(true), configured(false) {}

    bool init(const ClientConfig& cfg, std::string& err);
    void set(bool on) {
        if (!configured) return;
        int v = activeHigh ? (on ? 1 : 0) : (on ? 0 : 1);
        _ptt_gpioSetValue(pin, v);
    }
    void shutdown() {
        if (!configured) return;
        set(false);
        _ptt_gpioUnexport(pin);
        configured = false;
    }
    const char* name() const { return "gpio_sysfs"; }
};
#endif

inline bool PttShellBackend::init(const ClientConfig& cfg, std::string& err) {
    (void)err;
    onCmd  = cfg.ptt_cmd_on;
    offCmd = cfg.ptt_cmd_off;
    return true;
}

inline bool PttCm108Backend::init(const ClientConfig& cfg, std::string& err) {
    (void)err;
    _ptt_ParseCm108Command(cfg.ptt_cmd_on, dev, pin);
    return true;
}

#ifdef _WIN32
inline bool PttSerialWinBackend::init(const ClientConfig& cfg, std::string& err)
{
    std::string port;
    if (!_ptt_ParseSerialCommand(cfg.ptt_cmd_on, port, useRTS, activeHigh)) {
        err = "serial backend selected but parse failed";
        return false;
    }
    if (port.empty()) {
        err = "serial: missing port (example: \"serial COM4 RTS\")";
        return false;
    }

    std::string openName = port;

    if (openName.compare(0, 4, "\\\\.\\") != 0) {
        if (openName.size() >= 4 && (openName[0]=='C' || openName[0]=='c')) {
            openName = "\\\\.\\" + openName;
        }
    }

    hComm = CreateFileA(openName.c_str(),
                        GENERIC_READ | GENERIC_WRITE,
                        0, 0, OPEN_EXISTING, 0, 0);

    if (hComm == INVALID_HANDLE_VALUE) {
        err = "failed to open serial port (check COM name and permissions)";
        return false;
    }

    set(false);

    LOG_INFO("PTT: Serial %s via %s (%s)\n",
             useRTS ? "RTS" : "DTR",
             openName.c_str(),
             activeHigh ? "active_high" : "active_low");
    return true;
}
#endif

#if ZFM_LINUX
inline bool PttSerialLinuxBackend::init(const ClientConfig& cfg, std::string& err)
{
    std::string port;
    if (!_ptt_ParseSerialCommand(cfg.ptt_cmd_on, port, useRTS, activeHigh)) {
        err = "serial backend selected but parse failed";
        return false;
    }
    if (port.empty()) {
        err = "serial: missing port (example: \"serial /dev/ttyUSB0 RTS\")";
        return false;
    }

    fd = open(port.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        err = "failed to open serial device (check path and permissions)";
        return false;
    }

    termios tio;
    if (tcgetattr(fd, &tio) == 0) {
        cfmakeraw(&tio);
        tcsetattr(fd, TCSANOW, &tio);
    }

    set(false);

    LOG_INFO("PTT: Serial %s via %s (%s)\n",
             useRTS ? "RTS" : "DTR",
             port.c_str(),
             activeHigh ? "active_high" : "active_low");
    return true;
}

inline bool PttGpioSysfsBackend::init(const ClientConfig& cfg, std::string& err)
{
    pin        = cfg.gpio_ptt_pin;
    activeHigh = cfg.gpio_ptt_active_high;

    if (pin < 0) {
        err = "invalid GPIO pin";
        return false;
    }

    _ptt_gpioExport(pin);
    if (!_ptt_gpioSetDirection(pin, "out")) {
        err = "failed to set GPIO direction (need root or udev rules)";
        return false;
    }

    _ptt_gpioSetValue(pin, activeHigh ? 0 : 1);
    configured = true;

    LOG_INFO("PTT: GPIO sysfs pin=%d (%s)\n",
             pin, activeHigh ? "active_high" : "active_low");
    return true;
}
#endif

static IPttBackend* _ptt_MakeBackend(const ClientConfig& cfg)
{
    if (!cfg.ptt_cmd_on.empty() && cfg.ptt_cmd_on.find("cm108") != std::string::npos) {
        return new PttCm108Backend();
    }

    {
        std::string port;
        bool useRts = true;
        bool activeHigh = true;
        if (_ptt_ParseSerialCommand(cfg.ptt_cmd_on, port, useRts, activeHigh)) {
#ifdef _WIN32
            return new PttSerialWinBackend();
#else
  #if ZFM_LINUX
            return new PttSerialLinuxBackend();
  #else
            return 0;
  #endif
#endif
        }
    }

    if (!cfg.ptt_cmd_on.empty() || !cfg.ptt_cmd_off.empty()) {
        return new PttShellBackend();
    }

#if ZFM_LINUX
    return new PttGpioSysfsBackend();
#else
    return 0;
#endif
}

inline bool initGpioPtt(const ClientConfig& cfg)
{
    if (!cfg.gpio_ptt_enabled) {
        if (g_pttBackend) { g_pttBackend->shutdown(); delete g_pttBackend; g_pttBackend = 0; }
        return true;
    }

    if (g_pttBackend) { g_pttBackend->shutdown(); delete g_pttBackend; g_pttBackend = 0; }

    g_pttBackend = _ptt_MakeBackend(cfg);
    if (!g_pttBackend) {
        LOG_INFO("PTT: enabled but no backend available (provide ptt_cmd_on/off)\n");
        return true;
    }

    std::string err;
    if (!g_pttBackend->init(cfg, err)) {
        LOG_WARN("PTT init failed (%s): %s\n",
                 g_pttBackend->name(),
                 err.empty() ? "unknown error" : err.c_str());
        delete g_pttBackend;
        g_pttBackend = 0;
        return false;
    }

    LOG_INFO("PTT backend: %s\n", g_pttBackend->name());
    return true;
}

inline void setPtt(bool on)
{
    if (!g_cfg.gpio_ptt_enabled) return;
    if (g_pttBackend) g_pttBackend->set(on);
}

inline void shutdownGpioPtt()
{
    if (g_pttBackend) {
        g_pttBackend->set(false);
        g_pttBackend->shutdown();
        delete g_pttBackend;
        g_pttBackend = 0;
    }
}

#endif
