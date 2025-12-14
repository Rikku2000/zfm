#include "ptt_input_evdev.h"

#if defined(__linux__) && !defined(_WIN32)
#include <atomic>
#include <thread>
#include <fcntl.h>
#include <unistd.h>
#include <linux/input.h>
#include <sys/select.h>
#include <cstring>

static std::atomic<bool> g_evdevRun(false);
static std::thread g_evdevThread;
static int g_evdevFd = -1;
static int g_evKey = 0;
static PttInputCallback g_cb = nullptr;

static void evdevLoop()
{
    while (g_evdevRun.load()) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(g_evdevFd, &fds);

        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200 * 1000;

        int rv = select(g_evdevFd + 1, &fds, nullptr, nullptr, &tv);
        if (rv <= 0) continue;
        if (!FD_ISSET(g_evdevFd, &fds)) continue;

        input_event ev;
        ssize_t r = read(g_evdevFd, &ev, sizeof(ev));
        if (r != (ssize_t)sizeof(ev)) continue;

        if (ev.type == EV_KEY && ev.code == g_evKey) {
            bool down = (ev.value != 0);
            if (g_cb) g_cb(down);
        }
    }
}

bool startEvdevPttInput(const std::string& devicePath, int keyCode, PttInputCallback cb)
{
    stopEvdevPttInput();

    int fd = open(devicePath.c_str(), O_RDONLY | O_NONBLOCK);
    if (fd < 0) return false;

    g_evdevFd = fd;
    g_evKey = keyCode;
    g_cb = cb;
    g_evdevRun = true;
    g_evdevThread = std::thread(evdevLoop);
    return true;
}

void stopEvdevPttInput()
{
    g_evdevRun = false;
    if (g_evdevThread.joinable()) g_evdevThread.join();
    if (g_evdevFd >= 0) { close(g_evdevFd); g_evdevFd = -1; }
    g_cb = nullptr;
    g_evKey = 0;
}

#else
bool startEvdevPttInput(const std::string&, int, PttInputCallback) { return false; }
void stopEvdevPttInput() {}
#endif
