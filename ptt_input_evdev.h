#pragma once

#include <string>

typedef void (*PttInputCallback)(bool down);

bool startEvdevPttInput(const std::string& devicePath, int keyCode, PttInputCallback cb);
void stopEvdevPttInput();
