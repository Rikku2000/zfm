CXX ?= g++
CC  ?= gcc

BUILD_DIR ?= build

CXXFLAGS_COMMON := -std=c++17 -O2 -Wall -Wextra -pthread
CFLAGS_COMMON   := -O2 -Wall -Wextra

DEPFLAGS := -MMD -MP

UNAME_S := $(shell uname -s 2>/dev/null)

ifeq ($(OS),Windows_NT)
  PLATFORM := windows
else
  PLATFORM := posix
endif

PKG_CONFIG ?= pkg-config

PORTAUDIO_CFLAGS := $(shell $(PKG_CONFIG) --cflags portaudio-2.0 2>/dev/null)
PORTAUDIO_LIBS   := $(shell $(PKG_CONFIG) --libs   portaudio-2.0 2>/dev/null)
ifeq ($(strip $(PORTAUDIO_LIBS)),)
  PORTAUDIO_LIBS := -lportaudio
endif

SDL2_CFLAGS := $(shell sdl2-config --cflags 2>/dev/null)
SDL2_LIBS   := $(shell sdl2-config --libs 2>/dev/null)
SDL2_CFLAGS_PKG := $(shell $(PKG_CONFIG) --cflags sdl2 2>/dev/null)
SDL2_LIBS_PKG   := $(shell $(PKG_CONFIG) --libs   sdl2 2>/dev/null)
SDL2TTF_CFLAGS  := $(shell $(PKG_CONFIG) --cflags SDL2_ttf 2>/dev/null)
SDL2TTF_LIBS    := $(shell $(PKG_CONFIG) --libs   SDL2_ttf 2>/dev/null)

ifeq ($(strip $(SDL2_LIBS_PKG)),)
  SDL2_CFLAGS_FINAL := $(SDL2_CFLAGS)
  SDL2_LIBS_FINAL   := $(SDL2_LIBS)
else
  SDL2_CFLAGS_FINAL := $(SDL2_CFLAGS_PKG)
  SDL2_LIBS_FINAL   := $(SDL2_LIBS_PKG)
endif

ifeq ($(strip $(SDL2TTF_LIBS)),)
  SDL2TTF_LIBS := -lSDL2_ttf
endif

ifeq ($(PLATFORM),windows)
  CM108_CFLAGS := -D_WIN32
  CM108_LIBS   := -lsetupapi -lhid
else
  CM108_CFLAGS :=
  CM108_LIBS   := -ludev
endif

ifeq ($(PLATFORM),windows)
  SOCKET_LIBS := -lws2_32
else
  SOCKET_LIBS := -latomic
endif

CXXFLAGS := $(CXXFLAGS_COMMON) $(DEPFLAGS)
CFLAGS   := $(CFLAGS_COMMON)   $(DEPFLAGS)

CXXFLAGS_SERVER := $(CXXFLAGS)
CXXFLAGS_CLIENT := $(CXXFLAGS) $(PORTAUDIO_CFLAGS)
CXXFLAGS_GUI    := $(CXXFLAGS) -DGUI $(PORTAUDIO_CFLAGS) $(SDL2_CFLAGS_FINAL) $(SDL2TTF_CFLAGS)

LDLIBS_SERVER := $(SOCKET_LIBS)
LDLIBS_CLIENT := $(SOCKET_LIBS) $(PORTAUDIO_LIBS) $(CM108_LIBS)
LDLIBS_GUI    := $(SOCKET_LIBS) $(PORTAUDIO_LIBS) $(CM108_LIBS) $(SDL2_LIBS_FINAL) $(SDL2TTF_LIBS)

SRV_SRC := server.cpp
CLI_SRC := client.cpp
GUI_SRC := client_gui.cpp
CM108_SRC := cm108.c

ifeq ($(PLATFORM),posix)
  PTT_INPUT_SRC := ptt_input_evdev.cpp
  PTT_INPUT_OBJ := $(BUILD_DIR)/ptt_input_evdev.o
  PTT_INPUT_DEPS := $(PTT_INPUT_OBJ:.o=.d)
else
  PTT_INPUT_SRC :=
  PTT_INPUT_OBJ :=
  PTT_INPUT_DEPS :=
endif

SRV_OBJ := $(BUILD_DIR)/server.o
CLI_OBJ := $(BUILD_DIR)/client.o
GUI_OBJ := $(BUILD_DIR)/client_gui.o
CM108_OBJ := $(BUILD_DIR)/cm108.o

SRV_DEPS := $(SRV_OBJ:.o=.d)
CLI_DEPS := $(CLI_OBJ:.o=.d)
GUI_DEPS := $(GUI_OBJ:.o=.d)
CM108_DEPS := $(CM108_OBJ:.o=.d)

ALL_TARGETS := server client client_gui

.PHONY: all clean
all: $(ALL_TARGETS)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

server: $(SRV_OBJ)
	$(CXX) -o $@ $^ $(LDLIBS_SERVER)

client: $(CLI_OBJ) $(CM108_OBJ) $(PTT_INPUT_OBJ)
	$(CXX) -o $@ $^ $(LDLIBS_CLIENT)

client_gui: $(GUI_OBJ) $(CM108_OBJ) $(PTT_INPUT_OBJ)
	$(CXX) -o $@ $^ $(LDLIBS_GUI)

$(SRV_OBJ): $(SRV_SRC) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS_SERVER) -c $< -o $@

$(CLI_OBJ): $(CLI_SRC) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS_CLIENT) -c $< -o $@

$(GUI_OBJ): $(GUI_SRC) $(CLI_SRC) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS_GUI) -c $< -o $@

$(CM108_OBJ): $(CM108_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CM108_CFLAGS) -c $< -o $@

ifeq ($(PLATFORM),posix)
$(PTT_INPUT_OBJ): $(PTT_INPUT_SRC) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@
endif

clean:
	rm -rf $(BUILD_DIR) $(ALL_TARGETS)

-include $(SRV_DEPS) $(CLI_DEPS) $(GUI_DEPS) $(CM108_DEPS) $(PTT_INPUT_DEPS)
