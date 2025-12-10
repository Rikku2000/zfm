CXX := g++
CC  := gcc

CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -pthread
CFLAGS   := -O2 -Wall -Wextra

PORTAUDIO_LIBS := -lportaudio

CM108_LIBS := -ludev

SDL2_CFLAGS := $(shell sdl2-config --cflags)
SDL2_LIBS   := $(shell sdl2-config --libs) -lSDL2_ttf

LDFLAGS_COMMON      := -pthread
LDFLAGS_SERVER      := $(LDFLAGS_COMMON)
LDFLAGS_CLIENT      := $(LDFLAGS_COMMON) $(PORTAUDIO_LIBS) $(CM108_LIBS)
LDFLAGS_CLIENT_GUI  := $(LDFLAGS_COMMON) $(PORTAUDIO_LIBS) $(CM108_LIBS) $(SDL2_LIBS)

ALL_TARGETS := server client client_gui

all: $(ALL_TARGETS)

server: server.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS_SERVER)

server.o: server.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

client: client.o cm108.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS_CLIENT)

client.o: client.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

client_gui: client_gui.o cm108.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS_CLIENT_GUI)

client_gui.o: client_gui.cpp client.cpp
	$(CXX) $(CXXFLAGS) -DGUI $(SDL2_CFLAGS) -c $< -o $@

cm108.o: cm108.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f *.o $(ALL_TARGETS)
