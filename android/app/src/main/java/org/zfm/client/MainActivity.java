package org.zfm.client;

import org.libsdl.app.SDLActivity;

public class MainActivity extends SDLActivity
{
    @Override
    protected String[] getLibraries() {
        return new String[]{
            "SDL2",
            "SDL2_ttf",
            "main"
        };
    }
}
