package org.zfm.client;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;

import org.libsdl.app.SDLActivity;

public class MainActivity extends SDLActivity {

    private static final int REQ_AUDIO = 1001;

    private boolean startedSDL = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        if (needsAudioPermission()) {
            requestPermissions(new String[]{Manifest.permission.RECORD_AUDIO}, REQ_AUDIO);
            return;
        }
        startedSDL = true;
        super.onCreate(savedInstanceState);
    }

    private boolean needsAudioPermission() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
                && checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED;
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);

        if (requestCode == REQ_AUDIO) {
            if (!needsAudioPermission() && !startedSDL) {
                recreate();
            }
        }
    }

    @Override
    protected String[] getLibraries() {
        return new String[]{
                "SDL2",
                "SDL2_ttf",
                "main"
        };
    }
}
