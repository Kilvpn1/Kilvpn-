package com.zerosec.agent.receiver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

import com.zerosec.agent.service.ZeroSecService;

public class BootReceiver extends BroadcastReceiver {

    private static final String TAG = "ZeroSec.BootReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            Log.i(TAG, "Boot detectado — iniciando ZeroSecService");

            Intent serviceIntent = new Intent(context, ZeroSecService.class);
            context.startForegroundService(serviceIntent);
        }
    }
}
