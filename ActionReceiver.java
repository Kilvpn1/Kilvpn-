package com.zerosec.agent.receiver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.zerosec.agent.service.ZeroSecService;

/**
 * ActionReceiver — Recebe aprovação/negação de ações direto da notificação.
 * O usuário toca em "Autorizar" ou "Negar" na notificação e
 * este receiver encaminha a decisão para o ZeroSecService.
 */
public class ActionReceiver extends BroadcastReceiver {

    private static final String TAG = "ZeroSec.ActionReceiver";

    public static final String ACTION_APPROVE = "com.zerosec.action.APPROVE";
    public static final String ACTION_DENY = "com.zerosec.action.DENY";

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        String findingId = intent.getStringExtra("finding_id");

        if (findingId == null) {
            Log.w(TAG, "finding_id ausente na intent");
            return;
        }

        Intent serviceIntent = new Intent(context, ZeroSecService.class);

        if (ACTION_APPROVE.equals(action)) {
            Log.i(TAG, "Usuário APROVOU ação para finding: " + findingId);
            serviceIntent.putExtra("command", ZeroSecService.CMD_APPROVE_ACTION);
            serviceIntent.putExtra("request_id", findingId);

        } else if (ACTION_DENY.equals(action)) {
            Log.i(TAG, "Usuário NEGOU ação para finding: " + findingId);
            serviceIntent.putExtra("command", ZeroSecService.CMD_DENY_ACTION);
            serviceIntent.putExtra("request_id", findingId);
        }

        context.startForegroundService(serviceIntent);
    }
}
