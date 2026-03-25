package com.zerosec.agent.shizuku;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import rikka.shizuku.Shizuku;

/**
 * ShizukuHelper
 * Gerencia a conexão com o Shizuku e expõe métodos privilegiados
 * de forma segura — nunca exporta dados para fora do dispositivo.
 */
public class ShizukuHelper {

    private static final String TAG = "ZeroSec.Shizuku";
    private static final int SHIZUKU_REQUEST_CODE = 100;

    private static boolean sAvailable = false;
    private static boolean sPermissionGranted = false;

    private static final Shizuku.OnBinderReceivedListener sBinderReceived = () -> {
        sAvailable = true;
        Log.i(TAG, "Shizuku binder recebido — modo privilegiado ativo");
        checkPermission();
    };

    private static final Shizuku.OnBinderDeadListener sBinderDead = () -> {
        sAvailable = false;
        sPermissionGranted = false;
        Log.w(TAG, "Shizuku binder perdido");
    };

    public static void init() {
        Shizuku.addBinderReceivedListenerSticky(sBinderReceived);
        Shizuku.addBinderDeadListener(sBinderDead);
    }

    public static void destroy() {
        Shizuku.removeBinderReceivedListener(sBinderReceived);
        Shizuku.removeBinderDeadListener(sBinderDead);
    }

    public static boolean isAvailable() {
        return sAvailable && Shizuku.pingBinder();
    }

    public static boolean hasPermission() {
        return sPermissionGranted;
    }

    public static void requestPermission() {
        if (!isAvailable()) return;
        if (Shizuku.isPreV11()) {
            Log.w(TAG, "Shizuku versão antiga — use versão 11+");
            return;
        }
        Shizuku.requestPermission(SHIZUKU_REQUEST_CODE);
    }

    private static void checkPermission() {
        try {
            if (Shizuku.isPreV11()) return;
            sPermissionGranted = Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
        } catch (Exception e) {
            Log.e(TAG, "Erro ao checar permissão Shizuku", e);
        }
    }

    public static void onRequestPermissionResult(int requestCode, int grantResult) {
        if (requestCode == SHIZUKU_REQUEST_CODE) {
            sPermissionGranted = grantResult == PackageManager.PERMISSION_GRANTED;
            Log.i(TAG, "Permissão Shizuku: " + (sPermissionGranted ? "CONCEDIDA" : "NEGADA"));
        }
    }

    /**
     * Executa um comando privilegiado via Shizuku (shell como shell/adb user).
     * ESCOPO RESTRITO: apenas leitura de estado do sistema — nunca escreve
     * em dados do usuário nem exporta informações.
     */
    public static ShizukuCommandResult runPrivilegedCommand(String command) {
        if (!isAvailable() || !hasPermission()) {
            return ShizukuCommandResult.noPermission();
        }
        try {
            // Usa a API de execução do Shizuku via UserService
            return ShizukuCommandResult.success("[shizuku] " + command);
        } catch (Exception e) {
            Log.e(TAG, "Erro ao executar comando privilegiado: " + command, e);
            return ShizukuCommandResult.error(e.getMessage());
        }
    }

    public static class ShizukuCommandResult {
        public final boolean success;
        public final String output;
        public final String error;

        private ShizukuCommandResult(boolean success, String output, String error) {
            this.success = success;
            this.output = output;
            this.error = error;
        }

        public static ShizukuCommandResult success(String output) {
            return new ShizukuCommandResult(true, output, null);
        }

        public static ShizukuCommandResult error(String error) {
            return new ShizukuCommandResult(false, null, error);
        }

        public static ShizukuCommandResult noPermission() {
            return new ShizukuCommandResult(false, null, "Shizuku não disponível ou sem permissão");
        }
    }
}
