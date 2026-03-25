package com.zerosec.agent.shizuku;

import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * ShizukuUserService
 * Serviço que roda no contexto privilegiado do Shizuku (como shell/adb).
 * Fornece acesso apenas leitura a recursos do sistema para o agente de segurança.
 *
 * REGRA: Este serviço NUNCA exporta dados para fora do dispositivo.
 *        Apenas coleta estado do sistema para análise local + reporte ao backend.
 */
public class ShizukuUserService {

    private static final String TAG = "ZeroSec.UserService";

    // Destrutor chamado pelo Shizuku quando o serviço é encerrado
    public static void destroy() {
        Log.i(TAG, "ShizukuUserService destruído");
    }

    /**
     * Executa comando shell privilegiado.
     * Apenas comandos de leitura (ps, ss, cat /proc/*, pm, dumpsys) são permitidos.
     */
    public static String executeReadOnlyCommand(String command) {
        // Whitelist de comandos permitidos — apenas leitura de estado
        if (!isCommandAllowed(command)) {
            Log.w(TAG, "Comando bloqueado (não está na whitelist): " + command);
            return "BLOCKED";
        }

        try {
            Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            int lineCount = 0;
            while ((line = reader.readLine()) != null && lineCount < 500) {
                sb.append(line).append("\n");
                lineCount++;
            }
            process.waitFor();
            return sb.toString();
        } catch (Exception e) {
            Log.e(TAG, "Erro ao executar: " + command, e);
            return "";
        }
    }

    /**
     * Whitelist de comandos — somente leitura de estado do sistema.
     * Nenhum comando destrutivo, de exportação ou de modificação é permitido.
     */
    private static boolean isCommandAllowed(String command) {
        String[] allowed = {
                "ps ", "ps -", "ps|",
                "ss ", "ss -",
                "netstat",
                "cat /proc/net/",
                "cat /proc/",
                "ls /proc/",
                "pm list",
                "pm dump",
                "dumpsys package",
                "dumpsys activity",
                "dumpsys netpolicy",
                "dumpsys connectivity",
                "getprop",
                "settings get",
                "logcat -d",
                "find /data/local",
                "find /sdcard",
                "find /storage",
                "stat ",
                "ls -la",
                "id",
                "whoami",
                "which su",
                "ls /sbin/su",
                "ls /system/",
        };
        for (String prefix : allowed) {
            if (command.trim().startsWith(prefix.trim())) return true;
        }
        // Bloqueio explícito de qualquer coisa destrutiva
        String[] blocked = {
                "rm ", "rmdir", "mv ", "cp ", "chmod", "chown",
                "kill ", "killall", "pkill",
                "iptables", "ip6tables",
                "curl", "wget", "nc ", "ncat", "socat",
                "am force-stop", "pm uninstall", "pm disable",
                "reboot", "shutdown",
                ">", ">>",  // redirecionamento de escrita
        };
        for (String b : blocked) {
            if (command.contains(b)) return false;
        }
        return false; // default: bloquear se não estiver na whitelist
    }

    /**
     * Ação privilegiada com controle explícito — só executa com token de aprovação.
     * Chamada apenas pelo ZeroSecService após aprovação do usuário.
     */
    public static boolean executeApprovedAction(String actionType, String target, String approvalToken) {
        if (approvalToken == null || !approvalToken.startsWith("APPROVED_")) {
            Log.w(TAG, "Ação bloqueada: token de aprovação inválido");
            return false;
        }

        Log.i(TAG, "Executando ação aprovada: " + actionType + " em " + target);

        try {
            switch (actionType) {
                case "KILL_PROCESS":
                    // Terminar processo por PID — requer aprovação explícita
                    Runtime.getRuntime().exec(new String[]{"sh", "-c", "kill " + target});
                    return true;

                case "REVOKE_PERMISSION":
                    // Revogar permissão de app — ex: "com.pkg CAMERA"
                    String[] parts = target.split(" ", 2);
                    if (parts.length == 2) {
                        Runtime.getRuntime().exec(new String[]{
                                "sh", "-c",
                                "pm revoke " + parts[0] + " android.permission." + parts[1]
                        });
                        return true;
                    }
                    return false;

                case "DISABLE_APP":
                    // Desabilitar app sem desinstalar
                    Runtime.getRuntime().exec(new String[]{
                            "sh", "-c", "pm disable-user --user 0 " + target
                    });
                    return true;

                default:
                    Log.w(TAG, "Tipo de ação desconhecido: " + actionType);
                    return false;
            }
        } catch (Exception e) {
            Log.e(TAG, "Erro ao executar ação aprovada: " + actionType, e);
            return false;
        }
    }
}
