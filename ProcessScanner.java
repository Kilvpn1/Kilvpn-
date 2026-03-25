package com.zerosec.agent.scanner;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.util.Log;

import com.zerosec.agent.model.Finding;
import com.zerosec.agent.shizuku.ShizukuHelper;
import com.zerosec.agent.shizuku.ShizukuUserService;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ProcessScanner {

    private static final String TAG = "ZeroSec.ProcessScanner";

    // Processos legítimos do sistema Android — não geram alertas
    private static final List<String> SYSTEM_PROCESSES = Arrays.asList(
            "system_server", "zygote", "zygote64", "surfaceflinger",
            "servicemanager", "hwservicemanager", "vold", "netd",
            "lmkd", "logd", "installd", "healthd", "storaged",
            "adbd", "init", "ueventd", "sh", "media.codec",
            "media.extractor", "android.hardware", "vendor."
    );

    private final Context context;

    public ProcessScanner(Context context) {
        this.context = context;
    }

    public List<Finding> scan() {
        List<Finding> findings = new ArrayList<>();

        findings.addAll(scanRunningProcesses());
        findings.addAll(scanRootProcesses());
        findings.addAll(scanZombieProcesses());

        return findings;
    }

    private List<Finding> scanRunningProcesses() {
        List<Finding> findings = new ArrayList<>();

        try {
            ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
            List<ActivityManager.RunningAppProcessInfo> procs = am.getRunningAppProcesses();

            if (procs == null) return findings;

            PackageManager pm = context.getPackageManager();
            List<String> suspicious = new ArrayList<>();

            for (ActivityManager.RunningAppProcessInfo proc : procs) {
                if (proc.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE
                        || proc.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_SERVICE) {

                    // Verifica se é app de terceiro rodando serviço em background
                    try {
                        ApplicationInfo info = pm.getApplicationInfo(proc.processName.split(":")[0], 0);
                        boolean isSystem = (info.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                        boolean isUpdatedSystem = (info.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;

                        if (!isSystem && !isUpdatedSystem) {
                            // App de terceiro com serviço ativo
                            String pkgName = proc.processName.split(":")[0];
                            if (!pkgName.startsWith("com.google") && !pkgName.startsWith("com.android")) {
                                suspicious.add(pkgName + " (PID: " + proc.pid + ")");
                            }
                        }
                    } catch (PackageManager.NameNotFoundException ignored) {}
                }
            }

            if (suspicious.size() > 3) {
                Map<String, Object> details = new HashMap<>();
                details.put("processes", suspicious);
                details.put("count", suspicious.size());

                Finding f = new Finding(
                        Finding.Category.process,
                        Finding.Severity.medium,
                        "Múltiplos serviços de terceiros em background",
                        suspicious.size() + " apps de terceiros mantêm serviços ativos em background. " +
                                "Verifique se todos são legítimos.",
                        false
                );
                f.details = details;
                findings.add(f);
            }

        } catch (Exception e) {
            Log.e(TAG, "Erro ao escanear processos", e);
        }

        return findings;
    }

    private List<Finding> scanRootProcesses() {
        List<Finding> findings = new ArrayList<>();

        if (!ShizukuHelper.isAvailable() || !ShizukuHelper.hasPermission()) {
            return findings;
        }

        String psOutput = ShizukuUserService.executeReadOnlyCommand("ps -A -o USER,PID,NAME");
        if (psOutput == null || psOutput.isEmpty() || psOutput.equals("BLOCKED")) {
            return findings;
        }

        List<Map<String, String>> rootProcs = new ArrayList<>();

        for (String line : psOutput.split("\n")) {
            String[] parts = line.trim().split("\\s+");
            if (parts.length < 3) continue;

            String user = parts[0];
            String pid = parts[1];
            String name = parts[parts.length - 1];

            if ("root".equals(user) || "0".equals(user)) {
                boolean isSystemProc = false;
                for (String sys : SYSTEM_PROCESSES) {
                    if (name.contains(sys)) {
                        isSystemProc = true;
                        break;
                    }
                }

                if (!isSystemProc && !name.startsWith("[")) {
                    Map<String, String> proc = new HashMap<>();
                    proc.put("pid", pid);
                    proc.put("name", name);
                    proc.put("user", user);
                    rootProcs.add(proc);
                }
            }
        }

        if (!rootProcs.isEmpty()) {
            Map<String, Object> details = new HashMap<>();
            details.put("root_processes", rootProcs);
            details.put("count", rootProcs.size());

            Finding f = new Finding(
                    Finding.Category.process,
                    Finding.Severity.high,
                    rootProcs.size() + " processo(s) root não identificado(s)",
                    "Processos rodando como root que não constam na lista de processos legítimos do sistema. " +
                            "Pode indicar comprometimento ou escalada de privilégios.",
                    true
            );
            f.details = details;
            findings.add(f);
        }

        return findings;
    }

    private List<Finding> scanZombieProcesses() {
        List<Finding> findings = new ArrayList<>();

        if (!ShizukuHelper.isAvailable() || !ShizukuHelper.hasPermission()) {
            return findings;
        }

        String psOutput = ShizukuUserService.executeReadOnlyCommand("ps -A -o STAT,PID,NAME");
        if (psOutput == null || psOutput.isEmpty()) return findings;

        List<String> zombies = new ArrayList<>();
        for (String line : psOutput.split("\n")) {
            if (line.trim().startsWith("Z")) {
                zombies.add(line.trim());
            }
        }

        if (zombies.size() > 5) {
            Map<String, Object> details = new HashMap<>();
            details.put("zombie_count", zombies.size());
            details.put("sample", zombies.subList(0, Math.min(3, zombies.size())));

            Finding f = new Finding(
                    Finding.Category.process,
                    Finding.Severity.low,
                    zombies.size() + " processos zumbi detectados",
                    "Processos zumbi em excesso podem indicar falhas no gerenciamento de processos ou comportamento anômalo de apps.",
                    false
            );
            f.details = details;
            findings.add(f);
        }

        return findings;
    }
}
