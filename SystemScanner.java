package com.zerosec.agent.scanner;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import com.zerosec.agent.model.Finding;
import com.zerosec.agent.shizuku.ShizukuHelper;
import com.zerosec.agent.shizuku.ShizukuUserService;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class SystemScanner {

    private static final String TAG = "ZeroSec.SystemScanner";

    private final Context context;

    public SystemScanner(Context context) {
        this.context = context;
    }

    public List<Finding> scan() {
        List<Finding> findings = new ArrayList<>();

        findings.addAll(checkSecurityPatch());
        findings.addAll(checkVerifiedBoot());
        findings.addAll(checkEncryption());
        findings.addAll(checkDeveloperOptions());
        findings.addAll(checkRootIndicators());
        findings.addAll(checkUsbDebugging());
        findings.addAll(checkAccessibilityServices());
        findings.addAll(checkDeviceAdmin());

        return findings;
    }

    private List<Finding> checkSecurityPatch() {
        List<Finding> findings = new ArrayList<>();

        String patch = Build.VERSION.SECURITY_PATCH; // formato: "2026-03-01"
        if (patch == null || patch.isEmpty()) return findings;

        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
            Date patchDate = sdf.parse(patch);
            long daysOld = TimeUnit.MILLISECONDS.toDays(System.currentTimeMillis() - patchDate.getTime());

            if (daysOld > 60) {
                Map<String, Object> details = new HashMap<>();
                details.put("security_patch", patch);
                details.put("days_outdated", daysOld);
                details.put("android_version", Build.VERSION.RELEASE);
                details.put("recommendation", "Verifique atualizações em: Configurações > Sistema > Atualização");

                Finding f = new Finding(
                        Finding.Category.vulnerability,
                        daysOld > 180 ? Finding.Severity.high : Finding.Severity.medium,
                        "Patch de segurança desatualizado há " + daysOld + " dias",
                        "O dispositivo está sem atualização de segurança desde " + patch + ". " +
                                "Vulnerabilidades conhecidas podem estar expostas.",
                        daysOld > 180
                );
                f.details = details;
                findings.add(f);
            }
        } catch (ParseException e) {
            Log.w(TAG, "Não foi possível parsear data do patch: " + patch);
        }

        return findings;
    }

    private List<Finding> checkVerifiedBoot() {
        List<Finding> findings = new ArrayList<>();

        if (!ShizukuHelper.isAvailable()) return findings;

        String state = ShizukuUserService.executeReadOnlyCommand(
                "getprop ro.boot.verifiedbootstate").trim();

        if (state.isEmpty() || state.equals("BLOCKED")) {
            // Tenta via sistema
            state = ShizukuUserService.executeReadOnlyCommand(
                    "getprop ro.boot.flash.locked").trim();
        }

        if (!state.isEmpty() && !state.equals("green") && !state.equals("1")) {
            Map<String, Object> details = new HashMap<>();
            details.put("verified_boot_state", state);
            details.put("meaning", state.equals("orange") ? "Bootloader desbloqueado" :
                    state.equals("red") ? "Boot corrompido/não verificado" :
                            state.equals("yellow") ? "Chave customizada — pode ser legítimo" : "Estado desconhecido");
            details.put("risk", "Sistema operacional pode ter sido modificado");

            Finding f = new Finding(
                    Finding.Category.vulnerability,
                    "red".equals(state) ? Finding.Severity.critical : Finding.Severity.high,
                    "Verified Boot em estado não confiável: " + state,
                    "O Verified Boot do Android indica que o sistema pode ter sido modificado. " +
                            "Estado: " + state,
                    true
            );
            f.details = details;
            findings.add(f);
        }

        return findings;
    }

    private List<Finding> checkEncryption() {
        List<Finding> findings = new ArrayList<>();

        if (!ShizukuHelper.isAvailable()) return findings;

        String cryptoState = ShizukuUserService.executeReadOnlyCommand(
                "getprop ro.crypto.state").trim();
        String cryptoType = ShizukuUserService.executeReadOnlyCommand(
                "getprop ro.crypto.type").trim();

        if (!cryptoState.equals("encrypted") && !cryptoState.isEmpty()) {
            Map<String, Object> details = new HashMap<>();
            details.put("crypto_state", cryptoState);
            details.put("crypto_type", cryptoType);
            details.put("risk", "Dados acessíveis sem autenticação em caso de roubo");

            Finding f = new Finding(
                    Finding.Category.vulnerability,
                    Finding.Severity.high,
                    "Armazenamento não criptografado",
                    "O armazenamento do dispositivo não está criptografado. Em caso de roubo ou acesso físico, " +
                            "todos os dados são acessíveis.",
                    true
            );
            f.details = details;
            findings.add(f);
        }

        return findings;
    }

    private List<Finding> checkDeveloperOptions() {
        List<Finding> findings = new ArrayList<>();

        if (!ShizukuHelper.isAvailable()) return findings;

        String devOptions = ShizukuUserService.executeReadOnlyCommand(
                "settings get global development_settings_enabled").trim();

        if ("1".equals(devOptions)) {
            Map<String, Object> details = new HashMap<>();
            details.put("developer_options", "enabled");
            details.put("risk", "Expõe APIs de depuração que podem ser exploradas");
            details.put("recommendation", "Desativar em: Configurações > Sistema > Opções do Desenvolvedor");

            Finding f = new Finding(
                    Finding.Category.vulnerability,
                    Finding.Severity.medium,
                    "Opções do Desenvolvedor ativas",
                    "As Opções do Desenvolvedor estão habilitadas. Isso expõe APIs de depuração e reduz a superfície de segurança do dispositivo.",
                    false
            );
            f.details = details;
            findings.add(f);
        }

        return findings;
    }

    private List<Finding> checkRootIndicators() {
        List<Finding> findings = new ArrayList<>();

        if (!ShizukuHelper.isAvailable() || !ShizukuHelper.hasPermission()) {
            return findings;
        }

        // Verifica presença de binários de root
        String[] rootPaths = {
                "/sbin/su", "/system/bin/su", "/system/xbin/su",
                "/data/local/xbin/su", "/data/local/bin/su",
                "/system/sd/xbin/su", "/system/bin/.ext/.su"
        };

        List<String> foundPaths = new ArrayList<>();
        for (String path : rootPaths) {
            String result = ShizukuUserService.executeReadOnlyCommand("ls " + path + " 2>/dev/null");
            if (result != null && !result.trim().isEmpty() && !result.contains("No such")) {
                foundPaths.add(path);
            }
        }

        // Verifica Magisk
        String magisk = ShizukuUserService.executeReadOnlyCommand("ls /data/adb/magisk 2>/dev/null");
        boolean magiskFound = magisk != null && !magisk.trim().isEmpty();

        if (!foundPaths.isEmpty() || magiskFound) {
            Map<String, Object> details = new HashMap<>();
            if (!foundPaths.isEmpty()) details.put("su_paths_found", foundPaths);
            if (magiskFound) details.put("magisk", "detectado em /data/adb/magisk");
            details.put("impact", "Proteções de segurança do Android contornadas");

            Finding f = new Finding(
                    Finding.Category.vulnerability,
                    Finding.Severity.critical,
                    "Indicadores de root detectados no dispositivo",
                    "Foram encontrados binários de root ou Magisk no sistema. O dispositivo pode estar rooted, " +
                            "comprometendo todas as proteções de segurança do Android.",
                    true
            );
            f.details = details;
            findings.add(f);
        }

        return findings;
    }

    private List<Finding> checkUsbDebugging() {
        List<Finding> findings = new ArrayList<>();

        if (!ShizukuHelper.isAvailable()) return findings;

        String adbEnabled = ShizukuUserService.executeReadOnlyCommand(
                "settings get global adb_enabled").trim();

        if ("1".equals(adbEnabled)) {
            String adbWifi = ShizukuUserService.executeReadOnlyCommand(
                    "settings get global adb_wifi_enabled 2>/dev/null").trim();

            Map<String, Object> details = new HashMap<>();
            details.put("adb_usb", "enabled");
            details.put("adb_wifi", "1".equals(adbWifi) ? "enabled" : "disabled");
            details.put("risk", "Acesso irrestrito ao sistema via cabo USB ou Wi-Fi");

            Finding f = new Finding(
                    Finding.Category.vulnerability,
                    Finding.Severity.medium,
                    "Depuração ADB " + ("1".equals(adbWifi) ? "USB + Wi-Fi" : "USB") + " habilitada",
                    "A depuração ADB permite acesso total ao sistema a partir de um computador conectado. " +
                            "Desative quando não estiver desenvolvendo.",
                    false
            );
            f.details = details;
            findings.add(f);
        }

        return findings;
    }

    private List<Finding> checkAccessibilityServices() {
        List<Finding> findings = new ArrayList<>();

        if (!ShizukuHelper.isAvailable()) return findings;

        String services = ShizukuUserService.executeReadOnlyCommand(
                "settings get secure enabled_accessibility_services").trim();

        if (services.isEmpty() || services.equals("null") || services.equals("BLOCKED")) {
            return findings;
        }

        List<String> thirdPartyServices = new ArrayList<>();
        for (String svc : services.split(":")) {
            svc = svc.trim();
            if (!svc.isEmpty() &&
                    !svc.startsWith("com.android") &&
                    !svc.startsWith("com.google") &&
                    !svc.startsWith("com.samsung.android") &&
                    !svc.startsWith("com.miui")) {
                thirdPartyServices.add(svc);
            }
        }

        if (!thirdPartyServices.isEmpty()) {
            Map<String, Object> details = new HashMap<>();
            details.put("third_party_accessibility_services", thirdPartyServices);
            details.put("risk", "Podem interceptar toques, ler conteúdo da tela e capturar senhas");

            Finding f = new Finding(
                    Finding.Category.permission,
                    Finding.Severity.high,
                    thirdPartyServices.size() + " serviço(s) de Acessibilidade de terceiros ativos",
                    "Apps com permissão de Acessibilidade têm acesso a tudo que aparece na tela, " +
                            "incluindo senhas e dados bancários.",
                    true
            );
            f.details = details;
            findings.add(f);
        }

        return findings;
    }

    private List<Finding> checkDeviceAdmin() {
        List<Finding> findings = new ArrayList<>();

        if (!ShizukuHelper.isAvailable()) return findings;

        String admins = ShizukuUserService.executeReadOnlyCommand(
                "dumpsys device_policy | grep -i 'admin' | grep -v 'android'").trim();

        if (!admins.isEmpty() && !admins.equals("BLOCKED")) {
            Map<String, Object> details = new HashMap<>();
            details.put("device_admins", admins.split("\n").length + " admin(s) detectado(s)");
            details.put("raw", admins.substring(0, Math.min(admins.length(), 300)));
            details.put("risk", "Apps com privilégio de admin podem bloquear dispositivo e apagar dados");

            Finding f = new Finding(
                    Finding.Category.permission,
                    Finding.Severity.medium,
                    "Apps com privilégio de Administrador do Dispositivo detectados",
                    "Apps com permissão de Device Admin têm controle elevado, incluindo capacidade de " +
                            "bloquear tela, apagar dados e instalar certificados.",
                    false
            );
            f.details = details;
            findings.add(f);
        }

        return findings;
    }
}
