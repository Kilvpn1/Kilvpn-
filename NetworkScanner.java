package com.zerosec.agent.scanner;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.TrafficStats;
import android.util.Log;

import com.zerosec.agent.model.Finding;
import com.zerosec.agent.shizuku.ShizukuHelper;
import com.zerosec.agent.shizuku.ShizukuUserService;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class NetworkScanner {

    private static final String TAG = "ZeroSec.NetworkScanner";

    // Portas suspeitas conhecidas
    private static final Map<String, String> SUSPICIOUS_PORTS = new HashMap<String, String>() {{
        put("4444", "Metasploit default");
        put("5554", "Android Emulator control");
        put("1337", "Porta hacker clássica");
        put("31337", "Back Orifice");
        put("9001", "Tor relay");
        put("8888", "Proxy/backdoor comum");
        put("6666", "IRC/botnet");
        put("1234", "Backdoor genérico");
        put("12345", "NetBus");
        put("54321", "Reverse shell comum");
    }};

    // IPs/ranges de Tor exit nodes conhecidos (amostra)
    private static final List<String> TOR_RANGES = Arrays.asList(
            "185.220.101", "185.220.100", "185.220.102",
            "199.249.230", "199.249.231", "204.8.156",
            "171.25.193", "176.10.99", "162.247.74"
    );

    // Baseline de tráfego (bytes) — para detecção de anomalia
    private static long lastRxBytes = -1;
    private static long lastTxBytes = -1;
    private static long lastCheckTime = -1;

    // Limite: se subir mais de 10MB em 60s sem app ativo em foreground — suspeito
    private static final long TRAFFIC_ANOMALY_THRESHOLD_BYTES = 10 * 1024 * 1024; // 10MB

    private final Context context;

    public NetworkScanner(Context context) {
        this.context = context;
    }

    public List<Finding> scan() {
        List<Finding> findings = new ArrayList<>();

        findings.addAll(scanOpenPorts());
        findings.addAll(scanConnections());
        findings.addAll(checkDns());
        findings.addAll(checkPrivateDns());
        findings.addAll(checkTrafficAnomaly());

        return findings;
    }

    private List<Finding> scanOpenPorts() {
        List<Finding> findings = new ArrayList<>();

        if (!ShizukuHelper.isAvailable() || !ShizukuHelper.hasPermission()) {
            return findings;
        }

        String ssOutput = ShizukuUserService.executeReadOnlyCommand("ss -tlnp");
        if (ssOutput == null || ssOutput.isEmpty()) {
            ssOutput = ShizukuUserService.executeReadOnlyCommand("cat /proc/net/tcp6");
        }

        for (Map.Entry<String, String> entry : SUSPICIOUS_PORTS.entrySet()) {
            String port = entry.getKey();
            String desc = entry.getValue();

            if (ssOutput.contains(":" + port + " ") || ssOutput.contains(":" + port + "\n")) {
                Map<String, Object> details = new HashMap<>();
                details.put("port", port);
                details.put("known_as", desc);
                details.put("recommendation", "Verifique qual processo está usando esta porta");

                Finding f = new Finding(
                        Finding.Category.network,
                        Finding.Severity.critical,
                        "Porta suspeita aberta: " + port,
                        "Porta " + port + " detectada aberta. Conhecida por: " + desc +
                                ". Pode indicar backdoor ou malware ativo.",
                        true
                );
                f.details = details;
                findings.add(f);
            }
        }

        return findings;
    }

    private List<Finding> scanConnections() {
        List<Finding> findings = new ArrayList<>();

        if (!ShizukuHelper.isAvailable() || !ShizukuHelper.hasPermission()) {
            return findings;
        }

        String connOutput = ShizukuUserService.executeReadOnlyCommand("ss -tnp state established");
        if (connOutput == null || connOutput.isEmpty()) return findings;

        List<String> torConnections = new ArrayList<>();
        String[] lines = connOutput.split("\n");

        for (String line : lines) {
            for (String torRange : TOR_RANGES) {
                if (line.contains(torRange)) {
                    torConnections.add(line.trim());
                    break;
                }
            }
        }

        if (!torConnections.isEmpty()) {
            Map<String, Object> details = new HashMap<>();
            details.put("connections", torConnections);
            details.put("type", "Tor exit node");

            Finding f = new Finding(
                    Finding.Category.network,
                    Finding.Severity.critical,
                    "Conexão ativa com Tor exit node detectada",
                    "O dispositivo possui conexão estabelecida com IPs de Tor exit nodes conhecidos. " +
                            "Pode indicar malware se comunicando anonimamente.",
                    true
            );
            f.details = details;
            findings.add(f);
        }

        return findings;
    }

    private List<Finding> checkDns() {
        List<Finding> findings = new ArrayList<>();

        if (!ShizukuHelper.isAvailable()) return findings;

        String dns1 = ShizukuUserService.executeReadOnlyCommand("getprop net.dns1").trim();
        String dns2 = ShizukuUserService.executeReadOnlyCommand("getprop net.dns2").trim();

        // DNS confiáveis conhecidos
        List<String> trustedDns = Arrays.asList(
                "8.8.8.8", "8.8.4.4",       // Google
                "1.1.1.1", "1.0.0.1",       // Cloudflare
                "9.9.9.9", "149.112.112.112", // Quad9
                "208.67.222.222",             // OpenDNS
                "192.168.1.1", "192.168.0.1", "10.0.0.1" // Roteadores comuns
        );

        if (dns1 != null && !dns1.isEmpty() && !dns1.equals("null")) {
            boolean trusted = false;
            for (String t : trustedDns) {
                if (dns1.startsWith(t) || dns1.startsWith("192.168.") || dns1.startsWith("10.")) {
                    trusted = true;
                    break;
                }
            }

            if (!trusted) {
                Map<String, Object> details = new HashMap<>();
                details.put("dns1", dns1);
                details.put("dns2", dns2);
                details.put("recommendation", "Verifique se este DNS foi alterado sem sua autorização");

                Finding f = new Finding(
                        Finding.Category.network,
                        Finding.Severity.high,
                        "DNS configurado para servidor desconhecido: " + dns1,
                        "O DNS primário do dispositivo aponta para um servidor não reconhecido. " +
                                "Possível DNS hijacking — todas as requisições de rede podem estar sendo interceptadas.",
                        true
                );
                f.details = details;
                findings.add(f);
            }
        }

        return findings;
    }

    private List<Finding> checkPrivateDns() {
        List<Finding> findings = new ArrayList<>();

        if (!ShizukuHelper.isAvailable()) return findings;

        String privateDns = ShizukuUserService.executeReadOnlyCommand(
                "settings get global private_dns_mode").trim();
        String privateDnsHost = ShizukuUserService.executeReadOnlyCommand(
                "settings get global private_dns_specifier").trim();

        if (!"hostname".equals(privateDns) && !"automatic".equals(privateDns)) {
            Map<String, Object> details = new HashMap<>();
            details.put("private_dns_mode", privateDns);
            details.put("recommendation", "Ativar em: Configurações > Rede > DNS Privado > Automático");

            Finding f = new Finding(
                    Finding.Category.network,
                    Finding.Severity.low,
                    "DNS-over-TLS (DNS Privado) não configurado",
                    "O dispositivo não usa DNS criptografado. Consultas DNS são visíveis na rede e podem ser interceptadas ou manipuladas.",
                    false
            );
            f.details = details;
            findings.add(f);
        }

        return findings;
    }

    /**
     * Detecção de anomalia de tráfego de rede.
     * Se o tráfego subir mais de 10MB em 60s sem interação do usuário — alerta.
     */
    public List<Finding> checkTrafficAnomaly() {
        List<Finding> findings = new ArrayList<>();

        long currentRx = TrafficStats.getTotalRxBytes();
        long currentTx = TrafficStats.getTotalTxBytes();
        long now = System.currentTimeMillis();

        if (lastRxBytes == -1) {
            // Primeira leitura — apenas salva baseline
            lastRxBytes = currentRx;
            lastTxBytes = currentTx;
            lastCheckTime = now;
            return findings;
        }

        long elapsed = now - lastCheckTime;
        if (elapsed < 30_000) return findings; // Não checar com menos de 30s de intervalo

        long deltaRx = currentRx - lastRxBytes;
        long deltaTx = currentTx - lastTxBytes;
        long totalDelta = deltaRx + deltaTx;

        // Atualiza baseline
        lastRxBytes = currentRx;
        lastTxBytes = currentTx;
        lastCheckTime = now;

        if (totalDelta > TRAFFIC_ANOMALY_THRESHOLD_BYTES) {
            long deltaSeconds = elapsed / 1000;
            float mbps = (totalDelta / 1024f / 1024f) / (deltaSeconds);

            Map<String, Object> details = new HashMap<>();
            details.put("download_mb", String.format("%.2f MB", deltaRx / 1024f / 1024f));
            details.put("upload_mb", String.format("%.2f MB", deltaTx / 1024f / 1024f));
            details.put("period_seconds", deltaSeconds);
            details.put("avg_mbps", String.format("%.2f MB/s", mbps));
            details.put("threshold", "10MB em 60s");

            Finding f = new Finding(
                    Finding.Category.network,
                    Finding.Severity.high,
                    "Tráfego de rede anômalo detectado",
                    String.format("%.1f MB transferidos em %ds. Pode indicar exfiltração de dados ou download malicioso em background.",
                            totalDelta / 1024f / 1024f, deltaSeconds),
                    true
            );
            f.details = details;
            findings.add(f);

            Log.w(TAG, "ALERTA: Tráfego anômalo — " + (totalDelta / 1024 / 1024) + "MB em " + deltaSeconds + "s");
        }

        return findings;
    }
}
