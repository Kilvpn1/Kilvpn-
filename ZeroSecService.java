package com.zerosec.agent.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

import androidx.core.app.NotificationCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.zerosec.agent.R;
import com.zerosec.agent.model.ActionRequest;
import com.zerosec.agent.model.Finding;
import com.zerosec.agent.model.ScanReport;
import com.zerosec.agent.network.ApiClient;
import com.zerosec.agent.receiver.ActionReceiver;
import com.zerosec.agent.scanner.MalwareScanner;
import com.zerosec.agent.scanner.NetworkScanner;
import com.zerosec.agent.scanner.ProcessScanner;
import com.zerosec.agent.scanner.SystemScanner;
import com.zerosec.agent.shizuku.ShizukuHelper;
import com.zerosec.agent.ui.ApprovalActivity;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * ZeroSecService — Serviço principal do agente de segurança.
 *
 * Roda em foreground, monitora o sistema em tempo real,
 * e requer aprovação do usuário para QUALQUER ação que altere o sistema.
 */
public class ZeroSecService extends Service {

    private static final String TAG = "ZeroSec.Service";

    // Channels
    public static final String CHANNEL_MONITORING = "zerosec_monitoring";
    public static final String CHANNEL_ALERTS = "zerosec_alerts";
    public static final String CHANNEL_APPROVAL = "zerosec_approval";

    // Notification IDs
    private static final int NOTIF_FOREGROUND = 1;
    private static final int NOTIF_ALERT_BASE = 100;

    // Broadcast actions
    public static final String ACTION_SCAN_STARTED = "com.zerosec.SCAN_STARTED";
    public static final String ACTION_SCAN_COMPLETED = "com.zerosec.SCAN_COMPLETED";
    public static final String ACTION_FINDING_DETECTED = "com.zerosec.FINDING_DETECTED";
    public static final String ACTION_REQUEST_APPROVAL = "com.zerosec.REQUEST_APPROVAL";
    public static final String ACTION_ACTION_EXECUTED = "com.zerosec.ACTION_EXECUTED";

    // Intent extras
    public static final String EXTRA_SCAN_REPORT = "scan_report";
    public static final String EXTRA_FINDING = "finding";
    public static final String EXTRA_ACTION_REQUEST = "action_request";

    // Comandos
    public static final String CMD_START_SCAN = "start_scan";
    public static final String CMD_APPROVE_ACTION = "approve_action";
    public static final String CMD_DENY_ACTION = "deny_action";
    public static final String CMD_STOP = "stop";

    private ExecutorService executor;
    private Handler mainHandler;
    private NetworkScanner networkScanner;
    private boolean isScanning = false;

    // Monitoramento em tempo real (tráfego de rede a cada 30s)
    private Handler monitorHandler;
    private Runnable monitorRunnable;
    private static final long MONITOR_INTERVAL_MS = 30_000;

    @Override
    public void onCreate() {
        super.onCreate();
        executor = Executors.newCachedThreadPool();
        mainHandler = new Handler(Looper.getMainLooper());
        networkScanner = new NetworkScanner(this);

        createNotificationChannels();
        ShizukuHelper.init();
        startRealtimeMonitoring();

        Log.i(TAG, "ZeroSecService iniciado");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTIF_FOREGROUND, buildForegroundNotification("Monitorando sistema..."));

        if (intent == null) return START_STICKY;

        String command = intent.getStringExtra("command");
        if (command == null) return START_STICKY;

        switch (command) {
            case CMD_START_SCAN:
                startFullScan();
                break;

            case CMD_APPROVE_ACTION:
                String approveReqId = intent.getStringExtra("request_id");
                handleApproval(approveReqId, true);
                break;

            case CMD_DENY_ACTION:
                String denyReqId = intent.getStringExtra("request_id");
                handleApproval(denyReqId, false);
                break;

            case CMD_STOP:
                stopSelf();
                break;
        }

        return START_STICKY;
    }

    /**
     * Varredura completa do sistema.
     * Coleta findings, envia ao backend, notifica via chat.
     */
    private void startFullScan() {
        if (isScanning) {
            Log.w(TAG, "Varredura já em andamento");
            return;
        }

        executor.execute(() -> {
            isScanning = true;
            String scanId = "real_" + UUID.randomUUID().toString().substring(0, 8);

            Log.i(TAG, "Iniciando varredura completa: " + scanId);
            broadcast(ACTION_SCAN_STARTED, null);
            updateForegroundNotification("Varrendo sistema... aguarde");

            ScanReport report = new ScanReport();
            report.scanId = scanId;
            report.startedAt = System.currentTimeMillis();
            report.deviceInfo = collectDeviceInfo();

            List<Finding> allFindings = new ArrayList<>();

            // Scanners em sequência
            runScanner("Processos", new ProcessScanner(this), allFindings);
            runScanner("Rede", networkScanner, allFindings);
            runScanner("Malware", new MalwareScanner(this), allFindings);
            runScanner("Sistema", new SystemScanner(this), allFindings);

            // Atribui scan_id a todos os findings
            for (Finding f : allFindings) {
                f.scanId = scanId;
                f.id = UUID.randomUUID().toString().substring(0, 12);
            }

            report.findings = allFindings;
            report.completedAt = System.currentTimeMillis();
            report.status = "completed";
            report.summary = new ScanReport.Summary();
            report.summary.compute(allFindings);

            Log.i(TAG, "Varredura concluída: " + allFindings.size() + " findings");

            // Envia ao backend
            ApiClient.getInstance(this).sendScanReport(report, new ApiClient.Callback() {
                @Override
                public void onSuccess(String response) {
                    Log.i(TAG, "Relatório enviado ao backend");
                    updateForegroundNotification("Monitorando sistema...");
                    broadcast(ACTION_SCAN_COMPLETED, report);
                    notifyFindings(allFindings, scanId);
                    isScanning = false;
                }

                @Override
                public void onError(String error) {
                    Log.e(TAG, "Erro ao enviar relatório: " + error);
                    updateForegroundNotification("Monitorando sistema...");
                    broadcast(ACTION_SCAN_COMPLETED, report);
                    notifyFindings(allFindings, scanId);
                    isScanning = false;
                }
            });
        });
    }

    private void runScanner(String name, Object scanner, List<Finding> results) {
        try {
            updateForegroundNotification("Analisando: " + name + "...");
            List<Finding> found = null;

            if (scanner instanceof ProcessScanner) found = ((ProcessScanner) scanner).scan();
            else if (scanner instanceof NetworkScanner) found = ((NetworkScanner) scanner).scan();
            else if (scanner instanceof MalwareScanner) found = ((MalwareScanner) scanner).scan();
            else if (scanner instanceof SystemScanner) found = ((SystemScanner) scanner).scan();

            if (found != null) {
                results.addAll(found);
                Log.i(TAG, name + ": " + found.size() + " findings");
            }
        } catch (Exception e) {
            Log.e(TAG, "Erro no scanner " + name, e);
        }
    }

    /**
     * Monitoramento em tempo real de tráfego de rede.
     * Roda a cada 30s — não coleta dados, apenas detecta anomalias de volume.
     */
    private void startRealtimeMonitoring() {
        monitorHandler = new Handler(Looper.getMainLooper());
        monitorRunnable = new Runnable() {
            @Override
            public void run() {
                executor.execute(() -> {
                    List<Finding> trafficFindings = networkScanner.checkTrafficAnomaly();
                    for (Finding f : trafficFindings) {
                        f.id = UUID.randomUUID().toString().substring(0, 12);
                        f.scanId = "realtime_" + System.currentTimeMillis();
                        notifyCriticalFinding(f);
                    }
                });
                monitorHandler.postDelayed(this, MONITOR_INTERVAL_MS);
            }
        };
        monitorHandler.postDelayed(monitorRunnable, MONITOR_INTERVAL_MS);
    }

    /**
     * Notifica findings críticos e de ação requerida.
     */
    private void notifyFindings(List<Finding> findings, String scanId) {
        int notifId = NOTIF_ALERT_BASE;

        for (Finding f : findings) {
            if (f.isCritical() || f.actionRequired) {
                notifyCriticalFinding(f);
                notifId++;
            }
        }

        // Sumário
        long critical = findings.stream().filter(f -> f.severity == Finding.Severity.critical).count();
        long high = findings.stream().filter(f -> f.severity == Finding.Severity.high).count();

        if (critical > 0 || high > 0) {
            showSummaryNotification(findings.size(), (int) critical, (int) high, scanId);
        }
    }

    private void notifyCriticalFinding(Finding finding) {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

        // Intent para abrir ApprovalActivity se ação requerida
        PendingIntent contentIntent = null;
        if (finding.actionRequired) {
            Intent approvalIntent = new Intent(this, ApprovalActivity.class);
            approvalIntent.putExtra("finding_id", finding.id);
            approvalIntent.putExtra("finding_title", finding.title);
            approvalIntent.putExtra("finding_severity", finding.severity.name());
            approvalIntent.putExtra("finding_description", finding.description);
            approvalIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            contentIntent = PendingIntent.getActivity(this, finding.id.hashCode(),
                    approvalIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        }

        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ALERTS)
                .setSmallIcon(R.drawable.ic_shield_alert)
                .setContentTitle("⚠️ " + finding.severity.name().toUpperCase() + ": " + finding.title)
                .setContentText(finding.description)
                .setStyle(new NotificationCompat.BigTextStyle().bigText(finding.description))
                .setPriority(finding.severity == Finding.Severity.critical ?
                        NotificationCompat.PRIORITY_MAX : NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true);

        if (contentIntent != null) {
            builder.setContentIntent(contentIntent);
        }

        if (finding.actionRequired) {
            // Botões de aprovação direto na notificação
            Intent approveIntent = new Intent(this, ActionReceiver.class);
            approveIntent.setAction(ActionReceiver.ACTION_APPROVE);
            approveIntent.putExtra("finding_id", finding.id);
            PendingIntent approvePi = PendingIntent.getBroadcast(this, finding.id.hashCode() + 1,
                    approveIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

            Intent denyIntent = new Intent(this, ActionReceiver.class);
            denyIntent.setAction(ActionReceiver.ACTION_DENY);
            denyIntent.putExtra("finding_id", finding.id);
            PendingIntent denyPi = PendingIntent.getBroadcast(this, finding.id.hashCode() + 2,
                    denyIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

            builder.addAction(0, "✅ Autorizar", approvePi);
            builder.addAction(0, "❌ Negar", denyPi);
        }

        nm.notify(finding.id.hashCode(), builder.build());
    }

    private void showSummaryNotification(int total, int critical, int high, String scanId) {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ALERTS)
                .setSmallIcon(R.drawable.ic_shield_alert)
                .setContentTitle("🛡️ Varredura concluída — " + total + " findings")
                .setContentText(critical + " críticos • " + high + " altos")
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true);

        nm.notify(NOTIF_ALERT_BASE + 99, builder.build());
    }

    /**
     * Executa ação aprovada pelo usuário.
     * Token de aprovação é gerado aqui para garantir que só ações explicitamente
     * aprovadas passem para o ShizukuUserService.
     */
    private void handleApproval(String requestId, boolean approved) {
        if (requestId == null) return;

        executor.execute(() -> {
            if (approved) {
                // Gera token de aprovação único
                String approvalToken = "APPROVED_" + System.currentTimeMillis();
                Log.i(TAG, "Ação APROVADA pelo usuário: " + requestId);

                // Executa via Shizuku com token
                // (ShizukuUserService valida o token antes de executar)
                boolean success = false; // ShizukuUserService.executeApprovedAction(...)

                ApiClient.getInstance(this).updateActionResult(requestId, approved, success);
                broadcast(ACTION_ACTION_EXECUTED, null);

            } else {
                Log.i(TAG, "Ação NEGADA pelo usuário: " + requestId);
                ApiClient.getInstance(this).updateActionResult(requestId, false, false);
            }
        });
    }

    private ScanReport.DeviceInfo collectDeviceInfo() {
        ScanReport.DeviceInfo info = new ScanReport.DeviceInfo();
        info.model = Build.MODEL;
        info.manufacturer = Build.MANUFACTURER;
        info.androidVersion = "Android " + Build.VERSION.RELEASE;
        info.sdkVersion = String.valueOf(Build.VERSION.SDK_INT);
        info.buildId = Build.DISPLAY;
        info.securityPatch = Build.VERSION.SECURITY_PATCH;
        info.isRooted = false; // será atualizado pelo SystemScanner
        info.shizukuAvailable = ShizukuHelper.isAvailable();
        return info;
    }

    private void createNotificationChannels() {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

        nm.createNotificationChannel(new NotificationChannel(
                CHANNEL_MONITORING, "Monitoramento Ativo",
                NotificationManager.IMPORTANCE_LOW));

        NotificationChannel alertChannel = new NotificationChannel(
                CHANNEL_ALERTS, "Alertas de Segurança",
                NotificationManager.IMPORTANCE_HIGH);
        alertChannel.setDescription("Notificações de vulnerabilidades e ameaças detectadas");
        nm.createNotificationChannel(alertChannel);

        NotificationChannel approvalChannel = new NotificationChannel(
                CHANNEL_APPROVAL, "Aprovação de Ações",
                NotificationManager.IMPORTANCE_MAX);
        approvalChannel.setDescription("Ações que requerem sua autorização explícita");
        nm.createNotificationChannel(approvalChannel);
    }

    private Notification buildForegroundNotification(String text) {
        return new NotificationCompat.Builder(this, CHANNEL_MONITORING)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle("ZERO SEC")
                .setContentText(text)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setOngoing(true)
                .build();
    }

    private void updateForegroundNotification(String text) {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        nm.notify(NOTIF_FOREGROUND, buildForegroundNotification(text));
    }

    private void broadcast(String action, Object data) {
        Intent intent = new Intent(action);
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (monitorHandler != null && monitorRunnable != null) {
            monitorHandler.removeCallbacks(monitorRunnable);
        }
        if (executor != null) executor.shutdownNow();
        ShizukuHelper.destroy();
        Log.i(TAG, "ZeroSecService encerrado");
    }
}
