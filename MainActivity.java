package com.zerosec.agent.ui;

import android.Manifest;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.zerosec.agent.R;
import com.zerosec.agent.service.ZeroSecService;
import com.zerosec.agent.shizuku.ShizukuHelper;

import rikka.shizuku.Shizuku;

public class MainActivity extends AppCompatActivity {

    private static final int PERM_NOTIFICATION = 1;
    private static final int PERM_SHIZUKU = 2;

    private TextView tvStatus;
    private TextView tvShizukuStatus;
    private TextView tvSummary;
    private Button btnScan;
    private Button btnRequestShizuku;
    private LinearLayout layoutSummary;
    private View scanningIndicator;

    private final BroadcastReceiver scanReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (ZeroSecService.ACTION_SCAN_STARTED.equals(action)) {
                onScanStarted();
            } else if (ZeroSecService.ACTION_SCAN_COMPLETED.equals(action)) {
                onScanCompleted();
            }
        }
    };

    private final Shizuku.OnRequestPermissionResultListener shizukuPermResult =
            (requestCode, grantResult) -> {
                ShizukuHelper.onRequestPermissionResult(requestCode, grantResult);
                runOnUiThread(this::updateShizukuStatus);
            };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tvStatus = findViewById(R.id.tv_status);
        tvShizukuStatus = findViewById(R.id.tv_shizuku_status);
        tvSummary = findViewById(R.id.tv_summary);
        btnScan = findViewById(R.id.btn_scan);
        btnRequestShizuku = findViewById(R.id.btn_request_shizuku);
        layoutSummary = findViewById(R.id.layout_summary);
        scanningIndicator = findViewById(R.id.scanning_indicator);

        ShizukuHelper.init();
        Shizuku.addRequestPermissionResultListener(shizukuPermResult);

        btnScan.setOnClickListener(v -> startScan());
        btnRequestShizuku.setOnClickListener(v -> requestShizukuPermission());

        requestNotificationPermission();
        updateShizukuStatus();

        // Inicia o serviço
        Intent serviceIntent = new Intent(this, ZeroSecService.class);
        startForegroundService(serviceIntent);
    }

    @Override
    protected void onResume() {
        super.onResume();
        IntentFilter filter = new IntentFilter();
        filter.addAction(ZeroSecService.ACTION_SCAN_STARTED);
        filter.addAction(ZeroSecService.ACTION_SCAN_COMPLETED);
        LocalBroadcastManager.getInstance(this).registerReceiver(scanReceiver, filter);
        updateShizukuStatus();
    }

    @Override
    protected void onPause() {
        super.onPause();
        LocalBroadcastManager.getInstance(this).unregisterReceiver(scanReceiver);
    }

    private void startScan() {
        Intent intent = new Intent(this, ZeroSecService.class);
        intent.putExtra("command", ZeroSecService.CMD_START_SCAN);
        startForegroundService(intent);
    }

    private void onScanStarted() {
        runOnUiThread(() -> {
            btnScan.setEnabled(false);
            btnScan.setText("Varrendo...");
            scanningIndicator.setVisibility(View.VISIBLE);
            tvStatus.setText("Analisando sistema...");
        });
    }

    private void onScanCompleted() {
        runOnUiThread(() -> {
            btnScan.setEnabled(true);
            btnScan.setText("Nova Varredura");
            scanningIndicator.setVisibility(View.GONE);
            tvStatus.setText("Monitorando sistema");
            layoutSummary.setVisibility(View.VISIBLE);
            tvSummary.setText("Varredura concluída. Verifique as notificações para findings críticos.");
        });
    }

    private void updateShizukuStatus() {
        if (ShizukuHelper.isAvailable() && ShizukuHelper.hasPermission()) {
            tvShizukuStatus.setText("✅ Shizuku ativo — modo privilegiado");
            tvShizukuStatus.setTextColor(0xFF00E676);
            btnRequestShizuku.setVisibility(View.GONE);
        } else if (ShizukuHelper.isAvailable()) {
            tvShizukuStatus.setText("⚠️ Shizuku disponível — permissão necessária");
            tvShizukuStatus.setTextColor(0xFFFFD600);
            btnRequestShizuku.setVisibility(View.VISIBLE);
        } else {
            tvShizukuStatus.setText("❌ Shizuku não encontrado — instale via Play Store");
            tvShizukuStatus.setTextColor(0xFFFF1744);
            btnRequestShizuku.setVisibility(View.GONE);
        }
    }

    private void requestShizukuPermission() {
        if (ShizukuHelper.isAvailable()) {
            ShizukuHelper.requestPermission();
        } else {
            Toast.makeText(this, "Instale o Shizuku primeiro", Toast.LENGTH_LONG).show();
        }
    }

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this,
                        new String[]{Manifest.permission.POST_NOTIFICATIONS}, PERM_NOTIFICATION);
            }
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERM_NOTIFICATION) {
            // Notification permission handled
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        Shizuku.removeRequestPermissionResultListener(shizukuPermResult);
        ShizukuHelper.destroy();
    }
}
