package com.zerosec.agent.network;

import android.content.Context;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.zerosec.agent.model.Finding;
import com.zerosec.agent.model.ScanReport;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * ApiClient — Comunicação com o backend ZERO SEC.
 *
 * REGRA DE PRIVACIDADE:
 * - Envia APENAS: ID da varredura, tipo/severidade/título do finding, metadados do dispositivo
 * - NUNCA envia: arquivos, conteúdo de mensagens, fotos, dados pessoais do usuário
 * - Toda comunicação é HTTPS
 */
public class ApiClient {

    private static final String TAG = "ZeroSec.ApiClient";
    private static final String BASE_URL = "https://zero-1a32f079.base44.app/functions";
    private static final MediaType JSON = MediaType.get("application/json");

    private static ApiClient instance;
    private final OkHttpClient httpClient;
    private final Gson gson;

    private ApiClient(Context context) {
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .build();
        this.gson = new GsonBuilder().create();
    }

    public static synchronized ApiClient getInstance(Context context) {
        if (instance == null) {
            instance = new ApiClient(context.getApplicationContext());
        }
        return instance;
    }

    public interface Callback {
        void onSuccess(String response);
        void onError(String error);
    }

    /**
     * Envia relatório de varredura ao backend.
     * Apenas metadados de segurança — sem dados pessoais.
     */
    public void sendScanReport(ScanReport report, Callback callback) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("scan_id", report.scanId);
        payload.put("device_info", deviceInfoToMap(report.deviceInfo));

        List<Map<String, Object>> findingsList = new ArrayList<>();
        for (Finding f : report.findings) {
            Map<String, Object> fm = new HashMap<>();
            fm.put("category", f.category != null ? f.category.name() : "vulnerability");
            fm.put("severity", f.severity != null ? f.severity.name() : "medium");
            fm.put("title", f.title);
            fm.put("description", f.description);
            fm.put("action_required", f.actionRequired);
            if (f.details != null) fm.put("details", f.details);
            findingsList.add(fm);
        }
        payload.put("findings", findingsList);

        String json = gson.toJson(payload);
        postAsync(BASE_URL + "/receiveScan", json, callback);
    }

    public void updateActionResult(String requestId, boolean approved, boolean executed) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("request_id", requestId);
        payload.put("approved", approved);
        payload.put("executed", executed);
        payload.put("timestamp", System.currentTimeMillis());

        String json = gson.toJson(payload);
        postAsync(BASE_URL + "/updateAction", json, new Callback() {
            @Override
            public void onSuccess(String response) {
                Log.i(TAG, "Action result atualizado");
            }

            @Override
            public void onError(String error) {
                Log.w(TAG, "Erro ao atualizar action result: " + error);
            }
        });
    }

    private void postAsync(String url, String jsonBody, Callback callback) {
        RequestBody body = RequestBody.create(jsonBody, JSON);
        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .addHeader("Content-Type", "application/json")
                .build();

        httpClient.newCall(request).enqueue(new okhttp3.Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.e(TAG, "Falha na requisição: " + e.getMessage());
                if (callback != null) callback.onError(e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                String responseBody = response.body() != null ? response.body().string() : "";
                if (response.isSuccessful()) {
                    if (callback != null) callback.onSuccess(responseBody);
                } else {
                    Log.w(TAG, "Erro HTTP " + response.code() + ": " + responseBody);
                    if (callback != null) callback.onError("HTTP " + response.code());
                }
            }
        });
    }

    private Map<String, Object> deviceInfoToMap(ScanReport.DeviceInfo info) {
        Map<String, Object> map = new HashMap<>();
        if (info == null) return map;
        map.put("model", info.model);
        map.put("manufacturer", info.manufacturer);
        map.put("os", info.androidVersion);
        map.put("sdk", info.sdkVersion);
        map.put("build", info.buildId);
        map.put("security_patch", info.securityPatch);
        map.put("shizuku_available", info.shizukuAvailable);
        return map;
    }
}
