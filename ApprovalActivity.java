package com.zerosec.agent.ui;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.zerosec.agent.R;
import com.zerosec.agent.service.ZeroSecService;

/**
 * ApprovalActivity — Tela de aprovação de ações críticas.
 *
 * Abre quando o usuário toca em uma notificação de ação requerida.
 * Exibe detalhes completos do finding e aguarda decisão explícita.
 *
 * Nenhuma ação é executada sem interação do usuário nesta tela.
 */
public class ApprovalActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_approval);

        String findingId = getIntent().getStringExtra("finding_id");
        String findingTitle = getIntent().getStringExtra("finding_title");
        String findingSeverity = getIntent().getStringExtra("finding_severity");
        String findingDescription = getIntent().getStringExtra("finding_description");

        TextView tvTitle = findViewById(R.id.tv_approval_title);
        TextView tvSeverity = findViewById(R.id.tv_approval_severity);
        TextView tvDescription = findViewById(R.id.tv_approval_description);
        TextView tvWarning = findViewById(R.id.tv_approval_warning);
        Button btnApprove = findViewById(R.id.btn_approve);
        Button btnDeny = findViewById(R.id.btn_deny);

        if (tvTitle != null) tvTitle.setText(findingTitle);
        if (tvSeverity != null) tvSeverity.setText("Severidade: " + findingSeverity);
        if (tvDescription != null) tvDescription.setText(findingDescription);
        if (tvWarning != null) tvWarning.setText(
                "⚠️ Esta ação modificará o sistema. Só será executada com sua confirmação explícita."
        );

        if (btnApprove != null) {
            btnApprove.setOnClickListener(v -> {
                dispatchDecision(findingId, true);
                finish();
            });
        }

        if (btnDeny != null) {
            btnDeny.setOnClickListener(v -> {
                dispatchDecision(findingId, false);
                finish();
            });
        }
    }

    private void dispatchDecision(String findingId, boolean approved) {
        Intent intent = new Intent(this, ZeroSecService.class);
        intent.putExtra("command", approved ?
                ZeroSecService.CMD_APPROVE_ACTION : ZeroSecService.CMD_DENY_ACTION);
        intent.putExtra("request_id", findingId);
        startForegroundService(intent);
    }
}
