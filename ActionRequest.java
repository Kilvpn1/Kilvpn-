package com.zerosec.agent.model;

public class ActionRequest {
    public enum ActionType {
        KILL_PROCESS,
        REVOKE_PERMISSION,
        BLOCK_NETWORK,
        DELETE_FILE,
        DISABLE_APP,
        UNINSTALL_APP
    }

    public enum Status { pending, approved, denied, executed }

    public String id;
    public String findingId;
    public String scanId;
    public ActionType actionType;
    public String description;
    public String riskLevel;
    public Status status = Status.pending;
    public long createdAt;
    public long decidedAt;

    // Parâmetros específicos da ação
    public String targetPackage;
    public int targetPid;
    public String targetFile;
    public String targetPermission;

    public ActionRequest(String findingId, ActionType type, String description, String risk) {
        this.id = "req_" + System.currentTimeMillis();
        this.findingId = findingId;
        this.actionType = type;
        this.description = description;
        this.riskLevel = risk;
        this.createdAt = System.currentTimeMillis();
    }
}
