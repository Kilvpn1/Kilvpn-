package com.zerosec.agent.model;

import java.util.Map;

public class Finding {
    public enum Category { process, network, file, vulnerability, log, permission }
    public enum Severity { critical, high, medium, low, info }
    public enum Status { open, acknowledged, resolved, ignored }

    public String id;
    public String scanId;
    public Category category;
    public Severity severity;
    public String title;
    public String description;
    public Map<String, Object> details;
    public Status status = Status.open;
    public boolean actionRequired;
    public String actionTaken;
    public long timestamp;

    public Finding() {
        this.timestamp = System.currentTimeMillis();
        this.status = Status.open;
    }

    public Finding(Category cat, Severity sev, String title, String desc, boolean actionRequired) {
        this();
        this.category = cat;
        this.severity = sev;
        this.title = title;
        this.description = desc;
        this.actionRequired = actionRequired;
    }

    public boolean isCritical() {
        return severity == Severity.critical || severity == Severity.high;
    }
}
