package com.zerosec.agent.model;

import java.util.ArrayList;
import java.util.List;

public class ScanReport {
    public String scanId;
    public String status; // running, completed, failed
    public long startedAt;
    public long completedAt;
    public DeviceInfo deviceInfo;
    public List<Finding> findings = new ArrayList<>();
    public Summary summary;

    public static class DeviceInfo {
        public String model;
        public String manufacturer;
        public String androidVersion;
        public String sdkVersion;
        public String buildId;
        public String securityPatch;
        public boolean isRooted;
        public boolean shizukuAvailable;
    }

    public static class Summary {
        public int total;
        public int critical;
        public int high;
        public int medium;
        public int low;
        public int info;
        public int actionRequired;

        public void compute(List<Finding> findings) {
            total = findings.size();
            for (Finding f : findings) {
                switch (f.severity) {
                    case critical: critical++; break;
                    case high: high++; break;
                    case medium: medium++; break;
                    case low: low++; break;
                    case info: info++; break;
                }
                if (f.actionRequired) actionRequired++;
            }
        }
    }
}
