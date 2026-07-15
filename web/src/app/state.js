export const state = {
    activeView: "overview",
    activeTab: "devices",
    activeTriageFilter: "all",
    autoRefreshSeconds: 0,
    talkersData: [],
    exportersData: [],
    devicesData: [],
    anomaliesData: [],
    riskDevicesData: [],
    trafficSeriesData: [],
    trafficRecordsData: [],
    trafficRecordFilters: {
        q: "",
        protocol: "",
        dstPort: ""
    },
    trafficRecordSort: {
        key: "timestamp",
        direction: "desc"
    },
    securitySummaryData: null,
    securityTimelineData: [],
    overviewErrors: {},
    trafficErrors: {},
    devicesError: null,
    anomaliesError: null,
    policiesError: null,
    notificationRulesError: null,
    notificationLogsError: null,
    auditLogsError: null,
    settingsError: null,
    overviewProtocolsData: [],
    overviewTopDevicesData: [],
    overviewHeatmapData: [],
    overviewCollectorHealthData: [],
    activeTrafficRange: "24h",
    selectedDeviceIP: null,
    selectedDeviceSubnet: "",
    selectedAnomalyId: null,
    policiesData: [],
    selectedPolicyId: null,
    policyRuleEditorDirty: false,
    notificationRulesData: [],
    selectedNotificationRuleId: null,
    notificationRuleEditorDirty: false,
    notificationLogsData: [],
    auditLogsData: [],
    auditLogPage: 0,
    auditLogPageSize: 10,
    unsavedChanges: {
        access: false,
        network: false,
        collectors: false,
        storage: false,
        thresholds: false,
        policies: false,
        notifications: false,
        integrations: false,
        system: false
    },
    settingsData: null,
    activeSettingsSection: "access",
    lastRoutedView: null,
    firstRunCompleted: true,
    firewallTemplates: null,
    activeFwTab: "unifi"
};

export function setSelectedDeviceIP(ip) {
    state.selectedDeviceIP = ip;
}

export function setSelectedDeviceSubnet(subnet) {
    state.selectedDeviceSubnet = subnet;
}

export function setSelectedAnomalyId(id) {
    state.selectedAnomalyId = id ? String(id) : null;
}

export function setSelectedPolicyId(id) {
    state.selectedPolicyId = id;
}

export function setSelectedNotificationRuleId(id) {
    state.selectedNotificationRuleId = id;
}

export function setActiveTriageFilter(filter) {
    state.activeTriageFilter = filter;
}

export function setActiveSettingsSection(section) {
    state.activeSettingsSection = section;
}

export function setActiveTrafficRange(range) {
    state.activeTrafficRange = range;
}

export function setUnsavedChanges(section, isUnsaved) {
    state.unsavedChanges[section] = isUnsaved;
}

export function setNotificationRuleEditorDirty(isDirty) {
    state.notificationRuleEditorDirty = isDirty;
}

export function setPolicyRuleEditorDirty(isDirty) {
    state.policyRuleEditorDirty = isDirty;
}

export function clearAllDirtyFlags() {
    Object.keys(state.unsavedChanges).forEach(k => {
        state.unsavedChanges[k] = false;
    });
    state.notificationRuleEditorDirty = false;
    state.policyRuleEditorDirty = false;
}

export function hasUnsavedChanges() {
    const settingsDirty = Object.values(state.unsavedChanges).some(v => v === true);
    return settingsDirty || state.notificationRuleEditorDirty || state.policyRuleEditorDirty;
}
