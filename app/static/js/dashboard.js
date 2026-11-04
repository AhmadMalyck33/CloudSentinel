
/* =====================================
   CloudSentinel Dashboard
   Dynamic Data Integration
   Security Alert Management
===================================== */

let apiKey = "";
let openDetailRow = null;
let statusDialogResolve = null;
let statusDialogButton = null;
let loadedAlerts = [];
let currentPage = 1;
let loadedAuditRecords = [];
let auditPage = 1;
const alertsPerPage = 10;
let statusMessageTimer = null;


function showStatusMessage(text, isError = false) {
    const message = document.getElementById("alert-message");
    if (statusMessageTimer) {
        clearTimeout(statusMessageTimer);
        statusMessageTimer = null;
    }
    message.textContent = text;
    message.className = isError ? "error-message" : "success-message";
    if (!isError) {
        statusMessageTimer = setTimeout(() => {
            message.textContent = "";
            message.className = "";
            statusMessageTimer = null;
        }, 6000);
    }
}


function apiFetch(url, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const headers = new Headers(options.headers || {});

    if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
        headers.set("X-API-Key", apiKey);
    }

    return fetch(url, {
        ...options,
        headers
    });
}


function initializeMonitoringLinks() {
    const hostname = window.location.hostname;
    const prometheusPort = document.body.dataset.prometheusPort;
    const grafanaPort = document.body.dataset.grafanaPort;

    document.getElementById("prometheus-link").href =
        `http://${hostname}:${prometheusPort}`;
    document.getElementById("grafana-link").href =
        `http://${hostname}:${grafanaPort}`;
}


function openStatusDialog(alert, newStatus, button) {
        const dialog = document.getElementById("status-dialog");
        const alertText = document.getElementById("status-dialog-alert");
        const actor = document.getElementById("status-actor");
        const reason = document.getElementById("status-reason");
        const error = document.getElementById("status-dialog-error");

        statusDialogButton = button;
        alertText.textContent =
            `${newStatus === "resolved" ? "Resolve" : "Acknowledge"} ` +
            `${alert.alert_type || "alert"} from ${alert.source_ip || "unknown IP"}`;
        actor.value = "";
        reason.value = "";
        error.textContent = "";
        document.getElementById("status-reason-count").textContent = "0/200";
        dialog.showModal();
        actor.focus();

        return new Promise(resolve => {
            statusDialogResolve = resolve;
        });
    }


function initializeStatusDialog() {
        const dialog = document.getElementById("status-dialog");
        const form = document.getElementById("status-form");
        const actor = document.getElementById("status-actor");
        const reason = document.getElementById("status-reason");
        const error = document.getElementById("status-dialog-error");

        reason.addEventListener("input", () => {
            document.getElementById("status-reason-count").textContent =
                `${reason.value.length}/200`;
        });

        form.addEventListener("submit", event => {
            event.preventDefault();
            const name = actor.value.trim();

            if (!name) {
                error.textContent = "Your name is required.";
                actor.focus();
                return;
            }
            if (name.length > 50) {
                error.textContent = "Your name must be 50 characters or fewer.";
                actor.focus();
                return;
            }
            if (reason.value.length > 200) {
                error.textContent = "Reason must be 200 characters or fewer.";
                reason.focus();
                return;
            }

            const result = {
                actor: name,
                reason: reason.value.trim() || null
            };
            const resolve = statusDialogResolve;
            statusDialogResolve = null;
            resolve(result);
            dialog.close();
        });

        document.getElementById("status-cancel").addEventListener(
            "click",
            () => dialog.close()
        );

        dialog.addEventListener("close", () => {
            if (statusDialogResolve) {
                statusDialogResolve(null);
                statusDialogResolve = null;
            }
            if (statusDialogButton) {
                statusDialogButton.focus();
                statusDialogButton = null;
            }
        });
    }

function appendDetailField(container, label, value) {
    const field = document.createElement("div");
    const labelElement = document.createElement("strong");
    const valueElement = document.createElement("span");

    labelElement.textContent = `${label}: `;
    valueElement.textContent = value ?? "N/A";
    field.append(labelElement, valueElement);
    container.appendChild(field);
}


async function createAlertDetailRow(alert, row) {
    const detailRow = document.createElement("tr");
    const detailCell = detailRow.insertCell();
    const detailPanel = document.createElement("div");
    const fields = document.createElement("div");
    const historyHeading = document.createElement("h3");
    const historyContainer = document.createElement("div");

    detailRow.className = "alert-detail-row";
    detailCell.colSpan = 6;
    detailPanel.className = "alert-detail";
    fields.className = "alert-detail-fields";
    historyHeading.textContent = "History";
    historyContainer.className = "alert-history";

    appendDetailField(fields, "Description", alert.description);
    appendDetailField(fields, "Summary", alert.summary);
    appendDetailField(fields, "Source / Target", alert.source_ip);
    appendDetailField(fields, "Destination IP", alert.destination_ip);
    appendDetailField(fields, "Failed attempts", alert.failed_attempts);
    appendDetailField(fields, "Unique ports", alert.unique_ports);
    appendDetailField(fields, "Time window start", alert.window_start);
    appendDetailField(fields, "Time window end", alert.window_end);
    appendDetailField(fields, "Generated at", alert.generated_at);
    appendDetailField(fields, "Updated at", alert.updated_at);
    appendDetailField(fields, "Alert ID", alert.alert_id);

    detailPanel.append(fields, historyHeading, historyContainer);
    detailCell.appendChild(detailPanel);
    row.after(detailRow);

    try {
        const response = await fetch("/audit");
        if (!response.ok) {
            throw new Error("Unable to retrieve alert history");
        }

        const data = await response.json();
        const records = (data.records || []).filter(
            record => record.alert_id === alert.alert_id
        );

        if (records.length === 0) {
            historyContainer.textContent = "No history available.";
            return detailRow;
        }

        records.forEach(record => {
            const historyRecord = document.createElement("div");
            historyRecord.className = "history-record";
            appendDetailField(historyRecord, "Timestamp", record.timestamp);
            appendDetailField(historyRecord, "Actor", record.actor);
            appendDetailField(
                historyRecord,
                "Status",
                `${record.old_status} -> ${record.new_status}`
            );
            appendDetailField(historyRecord, "Reason", record.reason);
            historyContainer.appendChild(historyRecord);
        });
    } catch (error) {
        console.error("Alert history loading error:", error);
        historyContainer.textContent = "Unable to load alert history.";
    }

    return detailRow;
}


async function toggleAlertDetails(alert, row) {
    const isOpen = row.getAttribute("aria-expanded") === "true";

    if (openDetailRow) {
        openDetailRow.remove();
        openDetailRow = null;
    }

    document.querySelectorAll(".alert-row[aria-expanded='true']")
        .forEach(openRow => openRow.setAttribute("aria-expanded", "false"));

    if (!isOpen) {
        row.setAttribute("aria-expanded", "true");
        const detailRow = await createAlertDetailRow(alert, row);
        if (row.getAttribute("aria-expanded") === "true") {
            openDetailRow = detailRow;
        } else {
            detailRow.remove();
        }
    }
}


function populateAlertTypes() {
    const typeFilter = document.getElementById("type-filter");
    const selectedType = typeFilter.value;
    const types = new Map();
    loadedAlerts.forEach(alert => {
        const alertType = alert.alert_type || "Unknown";
        const alertName = alert.alert_name;
        const summary = alert.summary;
        types.set(alertType, alertType);
        if (alertName) {
            types.set(alertName, alertName);
        }
        if (summary) {
            types.set(summary, summary);
        }
    });

    typeFilter.replaceChildren();
    const allOption = document.createElement("option");
    allOption.value = "all";
    allOption.textContent = "All";
    typeFilter.appendChild(allOption);

    [...types.keys()].sort().forEach(type => {
        const option = document.createElement("option");
        option.value = type;
        option.textContent = types.get(type);
        typeFilter.appendChild(option);
    });

    typeFilter.value = types.has(selectedType) ? selectedType : "all";
}


function getFilteredAlerts() {
    const status = document.getElementById("status-filter").value;
    const severity = document.getElementById("severity-filter").value;
    const type = document.getElementById("type-filter").value;
    const source = document.getElementById("source-search").value
        .trim()
        .toLowerCase();

    return loadedAlerts.filter(alert => {
        const alertStatus = (alert.status || "open").toLowerCase();
        const alertSeverity = (alert.severity || "low").toLowerCase();
        const alertType = alert.alert_type || "Unknown";
        const alertName = alert.alert_name || "";
        const summary = alert.summary || "";
        const sourceIp = (alert.source_ip || "").toLowerCase();

        return (status === "all" || alertStatus === status) &&
            (severity === "all" || alertSeverity === severity) &&
            (type === "all" ||
                [alertType, alertName, summary].includes(type)) &&
            sourceIp.includes(source);
    });
}


function renderAlerts() {
    const table = document.getElementById("alerts-table");
    const filteredAlerts = getFilteredAlerts();
    const totalPages = Math.max(
        1,
        Math.ceil(filteredAlerts.length / alertsPerPage)
    );
    currentPage = Math.min(currentPage, totalPages);
    const start = (currentPage - 1) * alertsPerPage;
    const pageAlerts = filteredAlerts.slice(start, start + alertsPerPage);

    openDetailRow = null;
    table.replaceChildren();

    if (filteredAlerts.length === 0) {
        const row = table.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 6;
        cell.textContent = "No alerts match your filters.";
        cell.className = "empty-message";
    } else {
        pageAlerts.forEach(alert => {
            const row = table.insertRow();
            row.tabIndex = 0;
            row.className = "alert-row";
            row.setAttribute("aria-expanded", "false");
            row.addEventListener("click", () => {
                toggleAlertDetails(alert, row);
            });
            row.addEventListener("keydown", event => {
                if (event.key === "Enter") {
                    event.preventDefault();
                    toggleAlertDetails(alert, row);
                }
            });

            // Alert type
            const typeCell = row.insertCell();
            typeCell.textContent =
                alert.alert_name || alert.alert_type || "Unknown";

            // Source / target
            const ipCell = row.insertCell();
            ipCell.textContent = alert.source_ip || "Unknown";

            // Severity badge
            const severityCell = row.insertCell();

            const severity = (
                alert.severity || "low"
            ).toLowerCase();

            const severityBadge = document.createElement("span");
            severityBadge.classList.add("severity");

            const severityClasses = {
                critical: "severity-critical",
                high: "severity-high",
                medium: "severity-medium",
                low: "severity-low"
            };

            severityBadge.classList.add(
                severityClasses[severity] || "severity-low"
            );

            severityBadge.textContent = severity.toUpperCase();
            severityCell.appendChild(severityBadge);

            // Alert status
            const statusCell = row.insertCell();

            const status = alert.status || "open";
            const statusBadge = document.createElement("span");

            statusBadge.classList.add("alert-status");
            statusBadge.classList.add(`status-${status}`);
            statusBadge.textContent = status.toUpperCase();

            statusCell.appendChild(statusBadge);

            // Generated timestamp
            const timeCell = row.insertCell();

            timeCell.textContent = alert.generated_at
                ? new Date(alert.generated_at).toLocaleString()
                : "N/A";

            // Alert management actions
            const actionsCell = row.insertCell();

            if (status === "open") {
                const acknowledgeButton =
                    document.createElement("button");

                acknowledgeButton.textContent = "Acknowledge";

                acknowledgeButton.addEventListener("click", event => {
                    event.stopPropagation();
                    updateAlertStatus(alert, "acknowledged", event.currentTarget);
                });

                actionsCell.appendChild(acknowledgeButton);

            } else if (status === "acknowledged") {
                const resolveButton =
                    document.createElement("button");

                resolveButton.textContent = "Resolve";

                resolveButton.addEventListener("click", event => {
                    event.stopPropagation();
                    updateAlertStatus(alert, "resolved", event.currentTarget);
                });

                actionsCell.appendChild(resolveButton);

            } else if (status === "resolved") {
                actionsCell.textContent = "Completed";
            }
        });
    }

    document.getElementById("page-indicator").textContent =
        `Page ${currentPage} of ${totalPages}`;
    document.getElementById("previous-page").disabled = currentPage <= 1;
    document.getElementById("next-page").disabled =
        currentPage >= totalPages;
}


// Load security alerts from Flask API
async function loadAlerts() {
    try {
        const response = await fetch("/alerts");

        if (!response.ok) {
            throw new Error("Unable to retrieve security alerts");
        }

        const data = await response.json();
        loadedAlerts = (data.alerts || []).slice().reverse();
        populateAlertTypes();
        renderAlerts();
    } catch (error) {
        console.error("Alert loading error:", error);

        const table = document.getElementById("alerts-table");
        table.replaceChildren();
        const row = table.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 6;
        cell.textContent = "Unable to load security alerts.";
        cell.className = "empty-message";
    }
}


function initializeAlertControls() {
    [
        "status-filter",
        "severity-filter",
        "type-filter",
        "source-search"
    ].forEach(id => {
        document.getElementById(id).addEventListener("input", () => {
            currentPage = 1;
            renderAlerts();
        });
    });

    document.getElementById("clear-filters").addEventListener(
        "click",
        () => {
            document.getElementById("status-filter").value = "all";
            document.getElementById("severity-filter").value = "all";
            document.getElementById("type-filter").value = "all";
            document.getElementById("source-search").value = "";
            currentPage = 1;
            renderAlerts();
        }
    );

    document.getElementById("previous-page").addEventListener(
        "click",
        () => {
            if (currentPage > 1) {
                currentPage -= 1;
                renderAlerts();
            }
        }
    );
    document.getElementById("next-page").addEventListener(
        "click",
        () => {
            const totalPages = Math.max(
                1,
                Math.ceil(getFilteredAlerts().length / alertsPerPage)
            );
            if (currentPage < totalPages) {
                currentPage += 1;
                renderAlerts();
            }
        }
    );
}


function renderAuditRecords() {
    const table = document.getElementById("audit-table");
    const totalPages = Math.max(
        1,
        Math.ceil(loadedAuditRecords.length / alertsPerPage)
    );
    auditPage = Math.min(auditPage, totalPages);
    const start = (auditPage - 1) * alertsPerPage;
    const pageRecords = loadedAuditRecords.slice(
        start,
        start + alertsPerPage
    );

    table.replaceChildren();

    if (loadedAuditRecords.length === 0) {
        const row = table.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 6;
        cell.textContent = "No audit records found.";
        cell.className = "empty-message";
    } else {
        pageRecords.forEach(record => {
            const row = table.insertRow();
            const timeCell = row.insertCell();
            const idCell = row.insertCell();
            const actorCell = row.insertCell();
            const oldStatusCell = row.insertCell();
            const newStatusCell = row.insertCell();
            const reasonCell = row.insertCell();

            timeCell.textContent = record.timestamp || "N/A";
            const fullId = record.alert_id || "N/A";
            idCell.textContent = fullId.slice(0, 8);
            idCell.title = fullId;
            actorCell.textContent = record.actor || "N/A";
            oldStatusCell.textContent = record.old_status || "N/A";
            newStatusCell.textContent = record.new_status || "N/A";
            reasonCell.textContent = record.reason || "N/A";
        });
    }

    document.getElementById("audit-page-indicator").textContent =
        `Page ${auditPage} of ${totalPages}`;
    document.getElementById("audit-previous-page").disabled = auditPage <= 1;
    document.getElementById("audit-next-page").disabled =
        auditPage >= totalPages;
}


async function loadAuditRecords() {
    try {
        const response = await fetch("/audit");
        if (!response.ok) {
            throw new Error("Unable to retrieve audit records");
        }

        const data = await response.json();
        loadedAuditRecords = (data.records || []).slice().reverse();
        renderAuditRecords();
    } catch (error) {
        console.error("Audit loading error:", error);
        const table = document.getElementById("audit-table");
        table.replaceChildren();
        const row = table.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 6;
        cell.textContent = "Unable to load audit records.";
        cell.className = "empty-message";
    }
}


function setDashboardTab(tab) {
    const isAudit = tab === "audit";
    const alertsTab = document.getElementById("alerts-tab");
    const auditTab = document.getElementById("audit-tab");

    alertsTab.setAttribute("aria-selected", String(!isAudit));
    alertsTab.tabIndex = isAudit ? -1 : 0;
    auditTab.setAttribute("aria-selected", String(isAudit));
    auditTab.tabIndex = isAudit ? 0 : -1;
    document.getElementById("alerts-panel").hidden = isAudit;
    document.getElementById("audit-panel").hidden = !isAudit;
}


function initializeDashboardTabs() {
    const tabs = [
        document.getElementById("alerts-tab"),
        document.getElementById("audit-tab")
    ];

    tabs.forEach((tab, index) => {
        tab.addEventListener("click", () => {
            setDashboardTab(tab.id === "audit-tab" ? "audit" : "alerts");
        });
        tab.addEventListener("keydown", event => {
            let nextIndex = index;
            if (event.key === "ArrowRight" || event.key === "ArrowDown") {
                nextIndex = (index + 1) % tabs.length;
            } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
                nextIndex = (index + tabs.length - 1) % tabs.length;
            } else if (event.key === "Home") {
                nextIndex = 0;
            } else if (event.key === "End") {
                nextIndex = tabs.length - 1;
            } else if (event.key === "Enter" || event.key === " ") {
                setDashboardTab(tab.id === "audit-tab" ? "audit" : "alerts");
                return;
            } else {
                return;
            }

            event.preventDefault();
            tabs[nextIndex].focus();
            setDashboardTab(
                tabs[nextIndex].id === "audit-tab" ? "audit" : "alerts"
            );
        });
    });

    document.getElementById("audit-previous-page").addEventListener(
        "click",
        () => {
            if (auditPage > 1) {
                auditPage -= 1;
                renderAuditRecords();
            }
        }
    );
    document.getElementById("audit-next-page").addEventListener(
        "click",
        () => {
            const totalPages = Math.max(
                1,
                Math.ceil(loadedAuditRecords.length / alertsPerPage)
            );
            if (auditPage < totalPages) {
                auditPage += 1;
                renderAuditRecords();
            }
        }
    );
}


function updateSummaryCards(data) {
    document.getElementById("open-alerts").textContent = data.open;
    document.getElementById("acknowledged-alerts").textContent =
        data.acknowledged;
    document.getElementById("resolved-alerts").textContent = data.resolved;

    const severity = data.severity || {};
    document.getElementById("critical-high-alerts").textContent =
        (severity.critical || 0) + (severity.high || 0);
}


const svgNamespace = "http://www.w3.org/2000/svg";


function createSvgElement(name, attributes = {}) {
    const element = document.createElementNS(svgNamespace, name);
    Object.entries(attributes).forEach(([key, value]) => {
        element.setAttribute(key, value);
    });
    return element;
}


function showTrendEmpty(container) {
    container.replaceChildren();
    const empty = document.createElement("p");
    empty.className = "empty-message";
    empty.textContent = "No data yet";
    container.appendChild(empty);
}


function renderHourlyChart(hourlyData) {
    const container = document.getElementById("alerts-per-hour-chart");
    if (!hourlyData.length) {
        showTrendEmpty(container);
        return;
    }

    const width = 700;
    const height = 240;
    const chart = createSvgElement("svg", {
        viewBox: `0 0 ${width} ${height}`,
        role: "img",
        "aria-label": "Bar chart showing alerts per hour for the last 24 hours"
    });
    const maxCount = Math.max(
        1,
        ...hourlyData.map(item => Number(item.count) || 0)
    );
    const chartLeft = 42;
    const chartTop = 18;
    const chartHeight = 165;
    const baseY = chartTop + chartHeight;
    const barWidth = 20;
    const gap = 7;
    const currentHour = new Date();
    const tickStep = Math.max(1, Math.ceil(maxCount / 5));

    for (let tick = 0; tick <= maxCount; tick += tickStep) {
        const y = baseY - (tick / maxCount) * chartHeight;
        const tickLabel = createSvgElement("text", {
            x: chartLeft - 7,
            y: y + 4,
            "text-anchor": "end",
            fill: "#94a3b8",
            "font-size": "10"
        });
        tickLabel.textContent = String(tick);
        chart.appendChild(tickLabel);
    }

    hourlyData.forEach((item, index) => {
        const count = Number(item.count) || 0;
        const barHeight = (count / maxCount) * chartHeight;
        const x = chartLeft + index * (barWidth + gap);
        const bar = createSvgElement("rect", {
            x,
            y: baseY - barHeight,
            width: barWidth,
            height: barHeight,
            rx: 2,
            fill: "#38bdf8"
        });
        const label = createSvgElement("text", {
            x: x + barWidth / 2,
            y: 220,
            "text-anchor": "middle",
            fill: "#94a3b8",
            "font-size": "9"
        });
        const itemDate = new Date(item.hour);
        const isCurrentHour =
            itemDate.toDateString() === currentHour.toDateString() &&
            itemDate.getHours() === currentHour.getHours();
        label.textContent = index % 3 === 0 || isCurrentHour
            ? itemDate.getHours().toString().padStart(2, "0")
            : "";
        if (count > 0) {
            const valueLabel = createSvgElement("text", {
                x: x + barWidth / 2,
                y: baseY - barHeight - 5,
                "text-anchor": "middle",
                fill: "#cbd5e1",
                "font-size": "10"
            });
            valueLabel.textContent = String(count);
            chart.appendChild(valueLabel);
        }
        const countLabel = createSvgElement("title");
        countLabel.textContent = `${item.hour}: ${count} alerts`;
        bar.appendChild(countLabel);
        chart.append(bar, label);
    });

    container.replaceChildren(chart);
}


function renderTopSourceIps(sourceData) {
    const container = document.getElementById("top-source-ips-chart");
    if (!sourceData.length) {
        showTrendEmpty(container);
        return;
    }

    const width = 600;
    const rowHeight = 34;
    const chart = createSvgElement("svg", {
        viewBox: `0 0 ${width} ${sourceData.length * rowHeight}`,
        role: "img",
        "aria-label": "Horizontal bar chart showing the top source IPs"
    });
    const maxCount = Math.max(
        1,
        ...sourceData.map(item => Number(item.count) || 0)
    );

    sourceData.forEach((item, index) => {
        const y = index * rowHeight + 8;
        const count = Number(item.count) || 0;
        const label = createSvgElement("text", {
            x: 8,
            y: y + 15,
            fill: "#cbd5e1",
            "font-size": "12"
        });
        label.textContent = item.source_ip || "Unknown";
        const bar = createSvgElement("rect", {
            x: 145,
            y,
            width: (count / maxCount) * 390,
            height: 20,
            rx: 3,
            fill: "#38bdf8"
        });
        const countLabel = createSvgElement("text", {
            x: 550,
            y: y + 15,
            fill: "#94a3b8",
            "font-size": "12"
        });
        countLabel.textContent = String(count);
        chart.append(label, bar, countLabel);
    });

    container.replaceChildren(chart);
}


async function loadTrends() {
    try {
        const response = await fetch("/api/trends");
        if (!response.ok) {
            throw new Error("Unable to retrieve alert trends");
        }

        const data = await response.json();
        renderHourlyChart(data.alerts_per_hour || []);
        renderTopSourceIps(data.top_source_ips || []);
    } catch (error) {
        console.error("Trend loading error:", error);
        showTrendEmpty(document.getElementById("alerts-per-hour-chart"));
        showTrendEmpty(document.getElementById("top-source-ips-chart"));
    }
}


function infrastructureBarClass(percent) {
    if (percent > 85) {
        return "infrastructure-bar-red";
    }
    if (percent >= 70) {
        return "infrastructure-bar-amber";
    }
    return "infrastructure-bar-green";
}


function renderInfrastructure(data) {
    const container = document.getElementById("infrastructure-content");
    container.replaceChildren();

    if (data.status !== "success" || !data.containers.length) {
        const message = document.createElement("p");
        message.className = "empty-message";
        message.textContent = "Infrastructure metrics unavailable";
        container.appendChild(message);
        return;
    }

    const table = document.createElement("table");
    const header = document.createElement("thead");
    const headerRow = document.createElement("tr");
    [
        "Container",
        "CPU",
        "Memory used",
        "Memory limit",
        "Memory usage"
    ].forEach(text => {
        const cell = document.createElement("th");
        cell.textContent = text;
        headerRow.appendChild(cell);
    });
    header.appendChild(headerRow);
    table.appendChild(header);

    const body = document.createElement("tbody");
    data.containers.forEach(item => {
        const row = document.createElement("tr");
        const name = row.insertCell();
        const cpu = row.insertCell();
        const used = row.insertCell();
        const limit = row.insertCell();
        const memory = row.insertCell();
        name.textContent = item.name;
        cpu.textContent = `${item.cpu_percent}%`;
        used.textContent = `${item.memory_used_mb} MB`;
        limit.textContent = `${item.memory_limit_mb} MB`;

        const percent = Number(item.memory_percent) || 0;
        const bar = document.createElement("progress");
        bar.className = `infrastructure-bar ${
            infrastructureBarClass(percent)
        }`;
        bar.max = "100";
        bar.value = String(Math.min(100, Math.max(0, percent)));
        bar.setAttribute("aria-label", `${percent}% memory usage`);
        const value = document.createElement("span");
        value.textContent = `${percent}%`;
        memory.append(bar, value);
        body.appendChild(row);
    });
    table.appendChild(body);
    container.appendChild(table);
}


async function loadInfrastructure() {
    try {
        const response = await fetch("/api/infrastructure");
        if (!response.ok) {
            throw new Error("Unable to retrieve infrastructure metrics");
        }
        renderInfrastructure(await response.json());
    } catch (error) {
        console.error("Infrastructure loading error:", error);
        renderInfrastructure({
            status: "unavailable",
            containers: []
        });
    }
}


async function loadSummary() {
    const updatedElement = document.getElementById("summary-last-updated");

    try {
        const response = await fetch("/api/summary");
        if (!response.ok) {
            throw new Error("Unable to retrieve alert summary");
        }

        const data = await response.json();
        updateSummaryCards(data);

        updatedElement.textContent =
            `Last updated: ${new Date().toLocaleTimeString()}`;
    } catch (error) {
        console.error("Alert summary loading error:", error);

        [
            "open-alerts",
            "acknowledged-alerts",
            "resolved-alerts",
            "critical-high-alerts"
        ].forEach(id => {
            document.getElementById(id).textContent = "Error";
        });
        updatedElement.textContent = "Last updated: Error";
    }
}


// Update security alert status
async function updateAlertStatus(alert, newStatus, button) {

    const message = document.getElementById("alert-message");
    const statusDetails = await openStatusDialog(alert, newStatus, button);

    if (!statusDetails) {
        return;
    }

    try {
        const response = await apiFetch(
            `/alerts/${encodeURIComponent(alert.alert_id)}/status`,
            {
                method: "PATCH",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    status: newStatus,
                    actor: statusDetails.actor,
                    reason: statusDetails.reason
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.message || "Unable to update alert status"
            );
        }

        showStatusMessage(data.message);

        // Reload alerts to display the updated status
        await loadAlerts();

    } catch (error) {
        console.error("Alert update error:", error);

        showStatusMessage(error.message, true);
    }
}


async function runDetection() {
    const button = document.getElementById("run-detection");
    const message = document.getElementById("alert-message");

    button.disabled = true;
    message.textContent = "Running detection...";
    message.className = "";

    try {
        const response = await apiFetch("/process-events", {
            method: "POST"
        });
        let data = {};

        try {
            data = await response.json();
        } catch {
            data = {};
        }

        if (!response.ok) {
            const statusMessage = response.status === 401
                ? "Unauthorized: enter a valid API key."
                : response.status === 503
                    ? "Detection service is not configured."
                    : data.message || `Detection failed (${response.status}).`;
            throw new Error(statusMessage);
        }

        showStatusMessage(
            `Processed ${data.events_processed || 0} events, ` +
            `${data.new_alerts || 0} new alerts, ` +
            `${data.duplicates_skipped || 0} duplicates skipped`
        );

        await Promise.all([loadAlerts(), loadSummary()]);
    } catch (error) {
        console.error("Detection run error:", error);
        showStatusMessage(error instanceof TypeError
            ? "Network error: unable to run detection."
            : error.message, true);
    } finally {
        button.disabled = false;
    }
}


// Check Flask API health
async function checkAPIStatus() {

    const statusElement = document.getElementById("api-status");

    try {
        const response = await fetch("/health");

        if (!response.ok) {
            throw new Error("API is not healthy");
        }

        const data = await response.json();

        statusElement.textContent =
            data.status === "healthy" ? "Healthy" : "Unhealthy";

    } catch (error) {
        console.error("API health check failed:", error);
        statusElement.textContent = "Offline";
    }
}


function formatLastDetection(timestamp) {
    if (!timestamp) {
        return "Last detection: Never";
    }

    const detectionTime = new Date(timestamp);
    const minutesAgo = Math.max(
        0,
        Math.floor((Date.now() - detectionTime.getTime()) / 60000)
    );
    return `Last detection: ${minutesAgo} minute${minutesAgo === 1 ? "" : "s"} ago`;
}


async function loadSystemStatus() {
    const statusText = document.getElementById("system-status-text");
    const statusDot = document.querySelector(".status-dot");
    const securityStatus = document.getElementById("security-status");
    const lastDetection = document.getElementById("last-detection");
    const apiStatus = document.getElementById("api-status");
    const systemStatus = document.querySelector(".system-status");

    try {
        const response = await fetch("/api/status");
        if (!response.ok) {
            throw new Error("Unable to retrieve system status");
        }

        const data = await response.json();
        const degraded = [data.api, data.database, data.exporter].some(
            status => status === "down" || status === "unknown"
        );

        statusText.textContent = degraded
            ? "Degraded"
            : "All systems operational";
        securityStatus.textContent = degraded ? "Degraded" : "Active";
        apiStatus.textContent = data.api === "up" ? "Healthy" : "Offline";
        lastDetection.textContent = formatLastDetection(
            data.last_detection_at
        );
        systemStatus.classList.toggle("system-status-degraded", degraded);
        statusDot.classList.toggle("status-dot-degraded", degraded);
    } catch (error) {
        console.error("System status loading error:", error);
        statusText.textContent = "Degraded";
        securityStatus.textContent = "Degraded";
        apiStatus.textContent = "Offline";
        lastDetection.textContent = "Last detection: Unknown";
        systemStatus.classList.add("system-status-degraded");
        statusDot.classList.add("status-dot-degraded");
    }
}


// Initialize dashboard
document.addEventListener("DOMContentLoaded", () => {

    document.getElementById("api-key").addEventListener(
        "input",
        event => {
            apiKey = event.target.value;
        }
    );
    document.getElementById("run-detection").addEventListener(
        "click",
        runDetection
    );
    initializeStatusDialog();
    initializeAlertControls();
    initializeDashboardTabs();
    initializeMonitoringLinks();
    document.getElementById("refresh-alerts").addEventListener(
        "click",
        loadAlerts
    );

    loadAlerts();
    loadSummary();
    loadAuditRecords();
    loadTrends();
    loadInfrastructure();

    loadSystemStatus();

    // Refresh dashboard data every 30 seconds
    setInterval(() => {
        loadAlerts();
        loadSummary();
        loadAuditRecords();
        loadTrends();
        loadInfrastructure();
        loadSystemStatus();
    }, 30000);

});
