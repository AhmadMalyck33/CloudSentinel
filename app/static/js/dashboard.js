
/* =====================================
   CloudSentinel Dashboard
   Dynamic Data Integration
   Security Alert Management
===================================== */

// Load security alerts from Flask API
async function loadAlerts() {
    const table = document.getElementById("alerts-table");
    const message = document.getElementById("alert-message");

    try {
        const response = await fetch("/alerts");

        if (!response.ok) {
            throw new Error("Unable to retrieve security alerts");
        }

        const data = await response.json();
        const alerts = data.alerts || [];

        // Update total alerts
        document.getElementById("total-alerts").textContent =
            data.total_alerts ?? alerts.length;

        // Count high severity alerts
        // Count high severity alerts requiring attention
        const highAlerts = alerts.filter(
            alert =>
                alert.severity?.toLowerCase() === "high" &&
                ["open", "acknowledged"].includes(
                    alert.status?.toLowerCase()
                )
        ).length;

        // Update high severity alert counter
        document.getElementById("high-alerts").textContent =
            highAlerts;

        // Clear existing table rows
        table.replaceChildren();

        if (alerts.length === 0) {
            const row = table.insertRow();
            const cell = row.insertCell();

            cell.colSpan = 6;
            cell.textContent = "No security alerts found.";
            cell.className = "empty-message";

            return;
        }

        // Display newest alerts first
        alerts.slice().reverse().forEach(alert => {
            const row = table.insertRow();

            // Alert type
            const typeCell = row.insertCell();
            typeCell.textContent = alert.alert_type || "Unknown";

            // Source IP
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

                acknowledgeButton.addEventListener("click", () => {
                    updateAlertStatus(
                        alert.alert_id,
                        "acknowledged"
                    );
                });

                actionsCell.appendChild(acknowledgeButton);

            } else if (status === "acknowledged") {
                const resolveButton =
                    document.createElement("button");

                resolveButton.textContent = "Resolve";

                resolveButton.addEventListener("click", () => {
                    updateAlertStatus(
                        alert.alert_id,
                        "resolved"
                    );
                });

                actionsCell.appendChild(resolveButton);

            } else if (status === "resolved") {
                actionsCell.textContent = "Completed";
            }
        });

    } catch (error) {
        console.error("Alert loading error:", error);

        document.getElementById("total-alerts").textContent = "Error";
        document.getElementById("high-alerts").textContent = "Error";

        table.replaceChildren();

        const row = table.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 6;
        cell.textContent = "Unable to load security alerts.";
        cell.className = "empty-message";
    }
}


// Update security alert status
async function updateAlertStatus(alertId, newStatus) {

    const message = document.getElementById("alert-message");

    try {
        const response = await fetch(
            `/alerts/${encodeURIComponent(alertId)}/status`,
            {
                method: "PATCH",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    status: newStatus
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.message || "Unable to update alert status"
            );
        }

        message.textContent = data.message;
        message.className = "success-message";

        // Reload alerts to display the updated status
        await loadAlerts();

    } catch (error) {
        console.error("Alert update error:", error);

        message.textContent = error.message;
        message.className = "error-message";
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


// Initialize dashboard
document.addEventListener("DOMContentLoaded", () => {

    loadAlerts();

    checkAPIStatus();

    // Refresh dashboard data every 30 seconds
    setInterval(() => {
        loadAlerts();
        checkAPIStatus();
    }, 30000);

});
