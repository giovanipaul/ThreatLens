const elements = {
    uploadForm: document.querySelector("#upload-form"),
    uploadButton: document.querySelector("#upload-button"),
    uploadMessage: document.querySelector("#upload-message"),
    logFile: document.querySelector("#log-file"),
    logYear: document.querySelector("#log-year"),
    totalEvents: document.querySelector("#total-events"),
    failedEvents: document.querySelector("#failed-events"),
    successfulEvents: document.querySelector("#successful-events"),
    totalAlerts: document.querySelector("#total-alerts"),
    alertsTable: document.querySelector("#alerts-table"),
    alertsEmpty: document.querySelector("#alerts-empty"),
    eventsTable: document.querySelector("#events-table"),
    eventsEmpty: document.querySelector("#events-empty"),
    severityFilter: document.querySelector("#severity-filter"),
    resultFilter: document.querySelector("#result-filter"),
    ipFilter: document.querySelector("#ip-filter"),
    applyEventFilters: document.querySelector("#apply-event-filters"),
};

function createCell(value, className = "") {
    const cell = document.createElement("td");
    if (className) {
        const badge = document.createElement("span");
        badge.className = `badge ${className}`;
        badge.textContent = value;
        cell.append(badge);
    } else {
        cell.textContent = value;
    }
    return cell;
}

function formatTimestamp(value) {
    return new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
    }).format(new Date(value));
}

async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    if (!response.ok) {
        let message = `Request failed with status ${response.status}.`;
        try {
            const body = await response.json();
            message = body.detail || message;
        } catch {
            // Keep the status-based message when the response is not JSON.
        }
        throw new Error(message);
    }
    return response.json();
}

function renderEvents(events) {
    elements.eventsTable.replaceChildren();
    elements.eventsEmpty.style.display = events.length ? "none" : "block";

    for (const event of events) {
        const row = document.createElement("tr");
        row.append(
            createCell(formatTimestamp(event.timestamp)),
            createCell(event.result, event.result),
            createCell(event.username),
            createCell(`${event.source_ip}:${event.source_port}`),
            createCell(event.hostname),
            createCell(event.protocol),
        );
        elements.eventsTable.append(row);
    }
}

function renderAlerts(alerts) {
    elements.alertsTable.replaceChildren();
    elements.alertsEmpty.style.display = alerts.length ? "none" : "block";

    for (const alert of alerts) {
        const row = document.createElement("tr");
        row.append(
            createCell(alert.severity, alert.severity),
            createCell(alert.title),
            createCell(alert.source_ip),
            createCell(String(alert.event_count)),
            createCell(alert.usernames.join(", ")),
            createCell(formatTimestamp(alert.started_at)),
        );
        elements.alertsTable.append(row);
    }
}

async function loadEvents() {
    const parameters = new URLSearchParams({limit: "1000"});
    if (elements.resultFilter.value) {
        parameters.set("result", elements.resultFilter.value);
    }
    if (elements.ipFilter.value.trim()) {
        parameters.set("source_ip", elements.ipFilter.value.trim());
    }

    const events = await fetchJson(`/api/events?${parameters}`);
    renderEvents(events);
    return events;
}

async function loadAlerts() {
    const parameters = new URLSearchParams({limit: "1000"});
    if (elements.severityFilter.value) {
        parameters.set("severity", elements.severityFilter.value);
    }

    const alerts = await fetchJson(`/api/alerts?${parameters}`);
    renderAlerts(alerts);
    return alerts;
}

async function refreshDashboard() {
    try {
        const [allEvents, allAlerts] = await Promise.all([
            fetchJson("/api/events?limit=1000"),
            fetchJson("/api/alerts?limit=1000"),
        ]);
        elements.totalEvents.textContent = String(allEvents.length);
        elements.failedEvents.textContent = String(
            allEvents.filter((event) => event.result === "failure").length,
        );
        elements.successfulEvents.textContent = String(
            allEvents.filter((event) => event.result === "success").length,
        );
        elements.totalAlerts.textContent = String(allAlerts.length);
        await Promise.all([loadEvents(), loadAlerts()]);
    } catch (error) {
        elements.uploadMessage.textContent = error.message;
    }
}

elements.uploadForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!elements.logFile.files.length) {
        elements.uploadMessage.textContent = "Select a log file first.";
        return;
    }

    const formData = new FormData();
    formData.append("file", elements.logFile.files[0]);
    const yearQuery = elements.logYear.value
        ? `?year=${encodeURIComponent(elements.logYear.value)}`
        : "";

    elements.uploadButton.disabled = true;
    elements.uploadMessage.textContent = "Analyzing log file…";

    try {
        const summary = await fetchJson(`/api/logs/import${yearQuery}`, {
            method: "POST",
            body: formData,
        });
        elements.uploadMessage.textContent =
            `Parsed ${summary.events_parsed} events and saved ` +
            `${summary.events_saved} new records. Generated ` +
            `${summary.alerts_generated} alert(s).`;
        elements.uploadForm.reset();
        await refreshDashboard();
    } catch (error) {
        elements.uploadMessage.textContent = error.message;
    } finally {
        elements.uploadButton.disabled = false;
    }
});

elements.severityFilter.addEventListener("change", loadAlerts);
elements.applyEventFilters.addEventListener("click", loadEvents);

refreshDashboard();

