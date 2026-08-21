// HoneyGuard SOC Dashboard Application

let socket = null;
let soundEnabled = false;
let audioCtx = null;
let charts = {};
let allEventsCache = [];

// Sound notification using Web Audio API
function playAlertBeep(severity = "LOW") {
    if (!soundEnabled) return;
    try {
        if (!audioCtx) {
            audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        }
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);

        if (severity === "CRITICAL") {
            osc.frequency.setValueAtTime(880, audioCtx.currentTime); // High pitch alarm
            osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.15);
        } else if (severity === "HIGH") {
            osc.frequency.setValueAtTime(659, audioCtx.currentTime);
        } else {
            osc.frequency.setValueAtTime(440, audioCtx.currentTime);
        }

        gain.gain.setValueAtTime(0.1, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.15);

        osc.start();
        osc.stop(audioCtx.currentTime + 0.15);
    } catch (e) {
        console.error("Audio error:", e);
    }
}

// WebSocket Live Stream Connection
function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/live`;
    
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        console.log("[WS] Connected to HoneyGuard Live Attack Stream");
        const pill = document.getElementById("connection-status");
        if (pill) {
            pill.innerHTML = '<span class="status-dot"></span> LIVE FEED ACTIVE';
            pill.style.color = 'var(--accent-green)';
            pill.style.borderColor = 'rgba(63, 185, 80, 0.4)';
        }
    };

    socket.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === "NEW_ATTACK") {
                handleNewAttack(msg.data);
            }
        } catch (e) {
            console.error("WS Parse error:", e);
        }
    };

    socket.onclose = () => {
        console.warn("[WS] Disconnected from Live Attack Stream. Reconnecting in 3s...");
        const pill = document.getElementById("connection-status");
        if (pill) {
            pill.innerHTML = '<span class="status-dot" style="background-color: var(--accent-red); box-shadow: 0 0 8px var(--accent-red);"></span> DISCONNECTED';
            pill.style.color = 'var(--accent-red)';
            pill.style.borderColor = 'rgba(248, 81, 73, 0.4)';
        }
        setTimeout(connectWebSocket, 3000);
    };
}

function handleNewAttack(attack) {
    allEventsCache.unshift(attack);
    playAlertBeep(attack.severity);
    addAttackMarker(attack, true);
    prependAttackTableRow(attack, true);
    refreshStats();
}

function prependAttackTableRow(attack, isNew = false) {
    const tbody = document.getElementById("threat-feed-body");
    if (!tbody) return;

    const row = document.createElement("tr");
    row.className = `threat-row ${isNew ? 'new-flash' : ''}`;

    const dateStr = new Date(attack.timestamp).toLocaleTimeString();
    const tagsHtml = (Array.isArray(attack.ioc_tags) ? attack.ioc_tags : [])
        .map(t => `<span class="tag-pill">${t}</span>`).join(" ");

    let targetDetail = "-";
    if (attack.service === "SSH") {
        if (attack.username || attack.password) {
            targetDetail = `<code>${attack.username || '?'}:${attack.password || '••••'}</code>`;
        } else if (attack.payload) {
            targetDetail = `<code style="color: var(--accent-cyan);">$ ${escapeHtml(attack.payload)}</code>`;
        }
    } else if (attack.service === "HTTP") {
        targetDetail = `<code>${attack.http_method || 'GET'} ${escapeHtml(attack.http_path || '/')}</code>`;
    }

    row.innerHTML = `
        <td style="font-family: monospace; color: var(--text-muted);">${dateStr}</td>
        <td><span class="badge-sev ${attack.severity}">${attack.severity}</span></td>
        <td><strong style="color: ${attack.service === 'SSH' ? 'var(--accent-purple)' : 'var(--accent-blue)'};">${attack.service}</strong></td>
        <td>
            <div style="font-family: monospace; font-weight: 600;">${attack.src_ip}</div>
            <div style="font-size: 11px; color: var(--text-secondary);">${attack.city || 'Unknown'}, ${attack.country || 'Unknown'}</div>
        </td>
        <td>${targetDetail}</td>
        <td>${tagsHtml || '<span style="color: var(--text-muted);">None</span>'}</td>
        <td style="text-align: right;">
            <button class="btn" style="padding: 4px 8px; font-size: 11px;" onclick="openDetailModal(${JSON.stringify(attack).replace(/"/g, '&quot;')})">Inspect</button>
        </td>
    `;

    if (tbody.firstChild) {
        tbody.insertBefore(row, tbody.firstChild);
    } else {
        tbody.appendChild(row);
    }

    // Keep table limited to latest 100 rows for DOM performance
    while (tbody.children.length > 100) {
        tbody.removeChild(tbody.lastChild);
    }
}

function escapeHtml(text) {
    if (!text) return "";
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

async function loadInitialData() {
    try {
        // Load stats
        await refreshStats();

        // Load recent events
        const res = await fetch("/api/events?limit=50");
        const data = await res.json();
        allEventsCache = data.events || [];

        const tbody = document.getElementById("threat-feed-body");
        if (tbody) {
            tbody.innerHTML = "";
            allEventsCache.forEach(e => prependAttackTableRow(e, false));
        }

        loadHistoricalMarkers(allEventsCache);
        loadIoCTable();
    } catch (e) {
        console.error("Failed to load initial honeypot telemetry:", e);
    }
}

async function refreshStats() {
    try {
        const res = await fetch("/api/stats");
        const stats = await res.json();

        // KPI Counters
        document.getElementById("kpi-total-attacks").innerText = stats.total_events || 0;
        document.getElementById("kpi-unique-ips").innerText = stats.unique_attackers || 0;
        document.getElementById("kpi-high-risk").innerText = stats.high_risk_count || 0;

        // Port badges
        if (stats.services_status) {
            document.getElementById("badge-ssh-port").innerText = `SSH:${stats.services_status.ssh_port}`;
            document.getElementById("badge-http-port").innerText = `HTTP:${stats.services_status.http_port}`;
        }

        updateCharts(stats);
    } catch (e) {
        console.error("Failed to refresh stats:", e);
    }
}

async function loadIoCTable() {
    try {
        const res = await fetch("/api/iocs");
        const data = await res.json();
        const tbody = document.getElementById("ioc-table-body");
        if (!tbody) return;

        tbody.innerHTML = "";
        (data.iocs || []).forEach(ioc => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><span class="tag-pill" style="color: var(--accent-blue);">${ioc.ioc_type}</span></td>
                <td><code style="font-weight: 600; color: #fff;">${escapeHtml(ioc.ioc_value)}</code></td>
                <td><span class="badge-sev ${ioc.threat_level}">${ioc.threat_level}</span></td>
                <td style="font-family: monospace;">${ioc.hit_count}</td>
                <td style="font-size: 11px; color: var(--text-secondary);">${new Date(ioc.last_seen).toLocaleString()}</td>
                <td style="font-size: 12px; color: var(--text-muted);">${escapeHtml(ioc.notes || '-')}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Failed to load IoCs:", e);
    }
}

function updateCharts(stats) {
    // 1. MITRE ATT&CK / Vectors Chart (Doughnut)
    const mitreLabels = (stats.top_mitre || []).map(m => m.mitre_technique ? m.mitre_technique.split(" ")[0] : "Other");
    const mitreCounts = (stats.top_mitre || []).map(m => m.count);

    if (charts.mitre) charts.mitre.destroy();
    const ctxMitre = document.getElementById("chart-mitre")?.getContext("2d");
    if (ctxMitre) {
        charts.mitre = new Chart(ctxMitre, {
            type: "doughnut",
            data: {
                labels: mitreLabels.length ? mitreLabels : ["No data"],
                datasets: [{
                    data: mitreCounts.length ? mitreCounts : [1],
                    backgroundColor: ["#f85149", "#db6d28", "#d29922", "#58a6ff", "#bc8cff", "#39c5bb"]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "right", labels: { color: "#8b949e", font: { size: 11 } } }
                }
            }
        });
    }

    // 2. Top Attacking Countries Chart (Bar)
    const countryLabels = (stats.top_countries || []).map(c => `${c.country} (${c.country_code})`);
    const countryCounts = (stats.top_countries || []).map(c => c.count);

    if (charts.countries) charts.countries.destroy();
    const ctxCountries = document.getElementById("chart-countries")?.getContext("2d");
    if (ctxCountries) {
        charts.countries = new Chart(ctxCountries, {
            type: "bar",
            data: {
                labels: countryLabels.length ? countryLabels : ["No data"],
                datasets: [{
                    label: "Attacks",
                    data: countryCounts.length ? countryCounts : [0],
                    backgroundColor: "#58a6ff",
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: "#8b949e", font: { size: 10 } }, grid: { display: false } },
                    y: { ticks: { color: "#8b949e" }, grid: { color: "rgba(48, 54, 61, 0.4)" } }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    // 3. Top Tried Passwords
    const passLabels = (stats.top_passwords || []).map(p => p.password);
    const passCounts = (stats.top_passwords || []).map(p => p.count);

    if (charts.passwords) charts.passwords.destroy();
    const ctxPass = document.getElementById("chart-passwords")?.getContext("2d");
    if (ctxPass) {
        charts.passwords = new Chart(ctxPass, {
            type: "bar",
            data: {
                labels: passLabels.length ? passLabels : ["No data"],
                datasets: [{
                    label: "Attempts",
                    data: passCounts.length ? passCounts : [0],
                    backgroundColor: "#bc8cff",
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: "#8b949e" }, grid: { color: "rgba(48, 54, 61, 0.4)" } },
                    y: { ticks: { color: "#8b949e", font: { family: "monospace" } }, grid: { display: false } }
                },
                plugins: { legend: { display: false } }
            }
        });
    }
}

// Modal Inspector
function openDetailModal(eventObj) {
    const modal = document.getElementById("event-modal");
    const container = document.getElementById("modal-event-details");
    if (!modal || !container) return;

    container.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <h3 style="font-size: 18px; color: #fff;">Threat Event #${eventObj.id}</h3>
            <span class="badge-sev ${eventObj.severity}">${eventObj.severity} RISK (${eventObj.risk_score}/100)</span>
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 13px; margin-bottom: 16px;">
            <div><strong>Service:</strong> <span style="color: var(--accent-blue); font-weight: 600;">${eventObj.service}</span></div>
            <div><strong>Event Type:</strong> <code>${eventObj.event_type}</code></div>
            <div><strong>Attacker IP:</strong> <code>${eventObj.src_ip}:${eventObj.src_port}</code></div>
            <div><strong>Origin:</strong> ${eventObj.city || 'Unknown'}, ${eventObj.country || 'Unknown'} (${eventObj.country_code})</div>
            <div><strong>ISP / Org:</strong> ${eventObj.org || 'Unknown'}</div>
            <div><strong>MITRE Technique:</strong> <code style="color: var(--accent-yellow);">${eventObj.mitre_technique || 'N/A'}</code></div>
        </div>
        <div>
            <strong>Raw JSON Telemetry:</strong>
            <pre class="code-box">${escapeHtml(JSON.stringify(eventObj, null, 2))}</pre>
        </div>
    `;

    modal.classList.add("active");
}

function closeModal() {
    const modal = document.getElementById("event-modal");
    if (modal) modal.classList.remove("active");
}

// Simulation Launcher
async function launchSimulation(scenario) {
    const btn = event?.currentTarget;
    if (btn) btn.disabled = true;

    try {
        const res = await fetch("/api/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario: scenario })
        });
        const data = await res.json();
        console.log("Simulation started:", data);
    } catch (e) {
        alert("Failed to launch simulation: " + e.message);
    } finally {
        if (btn) btn.disabled = false;
    }
}

// Tab Switching
function switchTab(tabId) {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

    const btn = document.getElementById(`tab-btn-${tabId}`);
    const content = document.getElementById(`tab-content-${tabId}`);

    if (btn) btn.classList.add("active");
    if (content) content.classList.add("active");

    if (tabId === "iocs") {
        loadIoCTable();
    }
}

// Audio Toggle
function toggleAudio() {
    soundEnabled = !soundEnabled;
    const btn = document.getElementById("btn-sound-toggle");
    if (btn) {
        btn.innerHTML = soundEnabled ? 'Sound: ON' : 'Sound: OFF';
        btn.style.color = soundEnabled ? 'var(--accent-green)' : 'var(--text-secondary)';
    }
}

// Filter Event Table
function filterTable() {
    const search = document.getElementById("search-input")?.value.toLowerCase() || "";
    const serviceFilter = document.getElementById("filter-service")?.value || "ALL";
    const severityFilter = document.getElementById("filter-severity")?.value || "ALL";

    const rows = document.querySelectorAll("#threat-feed-body tr");
    rows.forEach(r => {
        const text = r.innerText.toLowerCase();
        const matchesSearch = !search || text.includes(search);
        r.style.display = matchesSearch ? "" : "none";
    });
}

// Initializer
document.addEventListener("DOMContentLoaded", () => {
    initAttackMap();
    connectWebSocket();
    loadInitialData();

    // Auto-refresh stats every 10s
    setInterval(refreshStats, 10000);
});
