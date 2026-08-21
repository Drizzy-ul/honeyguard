// HoneyGuard Interactive Attack Map (Leaflet.js)
let attackMap = null;
let markerLayer = null;
const markersByIP = new Map();

function initAttackMap() {
    const mapElement = document.getElementById("attack-map");
    if (!mapElement) return;

    // Center map on world view
    attackMap = L.map("attack-map", {
        center: [20, 0],
        zoom: 2,
        minZoom: 1,
        maxZoom: 12,
        worldCopyJump: true,
        zoomControl: true
    });

    // Dark Matter tile layer from CartoDB
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        attribution: '&copy; <a href="https://carto.com/">CARTO</a> | HoneyGuard SOC',
        subdomains: "abcd",
        maxZoom: 19
    }).addTo(attackMap);

    markerLayer = L.layerGroup().addTo(attackMap);
}

function getMarkerColor(severity) {
    switch (severity) {
        case "CRITICAL": return "#f85149";
        case "HIGH": return "#db6d28";
        case "MEDIUM": return "#d29922";
        default: return "#58a6ff";
    }
}

function addAttackMarker(event, shouldPulse = true) {
    if (!attackMap || !markerLayer) return;
    const lat = parseFloat(event.lat);
    const lon = parseFloat(event.lon);

    if (isNaN(lat) || isNaN(lon) || (lat === 0 && lon === 0)) {
        return;
    }

    const color = getMarkerColor(event.severity);
    const ip = event.src_ip;

    const popupHtml = `
        <div style="font-size: 12px; line-height: 1.4;">
            <div style="font-weight: 700; color: ${color}; margin-bottom: 4px;">
                🚨 ${event.severity} Attack on ${event.service}
            </div>
            <div><strong>IP:</strong> <code>${ip}</code></div>
            <div><strong>Location:</strong> ${event.city || 'Unknown'}, ${event.country || 'Unknown'} (${event.country_code || 'XX'})</div>
            <div><strong>ISP:</strong> ${event.org || 'Unknown'}</div>
            <div><strong>Risk Score:</strong> ${event.risk_score}/100</div>
            <div><strong>Time:</strong> ${new Date(event.timestamp).toLocaleTimeString()}</div>
        </div>
    `;

    // Create glowing circle marker
    const marker = L.circleMarker([lat, lon], {
        radius: 8,
        fillColor: color,
        color: "#fff",
        weight: 1.5,
        opacity: 0.9,
        fillOpacity: 0.75
    }).bindPopup(popupHtml);

    markerLayer.addLayer(marker);

    // If live event, create a brief radar ripple effect
    if (shouldPulse) {
        const pulseCircle = L.circleMarker([lat, lon], {
            radius: 8,
            fillColor: color,
            color: color,
            weight: 2,
            opacity: 1,
            fillOpacity: 0.4
        }).addTo(markerLayer);

        let currentRadius = 8;
        let opacity = 1;
        const interval = setInterval(() => {
            currentRadius += 4;
            opacity -= 0.1;
            if (opacity <= 0) {
                clearInterval(interval);
                markerLayer.removeLayer(pulseCircle);
            } else {
                pulseCircle.setRadius(currentRadius);
                pulseCircle.setStyle({ opacity: opacity, fillOpacity: opacity * 0.4 });
            }
        }, 60);
    }
}

function loadHistoricalMarkers(events) {
    if (!markerLayer) return;
    markerLayer.clearLayers();
    
    // Deduplicate by IP to keep map readable
    const seenIPs = new Set();
    events.forEach(e => {
        if (!seenIPs.has(e.src_ip)) {
            seenIPs.add(e.src_ip);
            addAttackMarker(e, false);
        }
    });
}
