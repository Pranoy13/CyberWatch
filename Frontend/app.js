// ========== GLOBALS ==========
const API = "https://cyberwatch-x1ek.onrender.com";
let packetInterval = null;
let alertInterval  = null;
let lineData       = [];
let pieChartObj    = null;
let lineChartObj   = null;
let ipChartObj     = null;

window.lastLogData    = {};
window.lastScanData   = {};
window.lastPacketData = [];
window.lastThreatData = [];
window.lastScrapeData = {};

// ========== INIT ==========
document.addEventListener("DOMContentLoaded", () => {
    initMatrix();

    const overlay = document.getElementById("loginOverlay");
    if (localStorage.getItem("cw_loggedIn") === "true") {
        overlay.style.display = "none";
        const u = localStorage.getItem("cw_user") || "Analyst";
        const sidebarUser = document.getElementById("sidebarUser");
        const avatar = document.getElementById("userAvatar");
        if (sidebarUser) sidebarUser.innerText = u;
        if (avatar) avatar.innerText = u.charAt(0).toUpperCase();
        initDashboard();
    } else {
        overlay.style.display = "flex";
    }

    const passInput = document.getElementById("loginPass");
    if (passInput) {
        passInput.addEventListener("input", () => {
            const p   = passInput.value;
            const bar = document.getElementById("strengthBar");
            const txt = document.getElementById("pwdStrength");
            let score = 0;
            if (p.length >= 8)        score++;
            if (p.length >= 12)       score++;
            if (/[A-Z]/.test(p))      score++;
            if (/[0-9]/.test(p))      score++;
            if (/[!@#$%^&*]/.test(p)) score++;
            const pct    = Math.round((score / 5) * 100);
            const colors = ["#ef4444","#ef4444","#f59e0b","#f59e0b","#10b981","#8b5cf6"];
            const labels = ["","Weak ❌","Fair ⚠️","Good 👍","Strong ✅","Excellent 🔥"];
            const color  = colors[score] || "#ef4444";
            const label  = labels[score] || "";
            if (bar) {
                bar.style.width     = pct + "%";
                bar.style.background = color;
                bar.style.boxShadow = `0 0 8px ${color}`;
            }
            if (txt) {
                txt.innerText   = p ? `Password strength: ${label}` : "";
                txt.style.color = color;
            }
        });
    }
});

// ========== MATRIX BACKGROUND ==========
function initMatrix() {
    const canvas = document.getElementById("matrixCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
    const chars    = "01アイウエオカキクケコサシスセソタチツテトナニヌネノ";
    const fontSize = 14;
    const cols     = Math.floor(canvas.width / fontSize);
    const drops    = Array(cols).fill(1);
    function draw() {
        ctx.fillStyle = "rgba(7,3,15,0.05)";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = "#8b5cf6";
        ctx.font      = fontSize + "px monospace";
        drops.forEach((y, i) => {
            const char = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(char, i * fontSize, y * fontSize);
            if (y * fontSize > canvas.height && Math.random() > 0.975)
                drops[i] = 0;
            drops[i]++;
        });
    }
    setInterval(draw, 50);
    window.addEventListener("resize", () => {
        canvas.width  = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// ========== SHOW/HIDE PASSWORD ==========
function togglePassword() {
    const pass = document.getElementById("loginPass");
    const eye  = document.getElementById("eyeIcon");
    if (pass.type === "password") {
        pass.type     = "text";
        eye.innerText = "🙈";
    } else {
        pass.type     = "password";
        eye.innerText = "👁";
    }
}

// ========== LOGIN PAGE AUDIT ==========
function toggleAudit() {
    const box = document.getElementById("loginAuditBox");
    box.classList.toggle("open");
}

function auditPasswordInline() {
    const pwd = document.getElementById("auditPwdLogin").value;
    const out = document.getElementById("auditInlineResult");
    if (!pwd) { out.innerHTML = ""; return; }
    let score = 0;
    if (pwd.length >= 8)            score++;
    if (pwd.length >= 12)           score++;
    if (/[A-Z]/.test(pwd))          score++;
    if (/[0-9]/.test(pwd))          score++;
    if (/[!@#$%^&*()_+]/.test(pwd)) score++;
    const pct    = Math.round((score / 5) * 100);
    const colors = ["#ef4444","#ef4444","#f59e0b","#f59e0b","#10b981","#8b5cf6"];
    const labels = ["Very Weak","Weak","Fair","Good","Strong","Excellent"];
    const color  = colors[score] || "#ef4444";
    const label  = labels[score] || "Very Weak";
    out.innerHTML = `
        <div style="display:flex;justify-content:space-between;
            margin-bottom:6px;font-size:12px;">
            <span style="color:${color};font-weight:700;">${label}</span>
            <span style="color:var(--text-muted);">${pct}%</span>
        </div>
        <div style="background:rgba(255,255,255,0.05);border-radius:10px;
            height:4px;overflow:hidden;">
            <div style="width:${pct}%;height:100%;background:${color};
                border-radius:10px;transition:0.4s;"></div>
        </div>`;
}

// ========== LOGIN ==========
async function doLogin() {
    const u   = document.getElementById("loginUser").value.trim();
    const p   = document.getElementById("loginPass").value.trim();
    const msg = document.getElementById("loginMsg");
    if (!u || !p) {
        msg.style.color = "#f59e0b";
        msg.innerText   = "⚠️ Enter both username and password";
        return;
    }
    msg.style.color = "#94a3b8";
    msg.innerText   = "⏳ Logging in...";
    try {
        const res  = await fetch(`${API}/login`, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ username: u, password: p })
        });
        const data = await res.json();
        if (data.status === "success") {
            localStorage.setItem("cw_loggedIn", "true");
            localStorage.setItem("cw_user", u);
            document.getElementById("loginOverlay").style.display = "none";
            const sidebarUser = document.getElementById("sidebarUser");
            const avatar      = document.getElementById("userAvatar");
            if (sidebarUser) sidebarUser.innerText = u;
            if (avatar)      avatar.innerText      = u.charAt(0).toUpperCase();
            initDashboard();
        } else {
            msg.style.color = "#ef4444";
            msg.innerText   = "❌ Wrong credentials. If new user, click Register first.";
        }
    } catch {
        msg.style.color = "#f59e0b";
        msg.innerText   = "⚠️ Server waking up (free tier). Wait 30 seconds and try again.";
    }
}

// ========== REGISTER ==========
async function doRegister() {
    const u   = document.getElementById("loginUser").value.trim();
    const p   = document.getElementById("loginPass").value.trim();
    const msg = document.getElementById("loginMsg");
    if (!u || !p) {
        msg.style.color = "#f59e0b";
        msg.innerText   = "⚠️ Enter username and password first";
        return;
    }
    if (p.length < 6) {
        msg.style.color = "#ef4444";
        msg.innerText   = "❌ Password must be at least 6 characters";
        return;
    }
    msg.style.color = "#94a3b8";
    msg.innerText   = "⏳ Registering...";
    try {
        const res  = await fetch(`${API}/register`, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ username: u, password: p })
        });
        const data = await res.json();
        if (data.status === "registered") {
            msg.style.color = "#10b981";
            msg.innerText   = `✅ Account "${u}" created! Now click Login.`;
            document.querySelector(".btn-login").style.boxShadow =
                "0 0 20px rgba(16,185,129,0.5)";
            setTimeout(() => {
                document.querySelector(".btn-login").style.boxShadow = "";
            }, 3000);
        } else {
            msg.style.color = "#f59e0b";
            msg.innerText   = `⚠️ Username "${u}" already taken. Try another or just login.`;
        }
    } catch {
        msg.style.color = "#ef4444";
        msg.innerText   = "⚠️ Server waking up, wait 30 seconds and try again.";
    }
}

// ========== LOGOUT ==========
function doLogout() {
    localStorage.removeItem("cw_loggedIn");
    localStorage.removeItem("cw_user");
    clearInterval(packetInterval);
    clearInterval(alertInterval);
    location.reload();
}

// ========== SECTION NAVIGATION ==========
function showSection(id) {
    document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));
    document.querySelectorAll(".sidebar ul li").forEach(li => li.classList.remove("active"));
    document.getElementById(id).classList.add("active");
    const nav = document.getElementById("nav-" + id);
    if (nav) nav.classList.add("active");
}

// ========== DASHBOARD ==========
function initDashboard() {
    drawPieChart(1, 0);
    drawLineChart();
    updateDashboard();
    alertInterval = setInterval(pollAlerts, 5000);
    setInterval(updateDashboard, 10000);
}

function updateDashboard() {
    document.getElementById("dc-packets").innerText = window.lastPacketData.length || "—";
    document.getElementById("dc-threats").innerText = window.lastThreatData.length || "—";
    updateRiskScore();
}

function updateRiskScore() {
    const threats = window.lastThreatData.length || 0;
    const failed  = window.lastLogData.failed    || 0;
    let score = Math.max(0, Math.min(100, 100 - (threats * 10) - (failed * 2)));
    document.getElementById("riskScore").innerText = score;
    const el = document.getElementById("riskStatus");
    if (score >= 80) {
        document.getElementById("riskScore").style.color = "#22c55e";
        el.innerText = "🟢 System Secure";
    } else if (score >= 50) {
        document.getElementById("riskScore").style.color = "#eab308";
        el.innerText = "🟡 Moderate Risk";
    } else {
        document.getElementById("riskScore").style.color = "#ef4444";
        el.innerText = "🔴 High Risk — Immediate Action Required";
    }
}

// ========== CHARTS ==========
function drawPieChart(safe, threat) {
    const ctx = document.getElementById("pieChart");
    if (!ctx) return;
    if (pieChartObj) pieChartObj.destroy();
    pieChartObj = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: ["Safe", "Threat"],
            datasets: [{ data: [safe, threat],
                backgroundColor: ["#22c55e","#ef4444"],
                borderWidth: 0 }]
        },
        options: {
            responsive: true,
            plugins: { legend: { labels: { color: "#94a3b8" } } },
            cutout: "65%"
        }
    });
}

function drawLineChart() {
    const ctx = document.getElementById("lineChart");
    if (!ctx) return;
    if (lineChartObj) lineChartObj.destroy();
    lineData = Array(10).fill(0);
    lineChartObj = new Chart(ctx, {
        type: "line",
        data: {
            labels: lineData.map((_, i) => `${i * 10}s`),
            datasets: [{
                label: "Packets/interval",
                data: lineData,
                borderColor: "#8b5cf6",
                backgroundColor: "rgba(139,92,246,0.08)",
                tension: 0.4, fill: true, pointRadius: 3
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: { ticks: { color: "#475569" }, grid: { color: "#1e293b" } },
                y: { ticks: { color: "#475569" }, grid: { color: "#1e293b" }, beginAtZero: true }
            },
            plugins: { legend: { labels: { color: "#94a3b8" } } }
        }
    });
}

function updateLineChart(count) {
    if (!lineChartObj) return;
    lineData.push(count);
    if (lineData.length > 10) lineData.shift();
    lineChartObj.data.datasets[0].data = [...lineData];
    lineChartObj.update();
}

function drawIPChart(ipStats) {
    const ctx = document.getElementById("ipChart");
    if (!ctx) return;
    if (ipChartObj) ipChartObj.destroy();
    const labels = Object.keys(ipStats).slice(0, 10);
    const values = labels.map(k => ipStats[k]);
    ipChartObj = new Chart(ctx, {
        type: "bar",
        data: {
            labels,
            datasets: [{
                label: "Failed Attempts",
                data: values,
                backgroundColor: "rgba(239,68,68,0.6)",
                borderColor: "#ef4444",
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: { ticks: { color: "#475569", maxRotation: 45 }, grid: { color: "#1e293b" } },
                y: { ticks: { color: "#475569" }, grid: { color: "#1e293b" }, beginAtZero: true }
            },
            plugins: { legend: { labels: { color: "#94a3b8" } } }
        }
    });
}

// ========== ALERT POPUPS ==========
async function pollAlerts() {
    try {
        const res  = await fetch(`${API}/alerts`);
        const data = await res.json();
        if (!Array.isArray(data)) return;
        const box = document.getElementById("dashAlerts");
        if (data.length === 0) {
            box.innerHTML = `<span style="color:#475569">No alerts yet — system monitoring active.</span>`;
            return;
        }
        box.innerHTML = data.slice(-5).reverse().map(a => `
            <div style="padding:8px 12px;border-radius:8px;margin-bottom:6px;
                background:rgba(239,68,68,0.08);border:1px solid #ef444450;
                font-size:13px;color:#fca5a5;">${a.msg}</div>`).join("");
        const latest = data[data.length - 1];
        showPopup(latest.msg, latest.type || "critical");
        updateDashboard();
    } catch {}
}

function showPopup(msg, type = "critical") {
    const container = document.getElementById("alertContainer");
    const div       = document.createElement("div");
    div.className   = `alert-popup ${type}`;
    div.innerText   = msg;
    div.onclick     = () => div.remove();
    container.appendChild(div);
    if (type === "critical") playAlertSound();
    setTimeout(() => div.remove(), 5000);
}

// ========== ALERT SOUND ==========
function playAlertSound() {
    try {
        const ctx        = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = ctx.createOscillator();
        const gainNode   = ctx.createGain();
        oscillator.connect(gainNode);
        gainNode.connect(ctx.destination);
        oscillator.type            = "sine";
        oscillator.frequency.value = 880;
        gainNode.gain.setValueAtTime(0.3, ctx.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.6);
        oscillator.start(ctx.currentTime);
        oscillator.stop(ctx.currentTime + 0.6);
    } catch {}
}

// ========== LOG ANALYSIS ==========
async function uploadLogs() {
    const file = document.getElementById("logFile").files[0];
    if (!file) { showPopup("⚠️ Please select a file first", "warning"); return; }
    const out  = document.getElementById("logOutput");
    out.innerHTML = `<span class="spinner"></span> Analyzing logs...`;
    const text = await file.text();
    try {
        const res  = await fetch(`${API}/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ logs: text })
        });
        const data = await res.json();
        if (data.error) { out.innerHTML = `<span style="color:#ef4444">Error: ${data.error}</span>`; return; }
        window.lastLogData = data;
        document.getElementById("dc-logs").innerText = data.total;
        drawPieChart(data.total - data.failed, data.failed);
        updateRiskScore();
        let suspHTML = "";
        if (data.suspicious && data.suspicious.length > 0) {
            suspHTML = `
            <div class="alert-box">
                <h4>🚨 Brute Force Detected — Suspicious IPs</h4>
                ${data.suspicious.map(s =>
                    `<p>• <strong>${s.ip}</strong> — ${s.attempts} failed attempts
                    <span class="badge badge-red">${s.risk}</span></p>`
                ).join("")}
            </div>`;
        }
        const rows = (data.logs || []).slice(0, 50).map(l => {
            const badge = l.risk === "High" ? "badge-red"
                        : l.risk === "Medium" ? "badge-yellow" : "badge-green";
            return `<tr>
                <td>${l.ip}</td>
                <td><span class="badge ${badge}">${l.risk}</span></td>
                <td style="font-size:11px;color:#64748b;">${l.raw}</td>
            </tr>`;
        }).join("");
        out.innerHTML = `
            <div class="stat-row">
                <div class="stat-box">
                    <div class="s-label">Total Entries</div>
                    <div class="s-value">${data.total}</div>
                </div>
                <div class="stat-box">
                    <div class="s-label">Failed / High Risk</div>
                    <div class="s-value red">${data.failed}</div>
                </div>
                <div class="stat-box">
                    <div class="s-label">Unique IPs</div>
                    <div class="s-value blue">${data.unique_ips}</div>
                </div>
            </div>
            ${suspHTML}
            <canvas id="ipChart" style="max-height:200px;margin-bottom:20px;"></canvas>
            <div class="btn-row">
                <button class="btn btn-secondary"
                    onclick="downloadJSON(window.lastLogData,'log_report')">
                    ⬇ Download Log Report
                </button>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr>
                        <th>IP Address</th><th>Risk</th><th>Log Line</th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>`;
        if (data.ip_stats) drawIPChart(data.ip_stats);
    } catch {
        out.innerHTML = `<span style="color:#ef4444">Failed to connect to backend.</span>`;
    }
}

// ========== NETWORK SCAN ==========
async function scanIP() {
    const ip  = document.getElementById("scanIP").value.trim();
    const out = document.getElementById("scanOutput");
    if (!ip) { showPopup("⚠️ Enter an IP address", "warning"); return; }
    out.innerHTML = `<span class="spinner"></span> Scanning ${ip}...`;
    try {
        const res  = await fetch(`${API}/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip })
        });
        const data = await res.json();
        if (data.error) { out.innerHTML = `<span style="color:#ef4444">Error: ${data.error}</span>`; return; }
        window.lastScanData = data;
        document.getElementById("dc-ports").innerText = data.open;
        const rows = (data.ports || []).map(p => {
            const badge     = p.risk.includes("High") ? "badge-red"
                            : p.risk.includes("Medium") ? "badge-yellow" : "badge-green";
            const statBadge = p.status === "open" ? "badge-green" : "badge-yellow";
            return `<tr>
                <td><strong>${p.port}</strong></td>
                <td><span class="badge ${statBadge}">${p.status}</span></td>
                <td>${p.service}</td>
                <td><span class="badge ${badge}">${p.risk}</span></td>
            </tr>`;
        }).join("");
        out.innerHTML = `
            <div class="stat-row">
                <div class="stat-box">
                    <div class="s-label">Target IP</div>
                    <div class="s-value blue" style="font-size:16px;">${data.ip}</div>
                </div>
                <div class="stat-box">
                    <div class="s-label">Open Ports</div>
                    <div class="s-value green">${data.open}</div>
                </div>
                <div class="stat-box">
                    <div class="s-label">Filtered</div>
                    <div class="s-value yellow">${data.filtered}</div>
                </div>
            </div>
            <div class="btn-row">
                <button class="btn btn-secondary"
                    onclick="downloadJSON(window.lastScanData,'scan_report')">
                    ⬇ Download Scan Report
                </button>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr>
                        <th>Port</th><th>Status</th><th>Service</th><th>Risk</th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>`;
    } catch {
        out.innerHTML = `<span style="color:#ef4444">Failed to connect to backend.</span>`;
    }
}

// ========== PACKET CAPTURE ==========
function startPacket() {
    if (packetInterval) clearInterval(packetInterval);
    fetchPackets();
    packetInterval = setInterval(fetchPackets, 10000);
    showPopup("▶ Packet capture started", "safe");
}

function stopPacket() {
    clearInterval(packetInterval);
    packetInterval = null;
    showPopup("⏹ Packet capture stopped", "warning");
}

async function fetchPackets() {
    try {
        const res  = await fetch(`${API}/packet`);
        const data = await res.json();
        if (!Array.isArray(data)) return;
        window.lastPacketData = data;
        document.getElementById("dc-packets").innerText = data.length;
        updateLineChart(data.length);
        const out = document.getElementById("packetOutput");
        if (data.length === 0) {
            out.innerHTML = `<span style="color:#475569">No packets captured yet.</span>`;
            return;
        }
        const rows = data.slice(-20).reverse().map(p => {
            const badge = p.threat.includes("Malicious") ? "badge-red"
                        : p.threat.includes("External")  ? "badge-yellow" : "badge-green";
            return `<tr>
                <td>${p.src}</td>
                <td>${p.dst}</td>
                <td><span class="badge badge-blue">${p.protocol}</span></td>
                <td style="font-size:11px;color:#64748b;max-width:180px;
                    overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                    ${p.payload || "—"}</td>
                <td><span class="badge ${badge}">${p.threat}</span></td>
            </tr>`;
        }).join("");
        out.innerHTML = `
            <div class="stat-row">
                <div class="stat-box">
                    <div class="s-label">Packets Captured</div>
                    <div class="s-value">${data.length}</div>
                </div>
                <div class="stat-box">
                    <div class="s-label">External IPs</div>
                    <div class="s-value yellow">
                        ${data.filter(p=>p.threat.includes("External")||p.threat.includes("Malicious")).length}
                    </div>
                </div>
                <div class="stat-box">
                    <div class="s-label">Safe</div>
                    <div class="s-value green">
                        ${data.filter(p=>p.threat.includes("Safe")).length}
                    </div>
                </div>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr>
                        <th>Source</th><th>Destination</th>
                        <th>Protocol</th><th>Payload</th><th>Status</th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>`;
    } catch {}
}

// ========== THREAT INTEL ==========
async function getThreats() {
    const out = document.getElementById("threatOutput");
    out.innerHTML = `<span class="spinner"></span> Checking against abuse.ch blocklist...`;
    try {
        const res  = await fetch(`${API}/threat-check`);
        const data = await res.json();
        if (data.error) { out.innerHTML = `<span style="color:#ef4444">${data.error}</span>`; return; }
        window.lastThreatData = data;
        document.getElementById("dc-threats").innerText = data.length;
        updateRiskScore();
        if (data.length === 0) {
            out.innerHTML = `
                <div style="text-align:center;padding:30px;color:#22c55e;">
                    <div style="font-size:40px;">✅</div>
                    <div style="margin-top:10px;font-size:16px;font-weight:700;">No Threats Detected</div>
                    <div style="font-size:13px;color:#475569;margin-top:6px;">
                        All captured IPs clean against abuse.ch blocklist</div>
                </div>`;
            return;
        }
        const rows = data.map(t => `
            <tr>
                <td><strong>${t.ip}</strong></td>
                <td><span class="badge badge-red">${t.status}</span></td>
                <td>${t.source || "abuse.ch"}</td>
            </tr>`).join("");
        out.innerHTML = `
            <div class="alert-box">
                <h4>🚨 ${data.length} Malicious IP(s) Detected</h4>
                <p>These IPs match the abuse.ch feodotracker blocklist.</p>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr>
                        <th>IP Address</th><th>Status</th><th>Source</th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>`;
    } catch {
        out.innerHTML = `<span style="color:#ef4444">Failed to connect to backend.</span>`;
    }
}

// ========== WEB SCRAPER ==========
async function scrapeSite() {
    const url = document.getElementById("scrapeURL").value.trim();
    const out = document.getElementById("scrapeOutput");
    if (!url) { showPopup("⚠️ Enter a URL", "warning"); return; }
    out.innerHTML = `<span class="spinner"></span> Scraping ${url}...`;
    try {
        const res  = await fetch(`${API}/scrape`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });
        const data = await res.json();
        if (data.error) { out.innerHTML = `<span style="color:#ef4444">Error: ${data.error}</span>`; return; }
        window.lastScrapeData = data;
        document.getElementById("dc-scrape").innerText = data.links ? data.links.length : "—";
        const riskBadge = data.phishing_risk.includes("High")   ? "badge-red"
                        : data.phishing_risk.includes("Medium") ? "badge-yellow" : "badge-green";
        const linksList = (data.links  || []).slice(0,15).map(l =>
            `<a href="${l}" target="_blank">${l}</a>`).join("");
        const imgList   = (data.images || []).slice(0,10).map(i => `<p>${i}</p>`).join("");
        const formsList = (data.forms  || []).slice(0,5).map(f =>
            `<p style="font-size:11px;">${f}</p>`).join("");
        out.innerHTML = `
            <div class="stat-row">
                <div class="stat-box"><div class="s-label">Headings</div>
                    <div class="s-value">${data.headings}</div></div>
                <div class="stat-box"><div class="s-label">Paragraphs</div>
                    <div class="s-value">${data.paragraphs}</div></div>
                <div class="stat-box"><div class="s-label">Links</div>
                    <div class="s-value blue">${(data.links||[]).length}</div></div>
                <div class="stat-box"><div class="s-label">Images</div>
                    <div class="s-value">${(data.images||[]).length}</div></div>
                <div class="stat-box"><div class="s-label">Forms</div>
                    <div class="s-value yellow">${(data.forms||[]).length}</div></div>
            </div>
            <div style="margin-bottom:16px;">
                <strong style="color:#94a3b8;">Title:</strong>
                <span style="color:#a78bfa;"> ${data.title}</span><br>
                <strong style="color:#94a3b8;">URL:</strong>
                <span style="color:#64748b;font-size:13px;"> ${data.url}</span><br>
                <strong style="color:#94a3b8;">Phishing Risk:</strong>
                <span class="badge ${riskBadge}" style="margin-left:6px;">
                    ${data.phishing_risk}</span>
            </div>
            <div class="btn-row">
                <button class="btn btn-secondary"
                    onclick="downloadJSON(window.lastScrapeData,'scrape_report')">
                    ⬇ Download Scrape Report
                </button>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-top:12px;">
                <div class="scrape-list">
                    <h5>🔗 Links (${(data.links||[]).length})</h5>
                    ${linksList || "<p style='color:#475569'>None found</p>"}
                </div>
                <div class="scrape-list">
                    <h5>🖼 Images (${(data.images||[]).length})</h5>
                    ${imgList || "<p style='color:#475569'>None found</p>"}
                </div>
                <div class="scrape-list">
                    <h5>📋 Forms (${(data.forms||[]).length})</h5>
                    ${formsList || "<p style='color:#475569'>None found</p>"}
                </div>
            </div>`;
    } catch {
        out.innerHTML = `<span style="color:#ef4444">Failed to connect to backend.</span>`;
    }
}

// ========== PASSWORD AUDITOR ==========
function auditPassword() {
    const pwd = document.getElementById("auditPwd").value;
    const out = document.getElementById("auditOutput");
    if (!pwd) { out.innerHTML = `<span style="color:#ef4444">Enter a password to audit.</span>`; return; }
    let score    = 0;
    let feedback = [];
    if (pwd.length >= 8)             { score++; } else { feedback.push("❌ Use at least 8 characters"); }
    if (pwd.length >= 12)            { score++; } else { feedback.push("⚠️ 12+ characters is stronger"); }
    if (/[A-Z]/.test(pwd))           { score++; } else { feedback.push("❌ Add uppercase letters (A-Z)"); }
    if (/[a-z]/.test(pwd))           { score++; } else { feedback.push("❌ Add lowercase letters (a-z)"); }
    if (/[0-9]/.test(pwd))           { score++; } else { feedback.push("❌ Add numbers (0-9)"); }
    if (/[!@#$%^&*()_+]/.test(pwd))  { score++; } else { feedback.push("❌ Add special characters (!@#$...)"); }
    const commonPwds = ["password","123456","admin","qwerty","letmein","welcome","monkey","password1"];
    if (commonPwds.includes(pwd.toLowerCase())) {
        score    = 0;
        feedback = ["🚨 This is a commonly used password — extremely weak!"];
    }
    const levels = [
        { label: "Very Weak",   color: "#ef4444", bg: "rgba(239,68,68,0.1)" },
        { label: "Weak",        color: "#ef4444", bg: "rgba(239,68,68,0.1)" },
        { label: "Fair",        color: "#eab308", bg: "rgba(234,179,8,0.1)" },
        { label: "Good",        color: "#eab308", bg: "rgba(234,179,8,0.1)" },
        { label: "Strong",      color: "#22c55e", bg: "rgba(34,197,94,0.1)" },
        { label: "Very Strong", color: "#22c55e", bg: "rgba(34,197,94,0.1)" },
        { label: "Excellent",   color: "#8b5cf6", bg: "rgba(139,92,246,0.1)" }
    ];
    const lvl       = levels[Math.min(score, levels.length - 1)];
    const pct       = Math.round((score / 6) * 100);
    const crackTime = score <= 1 ? "Instantly" : score <= 2 ? "Minutes"
                    : score <= 3 ? "Hours"     : score <= 4 ? "Days"
                    : score <= 5 ? "Years"     : "Centuries";
    out.innerHTML = `
        <div style="background:${lvl.bg};border:1px solid ${lvl.color};
            border-radius:12px;padding:20px;margin-bottom:16px;">
            <div style="display:flex;justify-content:space-between;
                align-items:center;margin-bottom:12px;">
                <span style="font-size:20px;font-weight:800;color:${lvl.color};">${lvl.label}</span>
                <span style="font-size:28px;font-weight:900;color:${lvl.color};">${pct}%</span>
            </div>
            <div style="background:#0a0f1e;border-radius:20px;height:10px;
                overflow:hidden;margin-bottom:12px;">
                <div style="width:${pct}%;height:100%;background:${lvl.color};
                    border-radius:20px;transition:0.5s;"></div>
            </div>
            <div style="display:flex;gap:20px;">
                <div>
                    <div style="font-size:11px;color:#64748b;text-transform:uppercase;">Length</div>
                    <div style="font-weight:700;color:#e2e8f0;">${pwd.length} chars</div>
                </div>
                <div>
                    <div style="font-size:11px;color:#64748b;text-transform:uppercase;">Est. Crack Time</div>
                    <div style="font-weight:700;color:${lvl.color};">${crackTime}</div>
                </div>
                <div>
                    <div style="font-size:11px;color:#64748b;text-transform:uppercase;">Score</div>
                    <div style="font-weight:700;color:#e2e8f0;">${score}/6</div>
                </div>
            </div>
        </div>
        ${feedback.length > 0 ? `
        <div style="background:#0f172a;border:1px solid #1e293b;
            border-radius:12px;padding:16px;">
            <div style="font-size:13px;font-weight:700;color:#94a3b8;margin-bottom:10px;">
                💡 Recommendations:</div>
            ${feedback.map(f => `
                <div style="font-size:13px;color:#cbd5e1;padding:4px 0;
                    border-bottom:1px solid #1e293b;">${f}</div>`).join("")}
        </div>` : `
        <div style="background:rgba(139,92,246,0.1);border:1px solid #8b5cf6;
            border-radius:12px;padding:16px;text-align:center;
            color:#a78bfa;font-weight:700;">
            ✅ Excellent password! All security criteria met.
        </div>`}`;
}

// ========== REPORTS ==========
function generateFullReport() {
    const out    = document.getElementById("reportOutput");
    const log    = window.lastLogData;
    const scan   = window.lastScanData;
    const packet = window.lastPacketData;
    const threat = window.lastThreatData;
    const scrape = window.lastScrapeData;
    out.innerHTML = `
        <div class="report-grid">
            <div class="report-card">
                <h4>📄 Log Analysis</h4>
                <p>Total Entries: <strong>${log.total || "—"}</strong><br>
                Failed / High Risk: <strong style="color:#ef4444">${log.failed || "—"}</strong><br>
                Unique IPs: <strong>${log.unique_ips || "—"}</strong><br>
                Suspicious IPs: <strong>${(log.suspicious||[]).length}</strong></p>
            </div>
            <div class="report-card">
                <h4>🌐 Network Scan</h4>
                <p>Target IP: <strong>${scan.ip || "—"}</strong><br>
                Open Ports: <strong style="color:#22c55e">${scan.open ?? "—"}</strong><br>
                Filtered: <strong style="color:#eab308">${scan.filtered ?? "—"}</strong><br>
                Total Scanned: <strong>${(scan.ports||[]).length}</strong></p>
            </div>
            <div class="report-card">
                <h4>📦 Packet Capture</h4>
                <p>Total Packets: <strong>${packet.length || "—"}</strong><br>
                External IPs: <strong style="color:#eab308">
                    ${packet.filter(p=>p.threat&&!p.threat.includes("Safe")).length}
                </strong><br>
                Malicious: <strong style="color:#ef4444">
                    ${packet.filter(p=>p.threat&&p.threat.includes("Malicious")).length}
                </strong></p>
            </div>
            <div class="report-card">
                <h4>🛡 Threat Intelligence</h4>
                <p>Malicious IPs Found: <strong style="color:#ef4444">
                    ${threat.length || "0"}</strong><br>
                Source: <strong>abuse.ch feodotracker</strong></p>
            </div>
            <div class="report-card">
                <h4>🌍 Web Scraper</h4>
                <p>Title: <strong>${scrape.title || "—"}</strong><br>
                Links: <strong>${(scrape.links||[]).length || "—"}</strong><br>
                Images: <strong>${(scrape.images||[]).length || "—"}</strong><br>
                Forms: <strong>${(scrape.forms||[]).length || "—"}</strong><br>
                Phishing Risk: <strong>${scrape.phishing_risk || "—"}</strong></p>
            </div>
            <div class="report-card">
                <h4>📊 Risk Score</h4>
                <p>Current Score: <strong style="color:#a78bfa;font-size:24px;">
                    ${document.getElementById("riskScore").innerText}
                </strong><br>
                Status: <strong>${document.getElementById("riskStatus").innerText}</strong></p>
            </div>
        </div>`;
}

// ========== DOWNLOADS ==========
function downloadJSON(data, filename) {
    if (!data || (Array.isArray(data) && data.length === 0) ||
        (typeof data === "object" && Object.keys(data).length === 0)) {
        showPopup("⚠️ No data to download. Run the module first.", "warning");
        return;
    }
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `${filename}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

function downloadFullJSON() {
    downloadJSON({
        log:    window.lastLogData,
        scan:   window.lastScanData,
        packet: window.lastPacketData,
        threat: window.lastThreatData,
        scrape: window.lastScrapeData
    }, "cyberwatch_full_report");
}

async function downloadPDF() {
    showPopup("📄 Generating PDF...", "safe");
    try {
        const res = await fetch(`${API}/generate-pdf`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                logs:    window.lastLogData,
                scan:    window.lastScanData,
                threats: window.lastThreatData,
                scrape:  window.lastScrapeData
            })
        });
        const blob = await res.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement("a");
        a.href     = url;
        a.download = "CyberWatch_Report.pdf";
        a.click();
        URL.revokeObjectURL(url);
    } catch {
        showPopup("⚠️ PDF generation failed.", "critical");
    }
}