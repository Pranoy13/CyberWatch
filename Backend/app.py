from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import re, nmap, requests, threading, sqlite3, hashlib, io
from scapy.all import sniff, IP, TCP, UDP, Raw
from bs4 import BeautifulSoup
from fpdf import FPDF

app = Flask(__name__)
CORS(app)

# ================= GLOBALS =================
packet_store = []
alerts = []
malicious_ips = []

# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    hashed = hashlib.sha256("admin123".encode()).hexdigest()
    c.execute("INSERT OR IGNORE INTO users(username,password) VALUES (?,?)", ("admin", hashed))
    conn.commit()
    conn.close()

init_db()

# ================= HEALTH CHECK =================
@app.route('/')
def home():
    return "CyberWatch Backend Running 🚀"

# ================= LOGIN =================
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        u = data.get("username", "").strip()
        p = data.get("password", "").strip()
        if not u or not p:
            return jsonify({"status": "fail", "msg": "Empty fields"})
        hashed = hashlib.sha256(p.encode()).hexdigest()
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        user = c.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (u, hashed)
        ).fetchone()
        conn.close()
        return jsonify({"status": "success" if user else "fail"})
    except Exception as e:
        return jsonify({"status": "fail", "msg": str(e)})

# ================= REGISTER =================
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        u = data.get("username", "").strip()
        p = data.get("password", "").strip()
        if not u or not p:
            return jsonify({"status": "fail", "msg": "Empty fields"})
        hashed = hashlib.sha256(p.encode()).hexdigest()
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("INSERT INTO users(username,password) VALUES (?,?)", (u, hashed))
        conn.commit()
        conn.close()
        return jsonify({"status": "registered"})
    except:
        return jsonify({"status": "exists"})

# ================= LOG ANALYSIS =================
def analyze_log(line):
    ip_match = re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", line)
    ip = ip_match.group() if ip_match else "Unknown"
    score = 0
    if re.search(r"failed|failure", line, re.IGNORECASE): score += 2
    if re.search(r"error", line, re.IGNORECASE): score += 1
    if re.search(r"denied|reject", line, re.IGNORECASE): score += 2
    if re.search(r"attack|malicious|intrusion", line, re.IGNORECASE): score += 3
    if score >= 3:
        risk = "High"
    elif score >= 1:
        risk = "Medium"
    else:
        risk = "Low"
    return {"ip": ip, "risk": risk, "raw": line[:120]}

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        logs = request.json.get('logs', '')
        lines = [l for l in logs.split("\n") if l.strip()]
        results = []
        ip_count = {}
        failed = 0
        for line in lines:
            res = analyze_log(line)
            results.append(res)
            if res["risk"] == "High":
                failed += 1
                ip = res["ip"]
                ip_count[ip] = ip_count.get(ip, 0) + 1
        suspicious = []
        for ip, count in ip_count.items():
            if count > 5:
                suspicious.append({"ip": ip, "attempts": count, "risk": "High"})
                alerts.append({
                    "type": "critical",
                    "msg": f"🚨 Brute Force: {ip} — {count} attempts",
                    "ip": ip
                })
        unique_ips = len(set(r["ip"] for r in results))
        return jsonify({
            "total": len(results),
            "failed": failed,
            "unique_ips": unique_ips,
            "logs": results[:100],
            "suspicious": suspicious,
            "ip_stats": ip_count
        })
    except Exception as e:
        return jsonify({"error": str(e)})

# ================= NETWORK SCAN =================
@app.route('/scan', methods=['POST'])
def scan():
    try:
        ip = request.json.get('ip', '').strip()
        if not ip:
            return jsonify({"error": "No IP provided"})
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments='-T4 -Pn -F')
        if ip not in nm.all_hosts():
            return jsonify({"error": "Host unreachable or no ports found"})
        ports = []
        open_count = 0
        filtered_count = 0
        for proto in nm[ip].all_protocols():
            for port in sorted(nm[ip][proto].keys()):
                state = nm[ip][proto][port]['state']
                service = nm[ip][proto][port].get('name', 'unknown')
                port_str = str(port)
                if re.match(r'^(21|22|23|3389)$', port_str):
                    risk = "High 🔴"
                elif re.match(r'^(80|443|8080|8443)$', port_str):
                    risk = "Medium 🟡"
                else:
                    risk = "Low 🟢"
                if state == "open":
                    open_count += 1
                elif state == "filtered":
                    filtered_count += 1
                ports.append({
                    "port": port,
                    "status": state,
                    "service": service,
                    "risk": risk
                })
        return jsonify({
            "ip": ip,
            "open": open_count,
            "filtered": filtered_count,
            "ports": ports
        })
    except Exception as e:
        return jsonify({"error": str(e)})

# ================= PACKET CAPTURE =================
def capture_packets():
    def process(pkt):
        try:
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                protocol = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "Other"
                payload = ""
                if pkt.haslayer(Raw):
                    payload = str(pkt[Raw].load)[:80]
                threat = "Safe ✅"
                if not src.startswith(("192.168.", "10.", "127.", "172.")):
                    threat = "External ⚠️"
                    if src in malicious_ips:
                        threat = "Malicious 🚨"
                        alerts.append({
                            "type": "critical",
                            "msg": f"🚨 Malicious IP detected: {src}",
                            "ip": src
                        })
                packet_store.append({
                    "src": src,
                    "dst": dst,
                    "protocol": protocol,
                    "payload": payload,
                    "threat": threat
                })
                if len(packet_store) > 100:
                    packet_store.pop(0)
        except:
            pass

    try:
        sniff(prn=process, store=False, timeout=3600)
    except Exception as e:
        print(f"Packet capture error: {e}")

@app.route('/packet')
def get_packets():
    return jsonify(packet_store[-50:])

# ================= THREAT INTEL =================
def load_threat():
    global malicious_ips
    try:
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
        r = requests.get(url, timeout=10)
        malicious_ips = [
            line.strip() for line in r.text.split("\n")
            if line.strip() and not line.startswith("#")
        ]
        print(f"Loaded {len(malicious_ips)} malicious IPs")
    except Exception as e:
        print(f"Threat feed error: {e}")
        malicious_ips = []

@app.route('/threat-check')
def threat():
    try:
        detected = []
        seen = set()
        for p in packet_store:
            if p["src"] in malicious_ips and p["src"] not in seen:
                detected.append({"ip": p["src"], "status": "Malicious 🚨", "source": "abuse.ch"})
                seen.add(p["src"])
        return jsonify(detected)
    except Exception as e:
        return jsonify({"error": str(e)})

# ================= ALERTS =================
@app.route('/alerts')
def get_alerts():
    return jsonify(alerts[-10:])

# ================= WEB SCRAPER =================
@app.route('/scrape', methods=['POST'])
def scrape():
    try:
        url = request.json.get('url', '').strip()
        if not url.startswith("http"):
            url = "https://" + url
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.text, 'html.parser')
        links = [a.get('href', '') for a in soup.find_all('a') if a.get('href')]
        images = [i.get('src', '') for i in soup.find_all('img') if i.get('src')]
        forms = [str(f)[:100] for f in soup.find_all('form')]
        scripts = [s.get('src', '') for s in soup.find_all('script') if s.get('src')]
        headings = len(soup.find_all(['h1','h2','h3','h4']))
        paragraphs = len(soup.find_all('p'))
        phishing_score = "High Risk 🔴" if len(forms) > 2 else "Medium 🟡" if len(forms) > 0 else "Low Risk 🟢"
        return jsonify({
            "title": soup.title.string.strip() if soup.title else "No title",
            "url": url,
            "headings": headings,
            "paragraphs": paragraphs,
            "links": links[:20],
            "images": images[:10],
            "forms": forms[:10],
            "scripts": scripts[:10],
            "phishing_risk": phishing_score
        })
    except Exception as e:
        return jsonify({"error": str(e)})

# ================= PDF REPORT =================
@app.route('/generate-pdf', methods=['POST'])
def generate_pdf():
    try:
        import datetime, tempfile, re as regex
        data = request.json

        # Strip emojis from any string
        def clean(text):
            return regex.sub(r'[^\x00-\x7F]+', '', str(text)).strip()

        pdf = FPDF()
        pdf.add_page()

        # Title
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_text_color(100, 60, 200)
        pdf.cell(0, 14, "CyberWatch - Investigation Report",
                 new_x="LMARGIN", new_y="NEXT", align="C")

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 8,
                 f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                 new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(6)

        def section_title(title):
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(100, 60, 200)
            pdf.cell(0, 10, clean(title), new_x="LMARGIN", new_y="NEXT")
            pdf.set_draw_color(100, 60, 200)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(3)

        def row(label, value):
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(55, 8, clean(label) + ":", new_x="RIGHT", new_y="TOP")
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(20, 20, 20)
            pdf.cell(0, 8, clean(value)[:80], new_x="LMARGIN", new_y="NEXT")

        # LOG
        log = data.get("logs", {})
        if log:
            section_title("1. Log Analysis")
            row("Total Entries", log.get("total", "N/A"))
            row("Failed / High Risk", log.get("failed", "N/A"))
            row("Unique IPs", log.get("unique_ips", "N/A"))
            susp = log.get("suspicious", [])
            row("Suspicious IPs", len(susp))
            for s in susp[:5]:
                row("  Brute Force IP",
                    f"{s.get('ip')} - {s.get('attempts')} attempts")
            pdf.ln(4)

        # SCAN
        scan = data.get("scan", {})
        if scan:
            section_title("2. Network Scan")
            row("Target IP", scan.get("ip", "N/A"))
            row("Open Ports", scan.get("open", "N/A"))
            row("Filtered Ports", scan.get("filtered", "N/A"))
            for p in scan.get("ports", [])[:10]:
                row(f"  Port {p.get('port')}",
                    f"{p.get('status')} | {p.get('service')} | {clean(p.get('risk',''))}")
            pdf.ln(4)

        # THREATS
        threats = data.get("threats", [])
        section_title("3. Threat Intelligence")
        row("Malicious IPs Found", len(threats))
        for t in threats[:10]:
            row("  Malicious IP",
                f"{t.get('ip')} - {clean(t.get('status',''))}")
        pdf.ln(4)

        # SCRAPE
        scrape = data.get("scrape", {})
        if scrape:
            section_title("4. Web Scraper")
            row("Title", scrape.get("title", "N/A"))
            row("URL", scrape.get("url", "N/A"))
            row("Links Found", len(scrape.get("links", [])))
            row("Images Found", len(scrape.get("images", [])))
            row("Forms Found", len(scrape.get("forms", [])))
            row("Phishing Risk", clean(scrape.get("phishing_risk", "N/A")))
            pdf.ln(4)

        # Footer
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 8, "CyberWatch Investigation Platform - Confidential Report",
                 new_x="LMARGIN", new_y="NEXT", align="C")

        # Save and send
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        tmp.close()
        pdf.output(tmp.name)

        return send_file(
            tmp.name,
            mimetype='application/pdf',
            as_attachment=True,
            download_name='CyberWatch_Report.pdf'
        )

    except Exception as e:
        print("PDF ERROR:", str(e))
        return jsonify({"error": str(e)})

# ================= RUN =================
if __name__ == "__main__":
    threading.Thread(target=load_threat, daemon=True).start()
    threading.Thread(target=capture_packets, daemon=True).start()
    app.run(debug=True, use_reloader=False)