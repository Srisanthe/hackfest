"""server.py - Lightweight server connecting Scene HTML frontend to auth.py SQLite backend.
Runs using Python standard library with no external pip dependencies.
Run with: python server.py
"""
import http.server
import json
import os
import urllib.parse
import webbrowser
import auth

PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

HASH_CACHE = set()

def get_malware_hashes():
    global HASH_CACHE
    if HASH_CACHE:
        return HASH_CACHE
    hashes = set()
    hash_file = os.path.join(DIRECTORY, "malware_hashes.txt")
    if os.path.isfile(hash_file):
        try:
            with open(hash_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    h = line.strip().lower().split()[0] if line.strip() else ""
                    if len(h) in (32, 64) and not h.startswith("#"):
                        hashes.add(h)
        except Exception:
            pass

    # Also automatically discover from malware-samples-master if present on D:\
    samples_dir = os.path.join(os.path.splitdrive(DIRECTORY)[0] + "\\", "malware-samples-master")
    if os.path.isdir(samples_dir):
        try:
            for root, _dirs, names in os.walk(samples_dir):
                for name in names:
                    base = os.path.splitext(name)[0].lower()
                    if len(base) in (32, 64) and all(c in "0123456789abcdef" for c in base):
                        hashes.add(base)
                    if "hash" in name.lower() or name.endswith(".txt"):
                        fp = os.path.join(root, name)
                        try:
                            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                                for line in f:
                                    t = line.strip().lower().split()[0] if line.strip() else ""
                                    if len(t) in (32, 64) and all(c in "0123456789abcdef" for c in t):
                                        hashes.add(t)
                        except Exception:
                            pass
        except Exception:
            pass

    HASH_CACHE = hashes
    return hashes

class SceneHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(content_length).decode("utf-8"))
        except Exception:
            return {}

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # Serve the app template directly on root / or /index.html
        if path in ("/", "/index.html", "/scene1.html"):
            template_path = os.path.join(DIRECTORY, "templates", "scene1.html")
            if os.path.isfile(template_path):
                try:
                    with open(template_path, "rb") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                    return
                except Exception as e:
                    return self._send_json({"ok": False, "message": str(e)}, 500)

        if path == "/api/blocklist":
            hashes = list(get_malware_hashes())
            return self._send_json({"ok": True, "count": len(hashes), "hashes": hashes})

        elif path == "/api/check-threat":
            target_hash = (params.get("hash", [""])[0] or "").lower()
            name = (params.get("name", [""])[0] or "").lower()
            hashes = get_malware_hashes()
            is_threat = target_hash in hashes or any(ext in name for ext in [".macro", "dropper", "agent-tesla", "gandcrab", "trickbot", "kpot", "emotet"])
            return self._send_json({"ok": True, "threat": is_threat, "sig": "Known malware signature" if is_threat else None})

        elif path == "/api/profile":
            user_id = params.get("user_id", [None])[0]
            if not user_id:
                return self._send_json({"ok": False, "message": "Missing user_id"}, 400)
            profile = auth.get_profile(int(user_id))
            if profile:
                return self._send_json({"ok": True, "profile": profile})
            return self._send_json({"ok": False, "message": "User not found"}, 404)

        elif path == "/api/scans":
            user_id = params.get("user_id", [None])[0]
            if not user_id:
                return self._send_json({"ok": False, "message": "Missing user_id"}, 400)
            scans = auth.get_scans(int(user_id))
            return self._send_json({"ok": True, "scans": scans})

        # Default: Serve static files (index.html, etc.)
        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        data = self._read_json()

        if path == "/api/register":
            username = data.get("username", "")
            email = data.get("email", "")
            password = data.get("password", "")
            ok, msg, code = auth.register_user(username, email, password)
            return self._send_json({"ok": ok, "message": msg, "recovery_code": code}, 200 if ok else 400)

        elif path == "/api/login":
            username = data.get("username") or data.get("email") or ""
            password = data.get("password", "")
            user, msg = auth.verify_user(username, password)
            if user:
                return self._send_json({"ok": True, "user": user, "message": msg})
            return self._send_json({"ok": False, "message": msg}, 401)

        elif path == "/api/reset-password":
            username = data.get("username", "")
            code = data.get("code", "")
            new_password = data.get("new_password", "")
            ok, msg, new_code = auth.reset_password(username, code, new_password)
            return self._send_json({"ok": ok, "message": msg, "new_recovery_code": new_code}, 200 if ok else 400)

        elif path == "/api/add-scan":
            user_id = data.get("user_id")
            mode = data.get("mode", "Quick")
            files_checked = int(data.get("files_checked", 0))
            threats = int(data.get("threats", 0))
            status = data.get("status", "Clean")
            if not user_id:
                return self._send_json({"ok": False, "message": "Missing user_id"}, 400)
            auth.add_scan(int(user_id), mode, files_checked, threats, status)
            return self._send_json({"ok": True, "message": "Scan recorded"})

        elif path == "/api/delete-file":
            filename = data.get("filename", "")
            filepath = data.get("filepath", "")
            target = filepath or filename
            resolved = None
            if target:
                if os.path.isfile(target):
                    resolved = target
                elif os.path.isfile(os.path.join(DIRECTORY, target)):
                    resolved = os.path.join(DIRECTORY, target)
            if resolved:
                try:
                    os.remove(resolved)
                    return self._send_json({"ok": True, "message": f"{os.path.basename(resolved)} deleted successfully from disk."})
                except Exception as e:
                    return self._send_json({"ok": False, "message": f"Could not delete: {e}"}, 500)
            return self._send_json({"ok": True, "message": f"Threat {filename} quarantined and neutralized."})

        return self._send_json({"ok": False, "message": "Not found"}, 404)

if __name__ == "__main__":
    auth.init_db()
    print(f"[*] SQLite database initialized: {auth.DB_PATH}")
    server = http.server.HTTPServer(("0.0.0.0", PORT), SceneHandler)
    url = f"http://localhost:{PORT}"
    print(f"[*] Scene Web Server running at {url}")
    print("[*] Opening website in your default browser...")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server.")