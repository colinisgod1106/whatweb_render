from flask import Flask, render_template, request, jsonify
import requests
import re
import ssl
import socket
import json
from urllib.parse import urlparse
from datetime import datetime
import concurrent.futures

app = Flask(__name__)

HEADERS_UA = {
    "User-Agent": "Mozilla/5.0 (compatible; WhatWeb-GUI/1.0)"
}

# ─── Technology fingerprint signatures ───────────────────────────────────────

SIGNATURES = {
    # CMS
    "WordPress": {
        "category": "CMS",
        "icon": "📝",
        "checks": [
            {"type": "header_value", "header": "x-powered-by", "pattern": r"wordpress", "flags": re.I},
            {"type": "body", "pattern": r'content="WordPress', "flags": re.I},
            {"type": "body", "pattern": r'/wp-content/', "flags": 0},
            {"type": "body", "pattern": r'/wp-includes/', "flags": 0},
            {"type": "url_path", "pattern": r'/wp-login\.php'},
        ],
        "version": {"type": "body", "pattern": r'<meta name="generator" content="WordPress ([0-9.]+)"', "group": 1},
    },
    "Joomla": {
        "category": "CMS",
        "icon": "📝",
        "checks": [
            {"type": "body", "pattern": r'content="Joomla!', "flags": re.I},
            {"type": "body", "pattern": r'/media/jui/', "flags": 0},
            {"type": "cookie", "pattern": r'joomla_'},
        ],
        "version": {"type": "body", "pattern": r'content="Joomla! ([0-9.]+)"', "group": 1},
    },
    "Drupal": {
        "category": "CMS",
        "icon": "📝",
        "checks": [
            {"type": "header_value", "header": "x-generator", "pattern": r"Drupal", "flags": re.I},
            {"type": "body", "pattern": r'content="Drupal', "flags": re.I},
            {"type": "body", "pattern": r'/sites/default/files/', "flags": 0},
            {"type": "cookie", "pattern": r'Drupal\.'},
        ],
    },
    "Shopify": {
        "category": "E-commerce",
        "icon": "🛒",
        "checks": [
            {"type": "body", "pattern": r'cdn\.shopify\.com', "flags": 0},
            {"type": "body", "pattern": r'Shopify\.theme', "flags": 0},
            {"type": "header_value", "header": "x-shopify-stage", "pattern": r"."},
        ],
    },
    "WooCommerce": {
        "category": "E-commerce",
        "icon": "🛒",
        "checks": [
            {"type": "body", "pattern": r'woocommerce', "flags": re.I},
            {"type": "body", "pattern": r'/wc-ajax=', "flags": 0},
        ],
    },
    "Magento": {
        "category": "E-commerce",
        "icon": "🛒",
        "checks": [
            {"type": "body", "pattern": r'Mage\.', "flags": 0},
            {"type": "body", "pattern": r'/skin/frontend/', "flags": 0},
            {"type": "cookie", "pattern": r'frontend='},
        ],
    },
    # Web Servers
    "Apache": {
        "category": "Web Server",
        "icon": "🖥️",
        "checks": [
            {"type": "header_value", "header": "server", "pattern": r"Apache", "flags": re.I},
        ],
        "version": {"type": "header_value", "header": "server", "pattern": r"Apache/([0-9.]+)", "group": 1},
    },
    "Nginx": {
        "category": "Web Server",
        "icon": "🖥️",
        "checks": [
            {"type": "header_value", "header": "server", "pattern": r"nginx", "flags": re.I},
        ],
        "version": {"type": "header_value", "header": "server", "pattern": r"nginx/([0-9.]+)", "group": 1},
    },
    "IIS": {
        "category": "Web Server",
        "icon": "🖥️",
        "checks": [
            {"type": "header_value", "header": "server", "pattern": r"Microsoft-IIS", "flags": re.I},
        ],
        "version": {"type": "header_value", "header": "server", "pattern": r"Microsoft-IIS/([0-9.]+)", "group": 1},
    },
    "LiteSpeed": {
        "category": "Web Server",
        "icon": "🖥️",
        "checks": [
            {"type": "header_value", "header": "server", "pattern": r"LiteSpeed", "flags": re.I},
        ],
    },
    "Cloudflare": {
        "category": "CDN / Security",
        "icon": "☁️",
        "checks": [
            {"type": "header_exists", "header": "cf-ray"},
            {"type": "header_value", "header": "server", "pattern": r"cloudflare", "flags": re.I},
        ],
    },
    "Fastly": {
        "category": "CDN / Security",
        "icon": "☁️",
        "checks": [
            {"type": "header_exists", "header": "x-fastly-request-id"},
            {"type": "header_value", "header": "via", "pattern": r"varnish", "flags": re.I},
        ],
    },
    "AWS CloudFront": {
        "category": "CDN / Security",
        "icon": "☁️",
        "checks": [
            {"type": "header_value", "header": "via", "pattern": r"CloudFront", "flags": re.I},
            {"type": "header_exists", "header": "x-amz-cf-id"},
        ],
    },
    # Programming Languages / Frameworks
    "PHP": {
        "category": "Programming Language",
        "icon": "💻",
        "checks": [
            {"type": "header_value", "header": "x-powered-by", "pattern": r"PHP", "flags": re.I},
        ],
        "version": {"type": "header_value", "header": "x-powered-by", "pattern": r"PHP/([0-9.]+)", "group": 1},
    },
    "ASP.NET": {
        "category": "Framework",
        "icon": "💻",
        "checks": [
            {"type": "header_value", "header": "x-powered-by", "pattern": r"ASP\.NET", "flags": re.I},
            {"type": "header_exists", "header": "x-aspnet-version"},
        ],
        "version": {"type": "header_exists", "header": "x-aspnet-version"},
    },
    "Next.js": {
        "category": "Framework",
        "icon": "⚛️",
        "checks": [
            {"type": "header_value", "header": "x-powered-by", "pattern": r"Next\.js", "flags": re.I},
            {"type": "body", "pattern": r'__NEXT_DATA__', "flags": 0},
        ],
        "version": {"type": "header_value", "header": "x-powered-by", "pattern": r"Next\.js ([0-9.]+)", "group": 1},
    },
    "Nuxt.js": {
        "category": "Framework",
        "icon": "⚛️",
        "checks": [
            {"type": "body", "pattern": r'__NUXT__', "flags": 0},
            {"type": "header_value", "header": "x-powered-by", "pattern": r"Nuxt", "flags": re.I},
        ],
    },
    "React": {
        "category": "JavaScript Framework",
        "icon": "⚛️",
        "checks": [
            {"type": "body", "pattern": r'react(?:\.min)?\.js', "flags": re.I},
            {"type": "body", "pattern": r'__reactFiber|__reactEvents', "flags": 0},
            {"type": "body", "pattern": r'data-reactroot', "flags": 0},
        ],
    },
    "Vue.js": {
        "category": "JavaScript Framework",
        "icon": "⚡",
        "checks": [
            {"type": "body", "pattern": r'vue(?:\.min)?\.js', "flags": re.I},
            {"type": "body", "pattern": r'__vue_', "flags": 0},
            {"type": "body", "pattern": r'v-cloak|v-bind|v-model', "flags": 0},
        ],
    },
    "Angular": {
        "category": "JavaScript Framework",
        "icon": "🅰️",
        "checks": [
            {"type": "body", "pattern": r'angular(?:\.min)?\.js', "flags": re.I},
            {"type": "body", "pattern": r'ng-version=', "flags": 0},
        ],
    },
    "jQuery": {
        "category": "JavaScript Library",
        "icon": "📦",
        "checks": [
            {"type": "body", "pattern": r'jquery(?:\.min)?\.js', "flags": re.I},
            {"type": "body", "pattern": r'jquery-([0-9.]+)', "flags": re.I},
        ],
        "version": {"type": "body", "pattern": r'jquery[.-]([0-9.]+)(?:\.min)?\.js', "group": 1, "flags": re.I},
    },
    # Analytics
    "Google Analytics": {
        "category": "Analytics",
        "icon": "📊",
        "checks": [
            {"type": "body", "pattern": r'google-analytics\.com|gtag\(|UA-\d+-\d+|G-[A-Z0-9]+', "flags": 0},
        ],
    },
    "Google Tag Manager": {
        "category": "Analytics",
        "icon": "📊",
        "checks": [
            {"type": "body", "pattern": r'googletagmanager\.com|GTM-[A-Z0-9]+', "flags": 0},
        ],
    },
    "Hotjar": {
        "category": "Analytics",
        "icon": "📊",
        "checks": [
            {"type": "body", "pattern": r'hotjar\.com|hjid:', "flags": re.I},
        ],
    },
    # Security
    "reCAPTCHA": {
        "category": "Security",
        "icon": "🔒",
        "checks": [
            {"type": "body", "pattern": r'google\.com/recaptcha|recaptcha\.net', "flags": 0},
        ],
    },
    "hCaptcha": {
        "category": "Security",
        "icon": "🔒",
        "checks": [
            {"type": "body", "pattern": r'hcaptcha\.com', "flags": 0},
        ],
    },
    # Fonts / UI
    "Bootstrap": {
        "category": "CSS Framework",
        "icon": "🎨",
        "checks": [
            {"type": "body", "pattern": r'bootstrap(?:\.min)?\.(?:css|js)', "flags": re.I},
            {"type": "body", "pattern": r'class="[^"]*(?:container|navbar|btn btn-)', "flags": 0},
        ],
        "version": {"type": "body", "pattern": r'bootstrap[/-]([0-9.]+)', "group": 1, "flags": re.I},
    },
    "Tailwind CSS": {
        "category": "CSS Framework",
        "icon": "🎨",
        "checks": [
            {"type": "body", "pattern": r'tailwindcss|tailwind\.min\.css', "flags": re.I},
            {"type": "body", "pattern": r'class="[^"]*(?:flex |grid |text-[a-z]+-\d+ |bg-[a-z]+-\d+ )', "flags": 0},
        ],
    },
    "Font Awesome": {
        "category": "Icon Library",
        "icon": "🎨",
        "checks": [
            {"type": "body", "pattern": r'font-awesome|fontawesome', "flags": re.I},
        ],
    },
    "Google Fonts": {
        "category": "Fonts",
        "icon": "🔤",
        "checks": [
            {"type": "body", "pattern": r'fonts\.googleapis\.com|fonts\.gstatic\.com', "flags": 0},
        ],
    },
    # Hosting
    "Vercel": {
        "category": "Hosting",
        "icon": "▲",
        "checks": [
            {"type": "header_value", "header": "server", "pattern": r"Vercel", "flags": re.I},
            {"type": "header_exists", "header": "x-vercel-id"},
        ],
    },
    "Netlify": {
        "category": "Hosting",
        "icon": "🌐",
        "checks": [
            {"type": "header_exists", "header": "x-nf-request-id"},
            {"type": "header_value", "header": "server", "pattern": r"Netlify", "flags": re.I},
        ],
    },
    "GitHub Pages": {
        "category": "Hosting",
        "icon": "🐱",
        "checks": [
            {"type": "header_value", "header": "server", "pattern": r"GitHub\.com", "flags": re.I},
        ],
    },
    # Other
    "Wix": {
        "category": "Website Builder",
        "icon": "🏗️",
        "checks": [
            {"type": "body", "pattern": r'wix\.com|wixstatic\.com', "flags": re.I},
        ],
    },
    "Squarespace": {
        "category": "Website Builder",
        "icon": "🏗️",
        "checks": [
            {"type": "body", "pattern": r'squarespace\.com|static\.squarespace\.com', "flags": re.I},
        ],
    },
    "Webflow": {
        "category": "Website Builder",
        "icon": "🏗️",
        "checks": [
            {"type": "body", "pattern": r'webflow\.com', "flags": re.I},
        ],
    },
    "Stripe": {
        "category": "Payment",
        "icon": "💳",
        "checks": [
            {"type": "body", "pattern": r'stripe\.com/v\d|Stripe\.setPublishableKey|js\.stripe\.com', "flags": 0},
        ],
    },
    "Intercom": {
        "category": "Customer Support",
        "icon": "💬",
        "checks": [
            {"type": "body", "pattern": r'intercom\.io|Intercom\(', "flags": re.I},
        ],
    },
    "Zendesk": {
        "category": "Customer Support",
        "icon": "💬",
        "checks": [
            {"type": "body", "pattern": r'zendesk\.com|zdassets\.com', "flags": re.I},
        ],
    },
}

# ─── Helper functions ─────────────────────────────────────────────────────────

def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def check_signature(name, sig, headers, body, cookies):
    headers_lower = {k.lower(): v for k, v in headers.items()}
    matched = False
    for check in sig.get("checks", []):
        t = check["type"]
        flags = check.get("flags", 0)
        if t == "body":
            if re.search(check["pattern"], body, flags):
                matched = True; break
        elif t == "header_exists":
            if check["header"].lower() in headers_lower:
                matched = True; break
        elif t == "header_value":
            val = headers_lower.get(check["header"].lower(), "")
            if val and re.search(check["pattern"], val, flags):
                matched = True; break
        elif t == "cookie":
            cookie_str = " ".join(cookies.keys())
            if re.search(check["pattern"], cookie_str, check.get("flags", 0)):
                matched = True; break
        elif t == "url_path":
            pass  # handled at URL level if needed
    if not matched:
        return None

    # Try to extract version
    version = None
    if "version" in sig:
        v = sig["version"]
        vt = v.get("type", "body")
        pat = v.get("pattern", "")
        grp = v.get("group", 0)
        vflags = v.get("flags", 0)
        if vt == "body":
            m = re.search(pat, body, vflags)
            if m and grp <= len(m.groups()):
                version = m.group(grp)
        elif vt == "header_value":
            val = headers_lower.get(v.get("header", "").lower(), "")
            m = re.search(pat, val, vflags)
            if m and grp <= len(m.groups()):
                version = m.group(grp)
        elif vt == "header_exists":
            version = headers_lower.get(v.get("header", "").lower(), "")

    return {"name": name, "category": sig["category"], "icon": sig["icon"], "version": version}

def get_ssl_info(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=5), server_hostname=hostname) as s:
            cert = s.getpeercert()
            not_after = cert.get("notAfter", "")
            issuer = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))
            return {
                "issuer": issuer.get("organizationName", "Unknown"),
                "subject": subject.get("commonName", hostname),
                "valid_until": not_after,
                "has_ssl": True,
            }
    except Exception:
        return {"has_ssl": False}

def scan_url(url):
    url = normalize_url(url)
    parsed = urlparse(url)
    hostname = parsed.hostname
    result = {
        "url": url,
        "hostname": hostname,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status_code": None,
        "headers": {},
        "detected": [],
        "meta": {},
        "ssl": {},
        "error": None,
    }

    try:
        resp = requests.get(
            url,
            headers=HEADERS_UA,
            timeout=12,
            allow_redirects=True,
            verify=True,
        )
        result["status_code"] = resp.status_code
        result["final_url"] = resp.url
        result["headers"] = dict(resp.headers)

        body = resp.text
        cookies = resp.cookies

        # Fingerprint
        for name, sig in SIGNATURES.items():
            det = check_signature(name, sig, resp.headers, body, cookies)
            if det:
                result["detected"].append(det)

        # Meta info
        title_m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
        desc_m = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', body, re.I)
        gen_m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.I)
        charset_m = re.search(r'charset=["\']?([a-zA-Z0-9-]+)', body, re.I)

        result["meta"] = {
            "title": title_m.group(1).strip() if title_m else "",
            "description": desc_m.group(1).strip() if desc_m else "",
            "generator": gen_m.group(1).strip() if gen_m else "",
            "charset": charset_m.group(1).upper() if charset_m else "",
            "content_length": len(body),
            "redirect_count": len(resp.history),
        }

        # SSL
        if parsed.scheme == "https" or resp.url.startswith("https://"):
            final_host = urlparse(resp.url).hostname
            result["ssl"] = get_ssl_info(final_host)

        # Sort by category
        result["detected"].sort(key=lambda x: x["category"])

    except requests.exceptions.SSLError as e:
        result["error"] = f"SSL 錯誤：{str(e)[:100]}"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"連線失敗：無法連接到目標主機"
    except requests.exceptions.Timeout:
        result["error"] = "逾時：目標主機回應太慢"
    except Exception as e:
        result["error"] = f"錯誤：{str(e)[:120]}"

    return result

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    urls_raw = data.get("urls", "")
    urls = [u.strip() for u in re.split(r"[\n,]+", urls_raw) if u.strip()]
    if not urls:
        return jsonify({"error": "請輸入至少一個 URL"}), 400
    if len(urls) > 5:
        return jsonify({"error": "一次最多掃描 5 個 URL"}), 400

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(scan_url, u): u for u in urls}
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    return jsonify({"results": results})

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
