#!/usr/bin/env python3
"""
cert_core.py  -  Shared CERT-X engine (no GUI)
----------------------------------------------
Certificate reading + expiry classification, reused by both the desktop
app and the web app. On a cloud/Linux host the Windows-only methods are
skipped automatically and it uses a direct TLS read.
"""
import ssl
import socket
import os
import sys
import base64
import json
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlparse
import urllib.request

try:
    import truststore
    truststore.inject_into_ssl()
except Exception:
    pass


def normalize_host(value):
    v = str(value).strip()
    if not v:
        return None
    host = v
    if "://" in v:
        host = urlparse(v).hostname or v
    host = host.strip().strip("/").split("/")[0]
    return host or None


def parse_cert_time(value):
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def evaluate(days_left):
    active = "Valid" if days_left >= 0 else "Invalid"
    filt = "<= 90 days" if days_left <= 90 else "> 90 days"
    if days_left < 0:
        action, level = "\U0001F4E2 Expired", "red"
    elif days_left == 0:
        action, level = "\U0001F4E2 Expiring today", "red"
    elif 1 <= days_left <= 45:
        action, level = "\u26A0\uFE0F Immediate Action required \u2013 Expiring soon", "red"
    elif 46 <= days_left <= 90:
        action, level = "\u26A0\uFE0F Action required \u2013 Expiring soon", "yellow"
    else:
        action, level = "\u2705 More than 90 days to renew", "green"
    return {"active": active, "filter": filt, "action": action, "level": level}




def normalize_host(value):
    v = str(value).strip()
    if not v:
        return None
    host = v
    if "://" in v:
        host = urlparse(v).hostname or v
    host = host.strip().strip("/").split("/")[0]
    return host or None


def parse_cert_time(value):
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


# ---- status engine (CERT-X 5-tier logic) ----
def evaluate(days_left):
    active = "Valid" if days_left >= 0 else "Invalid"
    filt = "<= 90 days" if days_left <= 90 else "> 90 days"
    if days_left < 0:
        action, level = "\U0001F4E2 Expired", "red"
    elif days_left == 0:
        action, level = "\U0001F4E2 Expiring today", "red"
    elif 1 <= days_left <= 45:
        action, level = "\u26A0\uFE0F Immediate Action required \u2013 Expiring soon", "red"
    elif 46 <= days_left <= 90:
        action, level = "\u26A0\uFE0F Action required \u2013 Expiring soon", "yellow"
    else:
        action, level = "\u2705 More than 90 days to renew", "green"
    return {"active": active, "filter": filt, "action": action, "level": level}


# ======================= NETWORKING (from proven Zscaler build) =======================

def detect_proxy():
    """Return proxy details from environment or Windows/system proxy settings.

    Returns a dict with host, port, username, password, source, or None.
    urllib.getproxies() is used because on Windows it can also consult the
    user's Internet Options proxy configuration.
    """
    candidates = []
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        val = os.environ.get(var)
        if val:
            candidates.append((val, var))

    try:
        proxies = urllib.request.getproxies()
        for key in ("https", "http", "all"):
            if proxies.get(key):
                candidates.append((proxies[key], f"system:{key}"))
    except Exception:
        pass

    for val, source in candidates:
        try:
            p = urlparse(val if "://" in val else "http://" + val)
            if p.hostname:
                return {
                    "host": p.hostname,
                    "port": p.port or 80,
                    "username": p.username,
                    "password": p.password,
                    "source": source,
                }
        except Exception:
            continue
    return None


def parse_proxy_str(s):
    s = (s or "").strip()
    if not s:
        return None
    p = urlparse(s if "://" in s else "http://" + s)
    if p.hostname:
        return {
            "host": p.hostname,
            "port": p.port or 80,
            "username": p.username,
            "password": p.password,
            "source": "manual",
        }
    return None


def _proxy_auth_header(proxy):
    user = proxy.get("username")
    password = proxy.get("password")
    if user is None:
        return ""
    raw = f"{user}:{password or ''}".encode("utf-8")
    return "Proxy-Authorization: Basic " + base64.b64encode(raw).decode("ascii") + "\r\n"


def _friendly_network_error(exc, host, proxy=None):
    """Turn common Windows/Zscaler errors into actionable messages."""
    msg = str(exc).strip() or exc.__class__.__name__
    prefix = f"{host}: "
    if isinstance(exc, socket.timeout):
        return prefix + ("Connection timed out. Check United VPN/Zscaler routing or proxy access. "
                         f"Proxy={proxy['host']}:{proxy['port']}" if proxy else
                         "Connection timed out. Check United VPN/Zscaler routing.")
    if isinstance(exc, ssl.SSLCertVerificationError):
        return prefix + ("TLS certificate verification failed. The corporate/Zscaler root CA may not "
                         "be trusted by this Python build. The updated app uses the Windows trust store. "
                         f"Details: {msg}")
    if isinstance(exc, ConnectionRefusedError):
        return prefix + (f"Connection refused by proxy {proxy['host']}:{proxy['port']}. "
                         "Verify the corporate proxy settings." if proxy else
                         "Connection refused. Check VPN/network access.")
    return prefix + msg



def _find_browser_exe():
    candidates = [
        os.path.join(os.environ.get("PROGRAMFILES", r"C:\\Program Files"), "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(os.environ.get("PROGRAMFILES(X86)", r"C:\\Program Files (x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(os.environ.get("PROGRAMFILES", r"C:\\Program Files"), "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(os.environ.get("PROGRAMFILES(X86)", r"C:\\Program Files (x86)"), "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "Application", "chrome.exe"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def _browser_http_json(port, path):
    import urllib.request
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=3) as r:
        return json.loads(r.read().decode("utf-8"))


def get_cert_via_winhttp(host, proxy=None, timeout=20):
    """Use Windows WinHTTP/Schannel with the Windows corporate proxy settings.

    This avoids Python sockets, PowerShell and browser debugging. WinHTTP is
    a native Windows networking API and can use the Windows automatic proxy
    configuration used by corporate environments. We only inspect the
    presented certificate; we do not require Python to trust the certificate.
    """
    if os.name != "nt":
        raise RuntimeError("Windows WinHTTP is available only on Windows")

    import ctypes
    from ctypes import wintypes

    winhttp = ctypes.WinDLL("winhttp.dll")
    crypt32 = ctypes.WinDLL("crypt32.dll")

    HINTERNET = wintypes.HANDLE
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0
    WINHTTP_ACCESS_TYPE_NO_PROXY = 1
    WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4
    WINHTTP_FLAG_SECURE = 0x00800000
    WINHTTP_FLAG_REFRESH = 0x00000100
    WINHTTP_OPTION_SECURITY_FLAGS = 31
    WINHTTP_OPTION_SERVER_CERT_CONTEXT = 78
    SECURITY_FLAG_IGNORE_UNKNOWN_CA = 0x00000100
    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID = 0x00002000
    SECURITY_FLAG_IGNORE_CERT_CN_INVALID = 0x00001000
    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE = 0x00000200

    class CRYPT_INTEGER_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    class CERT_CONTEXT(ctypes.Structure):
        _fields_ = [
            ("dwCertEncodingType", wintypes.DWORD),
            ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
            ("cbCertEncoded", wintypes.DWORD),
            ("pCertInfo", ctypes.c_void_p),
            ("hCertStore", wintypes.HANDLE),
        ]

    winhttp.WinHttpOpen.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPCWSTR,
                                    wintypes.LPCWSTR, wintypes.DWORD]
    winhttp.WinHttpOpen.restype = HINTERNET
    winhttp.WinHttpConnect.argtypes = [HINTERNET, wintypes.LPCWSTR, wintypes.WORD, wintypes.DWORD]
    winhttp.WinHttpConnect.restype = HINTERNET
    winhttp.WinHttpOpenRequest.argtypes = [HINTERNET, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                           wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPCWSTR), wintypes.DWORD]
    winhttp.WinHttpOpenRequest.restype = HINTERNET
    winhttp.WinHttpSetOption.argtypes = [HINTERNET, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    winhttp.WinHttpSetOption.restype = wintypes.BOOL
    winhttp.WinHttpSendRequest.argtypes = [HINTERNET, wintypes.LPCWSTR, wintypes.DWORD,
                                           ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t]
    winhttp.WinHttpSendRequest.restype = wintypes.BOOL
    winhttp.WinHttpReceiveResponse.argtypes = [HINTERNET, ctypes.c_void_p]
    winhttp.WinHttpReceiveResponse.restype = wintypes.BOOL
    winhttp.WinHttpQueryOption.argtypes = [HINTERNET, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
    winhttp.WinHttpQueryOption.restype = wintypes.BOOL
    winhttp.WinHttpCloseHandle.argtypes = [HINTERNET]
    winhttp.WinHttpCloseHandle.restype = wintypes.BOOL
    crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    crypt32.CertFreeCertificateContext.restype = wintypes.BOOL

    def last_error(prefix):
        code = ctypes.get_last_error()
        return f"{prefix} (Windows error {code})"

    session = None
    conn = None
    req = None
    cert_ctx_ptr = ctypes.c_void_p()
    try:
        if proxy:
            proxy_url = f"http://{proxy['host']}:{proxy['port']}"
            session = winhttp.WinHttpOpen("CertChecker/8.0", WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                                          proxy_url, None, 0)
        else:
            # Automatic proxy discovery / Windows corporate proxy configuration.
            session = winhttp.WinHttpOpen("CertChecker/8.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                          None, None, 0)
        if not session:
            raise RuntimeError(last_error("WinHTTP session could not be opened"))

        # WinHTTP timeout values are milliseconds: resolve/connect/send/receive.
        ms = int(timeout * 1000)
        timeout_buf = ctypes.c_uint(ms)
        for opt in (2, 3, 6, 7):  # RESOLVE, CONNECT, SEND, RECEIVE timeout options
            winhttp.WinHttpSetOption(session, opt, ctypes.byref(timeout_buf), ctypes.sizeof(timeout_buf))

        conn = winhttp.WinHttpConnect(session, host, 443, 0)
        if not conn:
            raise RuntimeError(last_error("WinHTTP could not connect to the host"))

        req = winhttp.WinHttpOpenRequest(conn, "GET", "/", None, None, None,
                                         WINHTTP_FLAG_SECURE | WINHTTP_FLAG_REFRESH)
        if not req:
            raise RuntimeError(last_error("WinHTTP could not create the HTTPS request"))

        # We are inspecting the presented certificate, so do not fail before
        # the certificate can be queried because of Zscaler/enterprise CA trust.
        security_flags = ctypes.c_ulong(
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
        )
        if not winhttp.WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS,
                                        ctypes.byref(security_flags), ctypes.sizeof(security_flags)):
            # Continue if the option is not accepted; SendRequest will provide
            # the real network diagnostic below.
            pass

        if not winhttp.WinHttpSendRequest(req, None, 0, None, 0, 0, 0):
            raise RuntimeError(last_error("WinHTTP SendRequest failed"))
        if not winhttp.WinHttpReceiveResponse(req, None):
            raise RuntimeError(last_error("WinHTTP ReceiveResponse failed"))

        size = wintypes.DWORD(ctypes.sizeof(ctypes.c_void_p))
        if not winhttp.WinHttpQueryOption(req, WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                                          ctypes.byref(cert_ctx_ptr), ctypes.byref(size)):
            raise RuntimeError(last_error("WinHTTP could not return the server certificate"))
        if not cert_ctx_ptr.value:
            raise RuntimeError("WinHTTP returned an empty server certificate context")

        cert_ctx = ctypes.cast(cert_ctx_ptr, ctypes.POINTER(CERT_CONTEXT)).contents
        if not cert_ctx.pbCertEncoded or cert_ctx.cbCertEncoded == 0:
            raise RuntimeError("WinHTTP returned a certificate context without encoded certificate data")
        der = ctypes.string_at(cert_ctx.pbCertEncoded, cert_ctx.cbCertEncoded)

        # Reuse Python's standard certificate parser only for decoding the DER;
        # no network connection or certificate trust decision is made by Python.
        import tempfile
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as f:
            f.write(pem)
            name = f.name
        try:
            decoded = ssl._ssl._test_decode_cert(name)
        finally:
            try:
                os.unlink(name)
            except Exception:
                pass
        return decoded
    except OSError as e:
        raise RuntimeError(str(e)) from e
    finally:
        if cert_ctx_ptr.value:
            try:
                crypt32.CertFreeCertificateContext(cert_ctx_ptr)
            except Exception:
                pass
        for h in (req, conn, session):
            if h:
                try:
                    winhttp.WinHttpCloseHandle(h)
                except Exception:
                    pass


def get_cert_via_windows_https(host, proxy=None, timeout=20):
    """Use Windows PowerShell/.NET (Schannel) to obtain the peer certificate."""
    ps = r"""
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$HostName = [Environment]::GetEnvironmentVariable('CERTCHECKER_HOST')
$TimeoutSec = [int][Environment]::GetEnvironmentVariable('CERTCHECKER_TIMEOUT')
$ProxyHost = [Environment]::GetEnvironmentVariable('CERTCHECKER_PROXY_HOST')
$ProxyPort = [int][Environment]::GetEnvironmentVariable('CERTCHECKER_PROXY_PORT')
if ([string]::IsNullOrWhiteSpace($HostName)) { throw 'Host name was empty.' }
$uri = 'https://' + $HostName + '/'
$req = [Net.HttpWebRequest]::Create($uri)
$req.Method = 'GET'
$req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151 Safari/537.36'
$req.Timeout = $TimeoutSec * 1000
$req.ReadWriteTimeout = $TimeoutSec * 1000
$req.AllowAutoRedirect = $false
$req.AutomaticDecompression = [Net.DecompressionMethods]::GZip -bor [Net.DecompressionMethods]::Deflate
if (-not [string]::IsNullOrWhiteSpace($ProxyHost) -and $ProxyPort -gt 0) {
    $req.Proxy = New-Object Net.WebProxy(('http://' + $ProxyHost + ':' + $ProxyPort), $false)
    $req.Proxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials
} else {
    $req.Proxy = [Net.WebRequest]::DefaultWebProxy
    if ($req.Proxy) { $req.Proxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials }
}
try {
    $resp = $req.GetResponse()
    try {
        $cert = $resp.ServicePoint.Certificate
        if (-not $cert) { throw 'Windows HTTPS connection succeeded but no server certificate was exposed.' }
        $c2 = New-Object Security.Cryptography.X509Certificates.X509Certificate2($cert)
        [pscustomobject]@{ok=$true;notAfter=$c2.NotAfter.ToUniversalTime().ToString('MMM dd HH:mm:ss yyyy GMT');notBefore=$c2.NotBefore.ToUniversalTime().ToString('MMM dd HH:mm:ss yyyy GMT');issuer=$c2.Issuer;subject=$c2.Subject;status=[int]$resp.StatusCode} | ConvertTo-Json -Compress
    } finally { $resp.Close() }
} catch {
    $status=$null
    if ($_.Exception.Response) { try { $status=[int]$_.Exception.Response.StatusCode } catch {} }
    [pscustomobject]@{ok=$false;error=$_.Exception.ToString();status=$status} | ConvertTo-Json -Compress
    exit 2
}
"""
    env = os.environ.copy()
    env['CERTCHECKER_HOST'] = host
    env['CERTCHECKER_TIMEOUT'] = str(int(timeout))
    env['CERTCHECKER_PROXY_HOST'] = proxy['host'] if proxy else ''
    env['CERTCHECKER_PROXY_PORT'] = str(proxy['port']) if proxy else '0'
    encoded = base64.b64encode(ps.encode('utf-16le')).decode('ascii')
    args = ['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',encoded]
    try:
        cp = subprocess.run(args, capture_output=True, text=True, timeout=timeout+10,
                            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0), env=env)
    except FileNotFoundError:
        raise RuntimeError('Windows PowerShell is not available on this computer.')
    except subprocess.TimeoutExpired:
        raise socket.timeout(f'Windows HTTPS request timed out after {timeout} seconds')
    out=(cp.stdout or '').strip()
    if not out:
        err=(cp.stderr or '').strip()
        raise RuntimeError('Windows HTTPS returned no diagnostic output' + (f': {err}' if err else ''))
    try:
        data=json.loads(out.splitlines()[-1])
    except Exception:
        raise RuntimeError('Could not parse Windows HTTPS diagnostic: ' + out[-1000:])
    if not data.get('ok'):
        status=data.get('status'); detail=data.get('error','Windows HTTPS request failed')
        if status: detail=f'HTTP status {status}: {detail}'
        raise RuntimeError(detail)
    return {'notAfter':data['notAfter'],'notBefore':data['notBefore'],'issuer':[('commonName',data.get('issuer',''))],'subject':[('commonName',data.get('subject',''))]}

def get_cert_via_requests(host, proxy=None, port=443, timeout=20):
    # Respect the GUI checkbox: do not inherit HTTPS_PROXY/HTTP_PROXY when unchecked.
    try:
        import requests
    except Exception as e:
        raise RuntimeError("requests is not installed in this build") from e
    url=f"https://{host}:{port}/"
    proxies=None
    if proxy:
        from urllib.parse import quote
        auth=""
        if proxy.get("username") is not None:
            auth=f"{quote(str(proxy["username"]))}:{quote(str(proxy.get("password") or ""))}@"
        proxies={"http":f"http://{auth}{proxy["host"]}:{proxy["port"]}",
                 "https":f"http://{auth}{proxy["host"]}:{proxy["port"]}"}
    session=requests.Session()
    session.trust_env=False
    try:
        r=session.get(url,timeout=timeout,allow_redirects=False,stream=True,
                      proxies=proxies,verify=False,headers={"User-Agent":"Mozilla/5.0 CertChecker/5.0"})
        try:
            sock=None
            conn=getattr(r.raw,"connection",None)
            if conn is not None: sock=getattr(conn,"sock",None)
            if sock is None:
                fp=getattr(r.raw,"_fp",None); fp=getattr(fp,"fp",None) if fp is not None else None
                raw=getattr(fp,"raw",None) if fp is not None else None
                sock=getattr(raw,"_sock",None) if raw is not None else None
            if sock is None: raise RuntimeError("HTTPS request succeeded but Python could not access the peer certificate socket")
            return sock.getpeercert()
        finally: r.close()
    finally: session.close()

def get_cert_via_proxy(host, proxy, port=443, timeout=20):
    """Open a CONNECT tunnel through a corporate HTTP proxy and return peer cert."""
    proxy_host, proxy_port = proxy["host"], proxy["port"]
    raw = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        auth = _proxy_auth_header(proxy)
        connect_req = (
            f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"User-Agent: CertChecker/2.0\r\n"
            f"Proxy-Connection: Keep-Alive\r\n"
            f"{auth}\r\n"
        )
        raw.sendall(connect_req.encode("ascii", "ignore"))

        resp = b""
        raw.settimeout(timeout)
        while b"\r\n\r\n" not in resp:
            chunk = raw.recv(4096)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 65536:
                raise RuntimeError("Proxy returned an unusually large response header")

        status_line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = status_line.split(" ", 2)
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if code != 200:
            reason = parts[2] if len(parts) > 2 else ""
            if code == 407:
                raise RuntimeError("Proxy requires authentication (HTTP 407). Set proxy as user:password@host:port or ask IT how Zscaler authentication is configured.")
            if code in (403, 407):
                raise RuntimeError(f"Corporate proxy blocked the connection ({code} {reason.strip()}). Ask IT to allow the destination if appropriate.")
            raise RuntimeError(f"Proxy refused connection ({code} {reason.strip()})")

        # We only need the presented certificate's dates. Do not require
        # Python to trust the Zscaler/enterprise interception CA here.
        ctx = ssl._create_unverified_context()
        ssock = ctx.wrap_socket(raw, server_hostname=host)
        try:
            return ssock.getpeercert()
        finally:
            try:
                ssock.close()
            except Exception:
                pass
    finally:
        try:
            raw.close()
        except Exception:
            pass


def get_cert_direct(host, port=443, timeout=20):
    """Read the presented TLS certificate without validating the chain.

    This checker is measuring certificate dates, not trust-chain validity.
    On corporate networks (including Zscaler), the TLS certificate presented
    to this machine may be signed by the enterprise inspection CA. Using an
    unverified TLS context lets us inspect that presented certificate instead
    of failing before getpeercert() can return it.
    """
    ctx = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            if not cert:
                # getpeercert() returns an empty dict when verification is
                # disabled. Ask for the DER certificate and parse it locally.
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    raise RuntimeError("TLS connection succeeded but no peer certificate was returned")
                # ssl._ssl._test_decode_cert requires a file, so use the
                # standard DER->PEM conversion and tempfile for portability.
                import tempfile
                pem = ssl.DER_cert_to_PEM_cert(der)
                with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as f:
                    f.write(pem)
                    name = f.name
                try:
                    cert = ssl._ssl._test_decode_cert(name)
                finally:
                    try:
                        os.unlink(name)
                    except Exception:
                        pass
            return cert


def check_one(host, proxy=None):
    """Check certificate using Windows WinHTTP first, then safe fallbacks."""
    errors = []
    try:
        return get_cert_via_winhttp(host, proxy=proxy)
    except Exception as e:
        errors.append("Windows WinHTTP: " + str(e))
    try:
        return get_cert_via_requests(host, proxy=proxy)
    except Exception as e:
        errors.append("Python HTTPS: " + str(e))
    try:
        if proxy:
            return get_cert_via_proxy(host, proxy)
        return get_cert_direct(host)
    except Exception as e:
        errors.append("Raw TLS: " + _friendly_network_error(e, host, proxy))
        raise RuntimeError("\n".join(errors)) from e




def classify_site(host):
    """High-level: fetch cert for host, return a result dict for reports."""
    today = datetime.now(timezone.utc).date()
    try:
        cert = check_one(host, proxy=None)
        if not cert:
            raise RuntimeError("No certificate returned")
        not_after = parse_cert_time(cert["notAfter"])
        not_before = parse_cert_time(cert["notBefore"])
        issuer = dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {}
        days_left = (not_after.date() - today).days
        ev = evaluate(days_left)
        return {
            "Website": host,
            "Expiry Date": not_after.strftime("%m/%d/%Y"),
            "Days Left": days_left,
            "Active Status": ev["active"],
            "Filter": ev["filter"],
            "Action Status": ev["action"],
            "Issuer": issuer.get("commonName", issuer.get("organizationName", "")),
            "Issued On": not_before.strftime("%m/%d/%Y"),
            "Error": "",
            "_level": ev["level"],
        }
    except Exception as e:
        return {
            "Website": host, "Expiry Date": "", "Days Left": "",
            "Active Status": "Invalid", "Filter": "",
            "Action Status": "\U0001F4E2 Could not read certificate",
            "Issuer": "", "Issued On": "", "Error": str(e), "_level": "red",
        }
