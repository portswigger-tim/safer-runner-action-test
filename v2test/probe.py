# Service-container egress probe (run by the service's health-cmd every few seconds).
import socket, ssl, time, urllib.request
def t(name, fn):
    try:
        r = fn()
    except Exception as e:
        r = "ERR " + type(e).__name__ + ": " + str(e)[:90]
    print(time.strftime("%H:%M:%S"), name, r, flush=True)
t("dns-example.org", lambda: socket.gethostbyname("example.org"))
t("https-example.org", lambda: urllib.request.urlopen("https://example.org", timeout=6).status)
t("http-example.org", lambda: urllib.request.urlopen("http://example.org", timeout=6).status)
t("https-github.com", lambda: urllib.request.urlopen("https://github.com/robots.txt", timeout=6).status)
t("tcp-1.1.1.1:853", lambda: socket.create_connection(("1.1.1.1", 853), timeout=5).close() or "connected")
