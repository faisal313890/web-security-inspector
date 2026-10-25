"""Deterministic loopback lab. No credentials, databases, or external services."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

class Demo(BaseHTTPRequestHandler):
    server_version='InspectorLab/1.0'
    sys_version=''
    def log_message(self,*args):pass
    def do_GET(self):
        if self.path=='/redirect':
            self.send_response(302);self.send_header('Location','/weak');self.end_headers();return
        if self.path=='/loop':
            self.send_response(302);self.send_header('Location','/loop');self.end_headers();return
        hardened=self.path.startswith('/hardened')
        body=(f'<!doctype html><title>Inspector lab</title><h1>{"Hardened headers" if hardened else "Weak headers"} lab</h1><p>Local HTTP practice site. Inspect /weak and /hardened.</p>').encode()
        self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8')
        if hardened:
            self.send_header('Content-Security-Policy',"default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Permissions-Policy','camera=(), microphone=(), geolocation=()')
            # No cookies on this route: HTTP cannot demonstrate proper secure-cookie delivery.
        else:
            self.send_header('Set-Cookie','demo_session=NOT_A_REAL_SECRET; Path=/')
            self.send_header('X-Powered-By','DemoFramework/0.0')
        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)

if __name__=='__main__':
    server=ThreadingHTTPServer(('127.0.0.1',8011),Demo)
    print('Practice site: http://127.0.0.1:8011/weak and /hardened — Ctrl+C to stop.')
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()
