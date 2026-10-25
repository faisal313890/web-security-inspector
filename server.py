"""Local browser interface for the inspector; no external Python dependencies."""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from inspector import inspect, InspectionError

ROOT=Path(__file__).resolve().parent
SCAN_LOCK=threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def reply(self,code,data,mime='application/json'):
        body=json.dumps(data,ensure_ascii=True).encode() if mime=='application/json' else data
        self.send_response(code)
        for k,v in {'Content-Type':mime,'Content-Length':str(len(body)), 'Cache-Control':'no-store',
          'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
          'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"}.items():
            self.send_header(k,v)
        self.end_headers();self.wfile.write(body)
    def local_host(self):
        return self.headers.get('Host') in {f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}'}
    def do_GET(self):
        if not self.local_host(): return self.reply(403,{'error':'Local host required.'})
        paths={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript'),'/style.css':('style.css','text/css')}
        if self.path not in paths: return self.reply(404,{'error':'Not found.'})
        name,mime=paths[self.path];self.reply(200,(ROOT/'static'/name).read_bytes(),mime)
    def do_POST(self):
        allowed={f'http://127.0.0.1:{self.server.server_port}',f'http://localhost:{self.server.server_port}'}
        if not self.local_host() or self.headers.get('X-Inspector')!='local' or self.headers.get('Origin',next(iter(allowed))) not in allowed:
            return self.reply(403,{'error':'Local requests only.'})
        if self.path!='/inspect':return self.reply(404,{'error':'Not found.'})
        if not SCAN_LOCK.acquire(blocking=False):return self.reply(409,{'error':'An inspection is already running. Wait for it to finish.'})
        try:
            self.connection.settimeout(15)
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=4096:return self.reply(413,{'error':'Request must be 1–4096 bytes.'})
            data=json.loads(self.rfile.read(length))
            if not isinstance(data,dict) or not isinstance(data.get('url'),str):raise InspectionError('Enter a URL.')
            if any(type(data.get(k,False)) is not bool for k in ('allow_local','probe_http')):raise InspectionError('Invalid inspection options.')
            report=inspect(data['url'],data.get('allow_local',False),data.get('probe_http',True))
            self.reply(200,report)
        except (ValueError,UnicodeError) as exc:self.reply(400,{'error':str(exc)[:200]})
        except TimeoutError:self.reply(408,{'error':'Input timed out.'})
        except (BrokenPipeError,ConnectionResetError):pass
        except Exception:self.reply(500,{'error':'Inspection failed unexpectedly. Check the target and try again.'})
        finally:SCAN_LOCK.release()


if __name__=='__main__':
    port=int(os.environ.get('INSPECTOR_PORT','8787'))
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    print(f'Web Security Inspector: http://127.0.0.1:{port} — Ctrl+C to stop.')
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()
