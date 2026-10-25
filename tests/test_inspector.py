import json,socket,threading,unittest
from unittest.mock import patch,MagicMock
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer
from inspector import InspectionError,normalize_url,display_url,resolve_target,inspect,analyze_headers,cookie_findings,PinnedConnection
from demo import Demo
from server import Handler

def response(url='https://example.com/',status=200,headers=None):
    return {'url':url,'status':status,'headers':headers or [('Content-Type','text/html')],
            'tls':{'certificate_verified':True,'protocol':'TLSv1.3'} if url.startswith('https:') else None}
def check(checks,name):return next(c for c in checks if c['check']==name)

class URLTests(unittest.TestCase):
    def test_url_normalization(self):
        self.assertEqual(normalize_url('example.com'),'https://example.com/')
        self.assertEqual(normalize_url('https://bücher.example/'),'https://xn--bcher-kva.example/')
        self.assertEqual(normalize_url('http://[::1]:8011/'),'http://[::1]:8011/')
    def test_url_credentials_schemes_controls_rejected(self):
        for v in ('ftp://example.com','https://a:b@example.com/','https://example.com/\r\nX:bad','file:///etc/passwd','https://example.com\\@evil.com',''):
            with self.assertRaises(InspectionError):normalize_url(v)
    def test_query_redacted(self):self.assertNotIn('SECRET',display_url(normalize_url('https://example.com/a?token=SECRET')))
    def resolve(self,addr,url='http://example.com/',local=False):
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(addr,80))]):return resolve_target(url,local)
    def test_non_public_and_multicast_blocked(self):
        for addr in ('127.0.0.1','10.0.0.1','169.254.169.254','224.0.0.1','0.0.0.0','192.168.1.1'):
            with self.assertRaises(InspectionError):self.resolve(addr)
    def test_public_permitted(self):self.assertEqual(self.resolve('93.184.216.34')[0],'93.184.216.34')
    def test_local_option_only_allows_loopback(self):
        self.assertEqual(self.resolve('127.0.0.1',local=True)[0],'127.0.0.1')
        with self.assertRaises(InspectionError):self.resolve('10.0.0.1',local=True)
    def test_nonstandard_public_port_rejected(self):
        with self.assertRaises(InspectionError):self.resolve('93.184.216.34','https://example.com:8000/')
    def test_mixed_dns_rejected(self):
        with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('93.184.216.34',80)),(2,1,6,'',('127.0.0.1',80))]):
            with self.assertRaises(InspectionError):resolve_target('http://example.com/')

class HeaderTests(unittest.TestCase):
    def test_missing_csp_has_action_and_reference(self):
        c=check(analyze_headers(response()),'Enforced CSP header');self.assertEqual(c['status'],'review');self.assertTrue(c['suggested_fix']);self.assertTrue(c['reference'])
    def test_report_only_not_enforced(self):
        r=response(headers=[('Content-Type','text/html'),('Content-Security-Policy-Report-Only',"default-src 'none'")])
        self.assertEqual(check(analyze_headers(r),'Enforced CSP header')['status'],'review')
    def test_non_html_skips_html_checks(self):
        self.assertEqual(check(analyze_headers(response(headers=[('Content-Type','application/json')])),'Enforced CSP header')['status'],'skipped')
    def test_hsts_zero_invalid_duplicate_review(self):
        for h in ('max-age=0','max-age=-1','max-age=10;max-age=20','invalid'):
            self.assertEqual(check(analyze_headers(response(headers=[('Strict-Transport-Security',h)])),'HSTS max-age')['status'],'review')
    def test_hsts_positive_and_http_skip(self):
        self.assertEqual(check(analyze_headers(response(headers=[('Strict-Transport-Security','max-age=31536000')])),'HSTS max-age')['status'],'pass')
        self.assertEqual(check(analyze_headers(response('http://example.com/')),'HSTS max-age')['status'],'skipped')
    def test_frame_ancestors_precedence(self):
        r=response(headers=[('Content-Type','text/html'),('X-Frame-Options','DENY'),('Content-Security-Policy','frame-ancestors *')])
        self.assertEqual(check(analyze_headers(r),'Frame embedding restriction')['status'],'review')
        r['headers'][-1]=('Content-Security-Policy',"frame-ancestors 'self'")
        self.assertEqual(check(analyze_headers(r),'Frame embedding restriction')['status'],'pass')
    def test_referrer_last_valid_value(self):
        r=response(headers=[('Referrer-Policy','unsafe-url, no-referrer')]);self.assertEqual(check(analyze_headers(r),'Explicit referrer policy')['status'],'pass')
    def test_cookie_secrets_redacted_and_samesite_none_flagged(self):
        out=cookie_findings(response(headers=[('Set-Cookie','session=TOPSECRET; Path=/; SameSite=None')]))
        self.assertNotIn('TOPSECRET',json.dumps(out));self.assertIn('SameSite=None requires Secure',out[0]['evidence'])
    def test_secure_cookie_flags(self):
        r=response(headers=[('Set-Cookie','session=SECRET; Secure; HttpOnly; SameSite=Lax')]);self.assertEqual(cookie_findings(r)[0]['status'],'pass')
    def test_cookie_host_prefix(self):
        r=response(headers=[('Set-Cookie','__Host-session=SECRET; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.com')])
        self.assertIn('__Host- prefix requirements not met',cookie_findings(r)[0]['evidence'])

class ChainTests(unittest.TestCase):
    def test_cross_scope_not_requested(self):
        t=MagicMock(return_value=response(status=302,headers=[('Location','https://other.example/')]))
        r=inspect('example.com',probe_http=False,transport=t);self.assertEqual(t.call_count,1);self.assertEqual(r['completion'],'incomplete')
    def test_www_followed(self):
        t=MagicMock(side_effect=[response(status=301,headers=[('Location','https://www.example.com/')]),response('https://www.example.com/')])
        self.assertEqual(inspect('example.com',probe_http=False,transport=t)['completion'],'complete')
    def test_downgrade_not_followed(self):
        t=MagicMock(return_value=response(status=302,headers=[('Location','http://example.com/')]))
        r=inspect('example.com',probe_http=False,transport=t);self.assertIn('downgrade',json.dumps(r));self.assertEqual(t.call_count,1)
    def test_loop_detected(self):
        t=MagicMock(return_value=response(status=302,headers=[('Location','/')]))
        r=inspect('example.com',probe_http=False,transport=t);self.assertIn('Redirect loop',json.dumps(r));self.assertEqual(t.call_count,1)
    def test_intermediate_cookies_checked(self):
        t=MagicMock(side_effect=[response(status=302,headers=[('Location','/end'),('Set-Cookie','sid=SECRET')]),response('https://example.com/end')])
        r=inspect('example.com',probe_http=False,transport=t);self.assertEqual(check(r['checks'],'Cookie attributes')['status'],'review');self.assertNotIn('SECRET',json.dumps(r))
    def test_http_probe(self):
        t=MagicMock(side_effect=[response(),response('http://example.com/',301,[('Location','https://example.com/')])])
        self.assertEqual(check(inspect('example.com',transport=t)['checks'],'HTTP root HTTPS redirect')['status'],'pass')
    def test_failed_fetch_never_passes(self):
        r=inspect('example.com',transport=MagicMock(side_effect=InspectionError('TLS verification failed')))
        self.assertEqual(r['summary']['pass'],0);self.assertEqual(r['completion'],'incomplete')
    def test_bad_location_safe(self):
        for loc in ('https://[broken','https://user:SECRET@example.com'):
            r=inspect('example.com',probe_http=False,transport=lambda *a:response(status=302,headers=[('Location',loc)]))
            self.assertEqual(r['completion'],'incomplete');self.assertNotIn('SECRET',json.dumps(r))
    def test_request_limit(self):
        r=inspect('example.com',probe_http=False,transport=lambda url,*a:response(url,302,[('Location',url+'next')]))
        self.assertEqual(len(r['responses']),6);self.assertEqual(r['completion'],'incomplete')
    def test_connection_pins_address_and_uses_original_sni(self):
        sock=MagicMock();ctx=MagicMock()
        with patch('socket.create_connection',return_value=sock) as connect,patch('ssl.create_default_context',return_value=ctx):
            conn=PinnedConnection('example.com',443,'93.184.216.34',True,7);conn.connect()
        self.assertEqual(connect.call_args.args[0],('93.184.216.34',443));self.assertEqual(ctx.wrap_socket.call_args.kwargs['server_hostname'],'example.com');self.assertEqual(conn.default_port,443)

class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab=ThreadingHTTPServer(('127.0.0.1',0),Demo);cls.gui=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        cls.threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (cls.lab,cls.gui)]
        for t in cls.threads:t.start()
        cls.laburl=f'http://127.0.0.1:{cls.lab.server_port}';cls.guiurl=f'http://127.0.0.1:{cls.gui.server_port}'
    @classmethod
    def tearDownClass(cls):
        for s in (cls.lab,cls.gui):s.shutdown();s.server_close()
        for t in cls.threads:t.join()
    def test_local_weak_vs_hardened(self):
        w=inspect(self.laburl+'/weak',True,False);h=inspect(self.laburl+'/hardened',True,False)
        self.assertEqual(w['completion'],'complete');self.assertGreater(w['summary']['review'],h['summary']['review'])
        self.assertEqual(check(h['checks'],'HTTPS transport')['status'],'review');self.assertNotIn('NOT_A_REAL_SECRET',json.dumps(w))
    def test_gui_endpoint_end_to_end(self):
        req=Request(self.guiurl+'/inspect',data=json.dumps({'url':self.laburl+'/weak','allow_local':True,'probe_http':False}).encode(),headers={'X-Inspector':'local','Content-Type':'application/json'})
        with urlopen(req) as r:report=json.load(r)
        self.assertEqual(report['completion'],'complete');self.assertGreater(report['summary']['review'],0)
    def test_cross_origin_rejected(self):
        req=Request(self.guiurl+'/inspect',data=b'{}',headers={'X-Inspector':'local','Origin':'https://evil.example'})
        with self.assertRaises(HTTPError) as e:urlopen(req)
        self.assertEqual(e.exception.code,403)
    def test_ui_security_headers(self):
        with urlopen(self.guiurl) as r:
            self.assertIn(b'Turn headers into',r.read());self.assertIn("frame-ancestors 'none'",r.headers['Content-Security-Policy'])

if __name__=='__main__':unittest.main()
