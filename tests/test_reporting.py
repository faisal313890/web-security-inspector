import json
import unittest
from inspector import analyze_headers,cookie_findings,inspect


def response(headers=None,url='https://example.com/',status=200):
    return {'url':url,'status':status,'headers':headers or [('Content-Type','text/html')],
            'tls':{'certificate_verified':True,'protocol':'TLSv1.3'}}


def check(items,name):return next(c for c in items if c['check']==name)


class ReportingTests(unittest.TestCase):
    def test_missing_httponly_is_context_not_review(self):
        item=cookie_findings(response([('Set-Cookie','preference=PRIVATE; Secure; SameSite=Strict')]))[0]
        self.assertEqual(item['status'],'info')
        self.assertEqual(item['assessment'],'context_required')
        self.assertIn('JavaScript-readable',item['evidence'])
        self.assertNotIn('PRIVATE',json.dumps(item))

    def test_omitted_samesite_alone_is_context(self):
        item=cookie_findings(response([('Set-Cookie','session=PRIVATE; Secure; HttpOnly')]))[0]
        self.assertEqual(item['status'],'info')
        self.assertIn('Some browsers apply Lax',item['evidence'])

    def test_incompatible_samesite_remains_review(self):
        item=cookie_findings(response([('Set-Cookie','session=PRIVATE; HttpOnly; SameSite=None')]))[0]
        self.assertEqual(item['status'],'review')
        self.assertEqual(item['assessment'],'hardening_observation')
        self.assertIn('SameSite=None requires Secure',item['evidence'])
        self.assertTrue(item['not_assessed'])

    def test_missing_hsts_is_not_claim_of_absent_protection(self):
        item=check(analyze_headers(response()),'HSTS max-age')
        self.assertIn('does not establish',item['meaning'])
        self.assertIn('Browser HSTS preload membership',item['not_assessed'])
        self.assertIn('Parent-domain includeSubDomains policy',item['not_assessed'])

    def test_zero_hsts_has_different_meaning_from_absent_header(self):
        item=check(analyze_headers(response([('Strict-Transport-Security','max-age=0')])),'HSTS max-age')
        self.assertIn('requests removal',item['meaning'])
        self.assertNotIn('No HSTS header was observed',item['meaning'])

    def test_hsts_not_applicable_to_ip_literal(self):
        item=check(analyze_headers(response([('Strict-Transport-Security','max-age=31536000')],url='https://127.0.0.1/')),'HSTS max-age')
        self.assertEqual(item['status'],'skipped')
        self.assertEqual(item['assessment'],'not_assessed')

    def test_report_only_csp_explicit_in_evidence(self):
        item=check(analyze_headers(response([('Content-Type','text/html'),('Content-Security-Policy-Report-Only',"default-src 'self'")])),'Enforced CSP header')
        self.assertEqual(item['status'],'review')
        self.assertIn('Report-only:',item['evidence'])
        self.assertIn('reports violations without enforcing',item['meaning'])
        self.assertIn('HTML meta CSP',item['not_assessed'])

    def test_json_exports_coverage_and_http_probe_scope(self):
        def transport(url,*args):
            return response(url=url)
        report=inspect('https://example.com',transport=transport)
        exported=json.loads(json.dumps(report))
        self.assertEqual(exported['version'],'0.2.0')
        self.assertTrue(all(g['status']=='not_assessed' for g in exported['coverage_gaps']))
        probe=check(exported['checks'],'HTTP root HTTPS redirect')
        self.assertIn('Browser upgrades',probe['meaning'])
        self.assertIn('Browser HSTS/preload upgrades',probe['not_assessed'])
        self.assertTrue(all('assessment' in c for c in exported['checks']))


if __name__=='__main__':unittest.main()
