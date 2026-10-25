"""A small HTTP configuration inspector. Python 3.12+, standard library only."""
import argparse
import http.client
import ipaddress
import json
import re
import socket
import ssl
import uuid
from datetime import datetime, timezone
from http.cookies import SimpleCookie, CookieError
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, urljoin, quote

VERSION = '0.2.0'
REDIRECTS = {301,302,303,307,308}
VISIBLE_HEADERS = {'content-type','content-security-policy','content-security-policy-report-only',
 'strict-transport-security','x-frame-options','x-content-type-options','referrer-policy',
 'permissions-policy','server','x-powered-by'}
REFERENCES = {
 'csp':'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy',
 'hsts':'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security',
 'cookies':'https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies',
 'framing':'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options',
 'nosniff':'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options',
 'referrer':'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy'}


class InspectionError(ValueError):
    pass


def normalize_url(value):
    if not isinstance(value,str) or not value.strip() or len(value)>2048:
        raise InspectionError('Enter an HTTP(S) URL or hostname, up to 2048 characters.')
    value=value.strip()
    if any(ord(c)<33 or ord(c)==127 for c in value) or '\\' in value:
        raise InspectionError('URLs may not contain whitespace, control characters, or backslashes.')
    if '://' not in value: value='https://'+value
    try:
        p=urlsplit(value)
        if p.scheme not in {'https','http'} or not p.hostname or p.username is not None or p.password is not None:
            raise InspectionError('Use HTTP(S) with a hostname and no embedded credentials.')
        host=p.hostname.encode('idna').decode('ascii').lower().rstrip('.')
        port=p.port or (443 if p.scheme=='https' else 80)
        if not 1<=port<=65535: raise ValueError()
        if not re.fullmatch(r'[a-z0-9.:-]+',host): raise ValueError()
        authority=f'[{host}]' if ':' in host else host
        if port != (443 if p.scheme=='https' else 80): authority+=f':{port}'
        return urlunsplit((p.scheme,authority,quote(p.path or '/',safe="/%:@!$&'()*+,;=-._~"),
                           quote(p.query,safe="%=&/?;:@!$'()*+,-._~"),''))
    except (ValueError,UnicodeError) as exc:
        raise InspectionError('Invalid URL, hostname, or port.') from exc


def display_url(url):
    p=urlsplit(url)
    return urlunsplit((p.scheme,p.netloc,p.path,'[redacted]' if p.query else '',''))


def resolve_target(url, allow_local=False):
    p=urlsplit(url);port=p.port or (443 if p.scheme=='https' else 80)
    try: answers=socket.getaddrinfo(p.hostname,port,type=socket.SOCK_STREAM)
    except OSError as exc: raise InspectionError('DNS lookup failed.') from exc
    addresses=list(dict.fromkeys(a[4][0] for a in answers))
    if not addresses: raise InspectionError('DNS lookup returned no addresses.')
    for address in addresses:
        ip=ipaddress.ip_address(address)
        # IPv4-mapped IPv6 must obey the underlying IPv4 restrictions too.
        ip=ip.ipv4_mapped if isinstance(ip,ipaddress.IPv6Address) and ip.ipv4_mapped else ip
        if (not ip.is_global or ip.is_multicast) and not (allow_local and ip.is_loopback):
            raise InspectionError('Target resolves to a non-public address. Only loopback lab targets can be enabled.')
    if port not in {80,443} and not (allow_local and all(ipaddress.ip_address(a).is_loopback for a in addresses)):
        raise InspectionError('Public targets support ports 80 and 443 only.')
    return addresses[0],port


class PinnedConnection(http.client.HTTPConnection):
    def __init__(self,host,port,address,secure,timeout):
        self.default_port=443 if secure else 80
        super().__init__(host,port,timeout=timeout)
        self.address,self.secure=address,secure
    def connect(self):
        sock=socket.create_connection((self.address,self.port),timeout=self.timeout)
        try:
            if self.secure: sock=ssl.create_default_context().wrap_socket(sock,server_hostname=self.host)
            self.sock=sock
        except Exception:
            sock.close();raise


def fetch(url,allow_local=False,timeout=7):
    """Resolve/check each hop, then connect to that exact IP with real Host/SNI."""
    address,port=resolve_target(url,allow_local)
    p=urlsplit(url)
    conn=PinnedConnection(p.hostname,port,address,p.scheme=='https',timeout)
    try:
        conn.connect()
        tls=None
        if p.scheme=='https':
            cert=conn.sock.getpeercert()
            tls={'certificate_verified':True,'protocol':conn.sock.version(),'certificate_not_after':cert.get('notAfter','')}
        path=urlunsplit(('','',p.path,p.query,''))
        conn.request('GET',path,headers={'User-Agent':'WebSecurityInspector/'+VERSION,
                                        'Accept':'text/html,application/xhtml+xml,*/*;q=0.5',
                                        'Connection':'close'})
        response=conn.getresponse()
        return {'url':url,'status':response.status,'headers':response.getheaders(),'tls':tls}
    except ssl.SSLCertVerificationError as exc:
        raise InspectionError('TLS certificate verification failed. Verification was not bypassed.') from exc
    except (OSError,ssl.SSLError,http.client.HTTPException) as exc:
        raise InspectionError('Connection failed, timed out, or returned invalid HTTP headers.') from exc
    finally: conn.close()


def values(response,name):
    return [v for k,v in response['headers'] if k.lower()==name.lower()]


def header(response,name): return ', '.join(values(response,name))


def finding(check,status,evidence,meaning,fix='',reference='',priority='info',assessment=None,not_assessed=()):
    labels={'pass':'criterion_observed','review':'hardening_observation',
            'info':'context_required','skipped':'not_assessed'}
    return {'check':check,'status':status,'priority':priority,'evidence':evidence,
            'meaning':meaning,'suggested_fix':fix,'reference':reference,
            'assessment':assessment or labels[status], 'not_assessed':list(not_assessed)}


def analyze_headers(response):
    h=lambda name:header(response,name)
    out=[];secure=urlsplit(response['url']).scheme=='https'
    html=any(t in h('content-type').lower() for t in ('text/html','application/xhtml+xml'))
    out.append(finding('HTTPS transport','pass' if secure else 'review',display_url(response['url']),
       'This response used verified TLS.' if secure else 'This response was received over unencrypted HTTP.',
       '' if secure else 'Serve this page over HTTPS and redirect HTTP requests to HTTPS.',priority='info' if secure else 'medium'))
    try:
        ipaddress.ip_address(urlsplit(response['url']).hostname)
        literal_ip=True
    except ValueError:
        literal_ip=False
    if secure and not literal_ip:
        hsts=values(response,'strict-transport-security')
        raw=hsts[0] if hsts else ''
        ages=re.findall(r'(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?=;|$)',raw,re.I)
        valid=len(hsts)==1 and len(ages)==1 and len(ages[0])<=12 and int(ages[0])>0
        out.append(finding('HSTS max-age','pass' if valid else 'review',raw or 'Header not observed.',
          'A positive HSTS lifetime was observed.' if valid else ('No HSTS header was observed on this response. This does not establish that browser HSTS protection is absent.' if not hsts else 'A single positive max-age was not confirmed. A zero value requests removal of this host’s stored policy; inherited or preloaded policies may still apply.'),
          '' if valid else 'After confirming reliable HTTPS, set an appropriate positive max-age. Add includeSubDomains only when all subdomains support HTTPS.',REFERENCES['hsts'],'info' if valid else 'medium',not_assessed=('Browser HSTS preload membership','Parent-domain includeSubDomains policy','Previously stored browser HSTS state')))
    else:
        out.append(finding('HSTS max-age','skipped','IP-address target' if literal_ip else 'HTTP response','HSTS hosts must be domain names; IP-address targets are not applicable.' if literal_ip else 'Browsers do not establish HSTS from an HTTP response.',reference=REFERENCES['hsts']))
    csp=values(response,'content-security-policy')
    if html:
        present=any(v.strip() for v in csp)
        out.append(finding('Enforced CSP header','pass' if present else 'review','Enforced: '+(' | '.join(csp) or '(absent)')+'; Report-only: '+(h('content-security-policy-report-only') or '(absent)'),
          'An enforced CSP header is present. Policy strength and browser effectiveness were not validated.' if present else ('No enforced CSP response header was observed. A report-only header was observed; it reports violations without enforcing this policy. HTML meta policies were not inspected.' if h('content-security-policy-report-only') else 'No enforced CSP response header was observed. HTML meta policies and other application defenses were not inspected.'),
          '' if present else 'Design and test a CSP for the application; stage it in report-only mode before enforcement.',REFERENCES['csp'],'info' if present else 'medium',not_assessed=('HTML meta CSP','Effective policy strength','Actual browser enforcement and exploitability')))
        frame_policies=[]
        for policy in csp:
            for part in policy.split(';'):
                tokens=part.strip().split()
                if tokens and tokens[0].lower()=='frame-ancestors':
                    frame_policies.append(tokens[1:]);break
        frame_restricted=any(tokens==["'none'"] or tokens==["'self'"] for tokens in frame_policies)
        xfo=values(response,'x-frame-options')
        xfo_ok=len(xfo)==1 and xfo[0].strip().upper() in {'DENY','SAMEORIGIN'}
        frame_ok=frame_restricted or (not frame_policies and xfo_ok)
        out.append(finding('Frame embedding restriction','pass' if frame_ok else 'review',
          'frame-ancestors='+str(frame_policies)+'; X-Frame-Options='+(h('x-frame-options') or '(absent)'),
          'A recognized restrictive framing policy was observed.' if frame_ok else 'A recognized restrictive framing policy was not confirmed. Custom allowlists require manual review; frame-ancestors overrides X-Frame-Options in modern browsers.',
          '' if frame_ok else "If embedding is unnecessary, use CSP frame-ancestors 'none'. Otherwise define the intended parent origins.",REFERENCES['framing'],'info' if frame_ok else 'medium'))
    else:
        for name in ('Enforced CSP header','Frame embedding restriction'):
            out.append(finding(name,'skipped',h('content-type') or 'Content-Type absent','HTML-specific checks are skipped unless an HTML content type is observed.'))
    nosniff=h('x-content-type-options').strip().lower()=='nosniff'
    out.append(finding('MIME sniffing protection','pass' if nosniff else 'review',h('x-content-type-options') or 'Header not observed.',
      'nosniff was observed.' if nosniff else 'The expected nosniff value was not observed.',
      '' if nosniff else 'Send X-Content-Type-Options: nosniff and correct Content-Type values.',REFERENCES['nosniff'],'info' if nosniff else 'low'))
    ref=h('referrer-policy')
    known={'no-referrer','no-referrer-when-downgrade','same-origin','origin','strict-origin','origin-when-cross-origin','strict-origin-when-cross-origin','unsafe-url'}
    recognized=[t.strip().lower() for t in ref.split(',') if t.strip().lower() in known]
    strong=bool(recognized and recognized[-1] in {'no-referrer','same-origin','strict-origin','strict-origin-when-cross-origin'})
    out.append(finding('Explicit referrer policy','pass' if strong else 'review',ref or 'Header not observed.',
      'An explicit restrictive policy was observed.' if strong else 'An explicit restrictive response policy was not confirmed; modern browsers may still apply a protective default.',
      '' if strong else 'Choose an application-appropriate policy such as strict-origin-when-cross-origin.',REFERENCES['referrer'],'info' if strong else 'low'))
    out.append(finding('Permissions policy','info',h('permissions-policy') or 'Header not observed.',
      'Review which browser features this application needs; header presence alone does not establish suitable restrictions.',
      'Consider disabling unused features such as camera and microphone when appropriate.'))
    banners={k:h(k) for k in ('server','x-powered-by') if h(k)}
    out.append(finding('Technology banners','info',json.dumps(banners) if banners else 'No selected banners observed.',
      'Banners are informational and may be inaccurate. They do not establish that a software version is vulnerable.',
      'Remove unnecessary detailed version banners where practical.'))
    return out


def cookie_findings(response):
    out=[]
    for raw in values(response,'set-cookie'):
        # Parse attributes but never return the original cookie value.
        cookie=SimpleCookie()
        try: cookie.load(raw)
        except CookieError: cookie=SimpleCookie()
        if not cookie:
            out.append(finding('Cookie parsing','info','An unparsed Set-Cookie field was observed; value withheld.',
                               'Cookie configuration could not be assessed. Review the response manually.'));continue
        for name,m in cookie.items():
            observations=[];review_reasons=[];context_notes=[]
            if not m['secure']:
                observations.append('Secure not set')
                review_reasons.append('Secure not set: review transport exposure and cookie sensitivity')
            if not m['httponly']:
                observations.append('HttpOnly not set')
                context_notes.append('JavaScript-readable cookies may intentionally omit HttpOnly; cookie purpose is unknown.')
            same=m['samesite'].lower()
            if not same:
                observations.append('SameSite not explicitly set')
                context_notes.append('Some browsers apply Lax by default; actual behavior depends on the browser and request context.')
            elif same not in {'strict','lax','none'}:
                observations.append('SameSite value unrecognized')
                review_reasons.append('Unrecognized SameSite value: verify intended behavior')
            if same=='none' and not m['secure']:
                review_reasons.append('SameSite=None requires Secure')
            if name.startswith('__Secure-') and (not m['secure'] or urlsplit(response['url']).scheme!='https'):
                review_reasons.append('__Secure- prefix requirements not met')
            if name.startswith('__Host-') and (not m['secure'] or m['domain'] or m['path']!='/' or urlsplit(response['url']).scheme!='https'):
                review_reasons.append('__Host- prefix requirements not met')
            evidence={'name':name,'Secure':bool(m['secure']),'HttpOnly':bool(m['httponly']),
                      'SameSite':m['samesite'] or '(absent)','observations':observations,
                      'review_reasons':review_reasons,'context_notes':context_notes,
                      'response_url':display_url(response['url'])}
            status='review' if review_reasons else ('info' if context_notes else 'pass')
            meaning=('Cookie configuration needs review; sensitivity, application use, and exploitability are unknown.' if review_reasons
                     else 'Cookie choices need application context; missing HttpOnly or an omitted SameSite alone is not treated as a confirmed weakness.' if context_notes
                     else 'The basic Secure, HttpOnly and explicit recognized SameSite attributes were observed; session security was not established.')
            out.append(finding('Cookie attributes',status,json.dumps(evidence),meaning,
              'Review purpose first: use Secure for HTTPS cookies, HttpOnly when JS access is unnecessary, and SameSite appropriate to the application.' if status!='pass' else '',
              REFERENCES['cookies'],'low' if status=='review' else 'info',
              assessment='context_required' if status=='info' else None,
              not_assessed=('Cookie purpose and sensitivity','Actual session/CSRF protection','Browser acceptance and runtime cookie behavior')))
    return out


def safe_location(response):
    loc=values(response,'location')
    if not loc: return None
    try: return display_url(normalize_url(urljoin(response['url'],loc[0])))
    except (InspectionError,ValueError): return '(invalid or credential-bearing location withheld)'


def same_scope(a,b):
    # Permit the usual bare-domain/www redirect, not arbitrary subdomains.
    def root(u):
        h=urlsplit(u).hostname or ''
        return h[4:] if h.startswith('www.') else h
    return root(a)==root(b)


def inspect(url,allow_local=False,probe_http=True,transport=fetch):
    start=normalize_url(url);current=start;seen=set();responses=[];notes=[];stop=None
    for _ in range(6):
        if current in seen: stop='Redirect loop detected.';break
        seen.add(current)
        try: response=transport(current,allow_local)
        except InspectionError as exc:
            stop=str(exc);break
        responses.append(response)
        if response['status'] not in REDIRECTS: break
        location=values(response,'location')
        if len(location)!=1 or not location[0].strip(): stop='Redirect lacks one unambiguous Location.';break
        try: nxt=normalize_url(urljoin(current,location[0]))
        except (InspectionError,ValueError): stop='Redirect Location is invalid.';break
        if not same_scope(start,nxt): stop='Redirect leaves the selected hostname/www scope; destination was not requested.';break
        if urlsplit(current).scheme=='https' and urlsplit(nxt).scheme=='http':
            stop='HTTPS-to-HTTP downgrade redirect detected; destination was not requested.';break
        current=nxt
    else:
        stop='Redirect limit reached (six responses).'
    checks=[]
    if responses:
        final=responses[-1]
        checks=analyze_headers(final)
        for r in responses: checks.extend(cookie_findings(r))
        if not any(values(r,'set-cookie') for r in responses):
            checks.append(finding('Observed cookies','info','No Set-Cookie response fields were observed.',
                                  'JavaScript cookies and cookies on other pages or authenticated flows were not checked.'))
        if final['status']>=400:
            notes.append('The final response is an HTTP error. Headers may belong to an error/block page rather than the application.')
        if final['status'] in REDIRECTS:
            notes.append('Inspection ended on a redirect response; destination page checks are incomplete.')
    if stop:
        checks.append(finding('Request chain completeness','review',stop,'The request chain was not fully inspected. Unobserved checks must not be treated as passed.',priority='info'))
    if responses and urlsplit(start).scheme=='https' and probe_http and (urlsplit(start).port in (None,443)):
        p=urlsplit(start);probe_host=f'[{p.hostname}]' if ':' in p.hostname else p.hostname;probe=urlunsplit(('http',probe_host,'/','',''))
        try:
            r=transport(probe,allow_local)
            loc=values(r,'location');target=normalize_url(urljoin(probe,loc[0])) if len(loc)==1 else None
            ok=r['status'] in REDIRECTS and target and urlsplit(target).scheme=='https' and same_scope(start,target)
            evidence=f'HTTP root returned {r["status"]}; destination: '+(display_url(target) if target else '(none/unrecognized)')
            checks.append(finding('HTTP root HTTPS redirect','pass' if ok else 'review',evidence,
              'The first HTTP root response redirects to in-scope HTTPS. Its destination was not followed by this probe.' if ok else 'The raw HTTP root response did not demonstrate an immediate in-scope HTTPS redirect. Browser upgrades through HSTS or preloading were not assessed.',
              '' if ok else 'Review server redirection separately from browser HSTS/preload behavior; check relevant application routes.',priority='info' if ok else 'medium',not_assessed=('Browser HSTS/preload upgrades','Redirect behavior on other paths','Full destination chain of this separate probe')))
        except (InspectionError,ValueError) as exc:
            checks.append(finding('HTTP root HTTPS redirect','skipped',str(exc),'The optional HTTP probe failed; redirect behavior is unknown.'))
    else:
        notes.append('The separate HTTP-root redirect probe was not run; the supplied URL chain is recorded below.')
    for i,c in enumerate(checks,1):c['id']=f'WSI-{i:03d}'
    observed=[]
    for r in responses:
        observed.append({'url':display_url(r['url']),'status':r['status'],'tls':r['tls'],
           'headers':[{'name':k,'value':v} for k,v in r['headers'] if k.lower() in VISIBLE_HEADERS],
           'redirect_to':safe_location(r)})
    return {'tool':'Web Security Inspector','version':VERSION,'report_id':str(uuid.uuid4()),
      'observed_at_utc':datetime.now(timezone.utc).isoformat(),'target':display_url(start),
      'completion':'complete' if responses and not stop else 'incomplete','responses':observed,'checks':checks,
      'summary':{s:sum(c['status']==s for c in checks) for s in ('pass','review','info','skipped')},
      'coverage_gaps':[
        {'area':'Browser HSTS protection','status':'not_assessed','detail':'Preload lists, parent-domain policies, and stored browser state were not queried.'},
        {'area':'CSP effectiveness','status':'not_assessed','detail':'HTML meta policies, browser execution, and effective policy strength were not evaluated.'},
        {'area':'Cookie application context','status':'not_assessed','detail':'Cookie purpose, sensitivity, browser behavior, and authenticated flows were not evaluated.'},
        {'area':'Exploitability','status':'not_assessed','detail':'No exploit attempt or proof of a security vulnerability was performed.'}],
      'notes':notes,'limitations':[
        'Single-URL response-header inspection using ordinary GET requests; maximum six chain requests plus one optional HTTP-root probe.',
        'No page body, JavaScript, authenticated flows, other endpoints, exploitability, SQL injection, XSS, access control, or CORS behavior was tested.',
        'A pass means only the stated criterion was observed. Missing hardening does not prove an exploitable vulnerability; no overall security score is assigned.',
        'Certificate verification uses the Python system trust configuration. Negotiated TLS data is not a full TLS configuration or revocation audit.',
        'Cookie values and URL query strings are omitted from reports. URLs can still contain sensitive path segments; review before sharing.',
        'DNS/public-IP checks and pinned connections apply at every requested hop. Redirects outside the hostname/www scope and HTTPS downgrades are not followed.']}


def main():
    parser=argparse.ArgumentParser(description='Inspect one authorized website URL with ordinary HTTP requests.')
    parser.add_argument('url');parser.add_argument('--allow-local',action='store_true',help='Allow loopback lab targets only')
    parser.add_argument('--no-http-probe',action='store_true');parser.add_argument('--out',type=Path)
    args=parser.parse_args()
    try: report=inspect(args.url,args.allow_local,not args.no_http_probe)
    except InspectionError as exc: parser.exit(2,str(exc)+'\n')
    content=json.dumps(report,indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(content,encoding='utf-8')
        print('Report saved:',args.out)
    print(report['target'],report['completion']);print(json.dumps(report['summary']))
    for c in report['checks']:
        if c['status']=='review':print(f"{c['id']} {c['check']}: {c['evidence']}")
    return 0 if report['completion']=='complete' else 1


if __name__=='__main__':raise SystemExit(main())
