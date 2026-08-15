"""Program Workspace store — per-engagement coverage tracking.

A workspace is a JSON file at ~/recon/workspaces/<key>.json holding a WSTG v4.2
checklist, a STRIDE threat model, bug-class progress, notes and a history log for
one bug-bounty program. Pure file store (no ES/DB deps) — the live host/finding
joins are done by the app-layer handlers. Reads never raise; a missing/corrupt
file returns None. Keys are sanitized to [A-Za-z0-9_-] so no path can traverse.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

from . import config, files

WORKSPACES_DIR = config.BASE_DIR / "workspaces"

# The active program (source of truth: scope/programs.json + target board).
GLASSDOOR_NAME = "Glassdoor Managed Bug Bounty Engagement"
GLASSDOOR_PLATFORM = "bugcrowd"

# valid states
WS_STATUS = {"active", "paused", "done"}
WSTG_STATUS = {"todo", "in-progress", "done", "na", "finding"}

# --- seed templates --------------------------------------------------------
# WSTG v4.2 canonical checklist: (CAT, category name, [official test names]).
# The list index +1 is the two-digit test number, so IDs are WSTG-<CAT>-<NN>
# in sequence (v4.2 == the first N tests of each category). 97 tests total.
_WSTG_SPEC: list[tuple[str, str, list[str]]] = [
    ("INFO", "Information Gathering", [
        "Conduct Search Engine Discovery Reconnaissance for Information Leakage",
        "Fingerprint Web Server",
        "Review Webserver Metafiles for Information Leakage",
        "Enumerate Applications on Webserver",
        "Review Webpage Content for Information Leakage",
        "Identify Application Entry Points",
        "Map Execution Paths Through Application",
        "Fingerprint Web Application Framework",
        "Fingerprint Web Application",
        "Map Application Architecture",
    ]),
    ("CONF", "Configuration and Deployment Management", [
        "Test Network Infrastructure Configuration",
        "Test Application Platform Configuration",
        "Test File Extensions Handling for Sensitive Information",
        "Review Old Backup and Unreferenced Files for Sensitive Information",
        "Enumerate Infrastructure and Application Admin Interfaces",
        "Test HTTP Methods",
        "Test HTTP Strict Transport Security",
        "Test RIA Cross Domain Policy",
        "Test File Permission",
        "Test for Subdomain Takeover",
        "Test Cloud Storage",
    ]),
    ("IDNT", "Identity Management", [
        "Test Role Definitions",
        "Test User Registration Process",
        "Test Account Provisioning Process",
        "Testing for Account Enumeration and Guessable User Account",
        "Testing for Weak or Unenforced Username Policy",
    ]),
    ("ATHN", "Authentication", [
        "Testing for Credentials Transported over an Encrypted Channel",
        "Testing for Default Credentials",
        "Testing for Weak Lock Out Mechanism",
        "Testing for Bypassing Authentication Schema",
        "Testing for Vulnerable Remember Password",
        "Testing for Browser Cache Weaknesses",
        "Testing for Weak Password Policy",
        "Testing for Weak Security Question Answer",
        "Testing for Weak Password Change or Reset Functionalities",
        "Testing for Weaker Authentication in Alternative Channel",
    ]),
    ("ATHZ", "Authorization", [
        "Testing Directory Traversal File Include",
        "Testing for Bypassing Authorization Schema",
        "Testing for Privilege Escalation",
        "Testing for Insecure Direct Object References",
    ]),
    ("SESS", "Session Management", [
        "Testing for Session Management Schema",
        "Testing for Cookies Attributes",
        "Testing for Session Fixation",
        "Testing for Exposed Session Variables",
        "Testing for Cross Site Request Forgery",
        "Testing for Logout Functionality",
        "Testing Session Timeout",
        "Testing for Session Puzzling",
        "Testing for Session Hijacking",
    ]),
    ("INPV", "Input Validation", [
        "Testing for Reflected Cross Site Scripting",
        "Testing for Stored Cross Site Scripting",
        "Testing for HTTP Verb Tampering",
        "Testing for HTTP Parameter Pollution",
        "Testing for SQL Injection",
        "Testing for LDAP Injection",
        "Testing for XML Injection",
        "Testing for SSI Injection",
        "Testing for XPath Injection",
        "Testing for IMAP SMTP Injection",
        "Testing for Code Injection",
        "Testing for Command Injection",
        "Testing for Format String Injection",
        "Testing for Incubated Vulnerability",
        "Testing for HTTP Splitting Smuggling",
        "Testing for HTTP Incoming Requests",
        "Testing for Host Header Injection",
        "Testing for Server-side Template Injection",
        "Testing for Server-Side Request Forgery",
    ]),
    ("ERRH", "Error Handling", [
        "Testing for Improper Error Handling",
        "Testing for Stack Traces",
    ]),
    ("CRYP", "Cryptography", [
        "Testing for Weak Transport Layer Security",
        "Testing for Padding Oracle",
        "Testing for Sensitive Information Sent via Unencrypted Channels",
        "Testing for Weak Encryption",
    ]),
    ("BUSL", "Business Logic", [
        "Test Business Logic Data Validation",
        "Test Ability to Forge Requests",
        "Test Integrity Checks",
        "Test for Process Timing",
        "Test Number of Times a Function Can Be Used Limits",
        "Testing for the Circumvention of Work Flows",
        "Test Defenses Against Application Misuse",
        "Test Upload of Unexpected File Types",
        "Test Upload of Malicious Files",
    ]),
    ("CLNT", "Client-side", [
        "Testing for DOM-Based Cross Site Scripting",
        "Testing for JavaScript Execution",
        "Testing for HTML Injection",
        "Testing for Client-side URL Redirect",
        "Testing for CSS Injection",
        "Testing for Client-side Resource Manipulation",
        "Testing Cross Origin Resource Sharing",
        "Testing for Cross Site Flashing",
        "Testing for Clickjacking",
        "Testing WebSockets",
        "Testing Web Messaging",
        "Testing Browser Storage",
        "Testing for Cross Site Script Inclusion",
    ]),
    ("APIT", "API Testing", [
        "API Reconnaissance",
    ]),
]

_STRIDE_CATS = {
    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
    "I": "Information Disclosure", "D": "Denial of Service", "E": "Elevation of Privilege",
}

_CLASSES = [
    "idor", "bac", "xss-reflected", "xss-stored", "xss-dom", "sqli", "ssrf",
    "graphql-bola", "cache-deception", "takeover", "ssti", "open-redirect", "xxe",
    "csrf", "auth-bypass", "info-disclosure", "secrets", "bucket", "nday",
]

# --- WSTG v4.2 static reference --------------------------------------------
# Per-test grounding so the Guided walkthrough never glosses over a test: an
# objective, a concrete how-to, the relevant recon-ctl lanes / external tools,
# and the official OWASP page URL (built from the canonical folder + test title,
# which matches OWASP's on-disk page naming). Keyed by full WSTG id.
_WSTG_FOLDER = {
    "INFO": "01-Information_Gathering",
    "CONF": "02-Configuration_and_Deployment_Management_Testing",
    "IDNT": "03-Identity_Management_Testing",
    "ATHN": "04-Authentication_Testing",
    "ATHZ": "05-Authorization_Testing",
    "SESS": "06-Session_Management_Testing",
    "INPV": "07-Input_Validation_Testing",
    "ERRH": "08-Testing_for_Error_Handling",
    "CRYP": "09-Testing_for_Weak_Cryptography",
    "BUSL": "10-Business_Logic_Testing",
    "CLNT": "11-Client-side_Testing",
    "APIT": "12-API_Testing",
}
_WSTG_BASE = ("https://owasp.org/www-project-web-security-testing-guide/latest/"
              "4-Web_Application_Security_Testing")


# Exact OWASP filenames (id -> "NN-slug") where a title-derived slug can't match the real page:
# OWASP preserves hyphens/casing in compound modifiers, and a couple of INPV tests were renamed.
_WSTG_URL_OVERRIDE = {
    "WSTG-CLNT-01": "01-Testing_for_DOM-based_Cross_Site_Scripting",
    "WSTG-CLNT-04": "04-Testing_for_Client-side_URL_Redirect",
    "WSTG-CLNT-06": "06-Testing_for_Client-side_Resource_Manipulation",
    "WSTG-INPV-15": "15-Testing_for_HTTP_Response_Splitting",
    "WSTG-INPV-16": "16-Testing_for_HTTP_Request_Smuggling",
    "WSTG-INPV-18": "18-Testing_for_Server-side_Template_Injection",
    "WSTG-INPV-19": "19-Testing_for_Server-Side_Request_Forgery",
    # OWASP renamed these tests (title/case drift from the code's older titles):
    "WSTG-INFO-04": "04-Attack_Surface_Identification",
    "WSTG-INFO-05": "05-Review_Web_Page_Content_for_Information_Leakage",
    "WSTG-ATHN-07": "07-Testing_for_Weak_Authentication_Methods",
    "WSTG-ERRH-01": "01-Testing_For_Improper_Error_Handling",
    "WSTG-CRYP-04": "04-Testing_for_Weak_Cryptographic_Primitives",
}


def _wstg_url(cat: str, num: int, name: str) -> str:
    folder = _WSTG_FOLDER.get(cat)
    if not folder:
        return f"{_WSTG_BASE}/"
    override = _WSTG_URL_OVERRIDE.get(f"WSTG-{cat}-{num:02d}")
    if override:
        return f"{_WSTG_BASE}/{folder}/{override}"
    # keep hyphens (OWASP preserves them in compound words like Client-side, DOM-based)
    slug = re.sub(r"[^A-Za-z0-9-]+", "_", name).strip("_")
    return f"{_WSTG_BASE}/{folder}/{num:02d}-{slug}"


# id -> (objective, how_to, tools). Names/category/url are merged from _WSTG_SPEC.
_WSTG_REF: dict[str, tuple[str, str, str]] = {
    "WSTG-INFO-01": (
        "Find information the app/organisation has leaked to search engines and public archives.",
        "Run search-engine and archive dorks (site:, filetype:, inurl:) and pull historical URLs to spot exposed paths, keys and docs. Cross-reference cached pages and pastebin/GitHub hits.",
        "google/bing dorks, recon-ghleaks, waybackurls/gau, recon-uncover"),
    "WSTG-INFO-02": (
        "Identify the web-server product and version to map it to known issues.",
        "Inspect Server/response headers, error-page banners and quirks; confirm with an active fingerprint. Note load balancers/CDNs that mask the origin.",
        "httpx, whatweb, nmap -sV, Burp"),
    "WSTG-INFO-03": (
        "Find metafiles (robots.txt, sitemap.xml, security.txt, .well-known) that leak paths or intent.",
        "Fetch the standard metafiles and parse Disallow/Allow entries and sitemaps for hidden or admin paths. Follow any referenced but unlinked resources.",
        "curl, httpx, recon-params crawl-host"),
    "WSTG-INFO-04": (
        "Enumerate all apps/vhosts running on the discovered hosts and ports.",
        "Resolve subdomains, sweep non-standard ports, and check virtual hosts / TLS SAN names for extra apps. Correlate with the ES asset surface.",
        "subfinder, recon-permute, recon-uncover, nmap, httpx"),
    "WSTG-INFO-05": (
        "Find sensitive info leaked in page content, comments, and JS (endpoints, keys, internal hosts).",
        "Read HTML comments and mine JS for endpoints, secrets and source-maps. jsintel un-maps minified bundles to the original source surface.",
        "recon-jsintel (jsluice/sourcemapper), recon-domxss, Burp"),
    "WSTG-INFO-06": (
        "Catalogue every request/parameter the app accepts (the attack surface).",
        "Proxy a full walk of the app and record every GET/POST, param, header and JSON field. Add hidden params via active discovery.",
        "Burp (site map), recon-params crawl-host, recon-params arjun, katana"),
    "WSTG-INFO-07": (
        "Understand the app's flows/states well enough to reason about coverage.",
        "Map the main workflows (auth, checkout, admin) and build a graph of transitions and trust boundaries. Use it to spot skipped-step and access-control gaps.",
        "Burp, manual walkthrough, recon-params crawl-host"),
    "WSTG-INFO-08": (
        "Fingerprint the application framework (Django/Rails/Laravel/Spring/etc.).",
        "Look at cookie names, default paths, error signatures, headers and JS bundles that reveal the framework and version. Map to framework-specific weaknesses.",
        "whatweb, wappalyzer, httpx, recon-mood <tech>"),
    "WSTG-INFO-09": (
        "Identify the specific application/product and version (CMS, panel, off-the-shelf app).",
        "Match favicons, meta generators, unique paths and JS to a known product; confirm the version. Feeds the n-day lane.",
        "whatweb, httpx, recon-nday, nuclei"),
    "WSTG-INFO-10": (
        "Produce the architecture picture: tiers, CDNs, gateways, third-party services, data flows.",
        "Diagram how requests route (CDN → WAF → gateway → app → API/DB) and where trust boundaries sit. Note where auth is enforced.",
        "Burp, DNS/CDN inspection, jsintel endpoint map"),
    "WSTG-CONF-01": (
        "Find weaknesses in the network/infra config exposed to the app tier.",
        "Sweep for exposed admin/management ports and services that shouldn't face the internet; verify open ports are real (not CDN-ACKed).",
        "nmap, httpx, recon-uncover (Shodan/Censys)"),
    "WSTG-CONF-02": (
        "Find platform-config mistakes: default files, sample apps, verbose modes, listings.",
        "Probe for default/sample content, directory listing, server-status/actuator style endpoints and debug flags. Confirm before claiming (many are by-design).",
        "nuclei, ffuf, httpx, recon-mood spring"),
    "WSTG-CONF-03": (
        "Check whether file extensions expose source or sensitive handling (.bak/.inc/.old/.php~).",
        "Request known files with alternate extensions and look for source disclosure or different handling. Watch for editor/backup suffixes.",
        "ffuf, curl, Burp Intruder"),
    "WSTG-CONF-04": (
        "Find old/backup/unreferenced files (archives, configs, dumps) left on the server.",
        "Fuzz for common backup names and archive extensions on known paths; check for .git/.svn/.env exposure. Verify content sensitivity before reporting.",
        "ffuf, git-dumper, nuclei, recon-params crawl-host"),
    "WSTG-CONF-05": (
        "Locate admin/management interfaces reachable from the internet.",
        "Brute common admin paths and inspect JS/routes for admin endpoints; check auth on each. An unauth-reachable admin panel is high value.",
        "ffuf, kiterunner (recon-kr), recon-params, Burp"),
    "WSTG-CONF-06": (
        "Test which HTTP methods are enabled (PUT/DELETE/TRACE) and whether they're dangerous.",
        "Send OPTIONS to list methods, then safely probe PUT/DELETE/TRACE and method-override headers. A writable PUT or verb-based authz bypass is a finding.",
        "curl -X, Burp Repeater, nuclei"),
    "WSTG-CONF-07": (
        "Verify HSTS is present and correctly configured on TLS endpoints.",
        "Check the Strict-Transport-Security header (max-age, includeSubDomains, preload). Missing HSTS alone is usually low/N-A without a concrete downgrade impact.",
        "curl -I, testssl.sh, Burp"),
    "WSTG-CONF-08": (
        "Test RIA cross-domain policies (crossdomain.xml, clientaccesspolicy.xml) for over-permissive rules.",
        "Fetch the policy files and flag wildcard domains that would allow untrusted cross-domain data access. Largely legacy Flash/Silverlight surface.",
        "curl, Burp"),
    "WSTG-CONF-09": (
        "Check file/directory permissions on exposed resources.",
        "Identify files that are world-readable/writable when they shouldn't be, and directories that allow listing or upload. Tie to concrete data exposure.",
        "httpx, ffuf, manual"),
    "WSTG-CONF-10": (
        "Detect dangling DNS that points to an unclaimed provider resource (subdomain takeover).",
        "For each CNAME/dangling record, verify NXDOMAIN or an unclaimed-provider fingerprint — not a live app 404. Only a claimable target is CONFIRMED.",
        "recon-permute, dnsx, subjack/nuclei-takeovers, the takeover lane"),
    "WSTG-CONF-11": (
        "Find exposed cloud storage (S3/GCS/Azure) referenced by the app.",
        "Mine bucket references from the app's own surface (never blind-permute), then read-only grade ACL/list; public-WRITE is reportable, public-READ is a content-sensitivity lead.",
        "recon-buckets (S3Scanner), jsintel/params provenance"),
    "WSTG-IDNT-01": (
        "Verify role definitions and that each role's privileges match intent.",
        "Enumerate the roles the app exposes and map what each can do; look for over-privileged or undocumented roles. Sets up authz testing.",
        "manual (2 owned accounts), Burp, app docs"),
    "WSTG-IDNT-02": (
        "Test the registration flow for weaknesses (unverified signup, role injection, duplicate identities).",
        "Register accounts and probe whether email/role/tenant fields are trusted from the client, and whether verification is enforced. Own-account setup only.",
        "Burp, recon-account, manual"),
    "WSTG-IDNT-03": (
        "Test how accounts are provisioned/de-provisioned for gaps (orphaned access, weak invites).",
        "Check invite/provisioning tokens for predictability and expiry, and whether de-provisioned users retain access. Use owned accounts.",
        "Burp, manual"),
    "WSTG-IDNT-04": (
        "Determine if valid usernames/emails can be enumerated via differing responses.",
        "Compare login/reset/registration responses and timing for existing vs non-existing accounts. A reliable oracle is the finding (impact permitting).",
        "Burp Intruder, ffuf, manual"),
    "WSTG-IDNT-05": (
        "Test username-policy weaknesses (predictable, no uniqueness, homoglyph/case collisions).",
        "Attempt to register colliding or predictable usernames and observe normalisation. Chain to enumeration or impersonation.",
        "Burp, manual"),
    "WSTG-ATHN-01": (
        "Confirm credentials are only transmitted over TLS.",
        "Watch the login/reset/change requests and confirm no credential is sent over HTTP or in a URL. Check for mixed-content submission.",
        "Burp, curl, testssl.sh"),
    "WSTG-ATHN-02": (
        "Test for default or well-known credentials on the app and any admin panels.",
        "Try vendor default creds on discovered login/admin interfaces (in-scope only). A working default is CONFIRMED access — stop at proof.",
        "manual, Burp, product docs"),
    "WSTG-ATHN-03": (
        "Test whether the lockout/anti-bruteforce mechanism is effective.",
        "Submit repeated failed logins and check for lockout, throttling or CAPTCHA. No lockout is a lead; pair with enumeration/weak-password for impact.",
        "Burp Intruder (throttled), manual"),
    "WSTG-ATHN-04": (
        "Test for authentication-schema bypass (forced browsing, param/logic flaws, token forgery).",
        "Attempt to reach post-auth resources directly, tamper auth params/JWTs, and skip steps. A real bypass that gets you IN is high severity — never brute someone else's login.",
        "Burp, jwt_tool, manual"),
    "WSTG-ATHN-05": (
        "Test 'remember me' for insecure persistence (predictable/eternal tokens, plaintext creds).",
        "Inspect the remember-me cookie for reversible/guessable content and whether it survives password change. Use owned accounts.",
        "Burp, manual"),
    "WSTG-ATHN-06": (
        "Check that sensitive pages aren't cached by the browser after logout.",
        "Review Cache-Control/Pragma on authenticated responses and confirm back-button/history doesn't reveal data post-logout. Usually low severity.",
        "Burp, browser devtools"),
    "WSTG-ATHN-07": (
        "Test password-policy strength (length, complexity, breach checks).",
        "Attempt weak/breached passwords on registration and change flows. Policy weakness is typically low unless it enables a broader chain.",
        "manual, Burp"),
    "WSTG-ATHN-08": (
        "Test security-question mechanisms for weak/guessable answers.",
        "Check whether questions are low-entropy or answers are OSINT-derivable, and whether they gate account recovery. Chain to account takeover.",
        "manual"),
    "WSTG-ATHN-09": (
        "Test password change/reset flows for bypass, token leakage, or host-header poisoning.",
        "Examine reset-token strength/expiry/single-use, whether the reset link honours a spoofed Host header, and whether the old password is required to change it.",
        "Burp, manual, Host-header injection probes"),
    "WSTG-ATHN-10": (
        "Test alternative auth channels (mobile app, API, SSO) for weaker enforcement.",
        "Compare auth strength across channels — the mobile/API path often skips lockout/MFA. Attack the weakest channel.",
        "Burp, mobile proxying, manual"),
    "WSTG-ATHZ-01": (
        "Test for path/directory traversal and local/remote file inclusion.",
        "Inject traversal sequences and file paths into path/file params and observe file read or inclusion. Prove read of a benign file — never harvest system secrets.",
        "Burp, ffuf, recon-params, manual"),
    "WSTG-ATHZ-02": (
        "Test for authorization-schema bypass (vertical: low-priv reaching high-priv functions).",
        "Replay privileged requests from a low-priv session and compare; use Burp Autorize for automated cross-role diffing. Two owned accounts.",
        "Burp Autorize, recon-ai-hunter, manual"),
    "WSTG-ATHZ-03": (
        "Test for privilege escalation (role/tenant elevation via tampered attributes or flows).",
        "Tamper role/plan/tenant fields and mass-assignable attributes to gain higher privileges; verify server-side enforcement. Owned accounts, stop at proof.",
        "Burp, recon-ai-hunter, manual"),
    "WSTG-ATHZ-04": (
        "Test for IDOR/BOLA: object references that aren't authorization-checked.",
        "Enumerate object-ref params and, with TWO owned accounts, swap IDs to read/modify the other account's object. Numeric=enumerable, UUID=harvest from JS. Never touch third-party IDs.",
        "recon-idor candidates, recon-ai-hunter, Burp Autorize, recon-graphql"),
    "WSTG-SESS-01": (
        "Analyse the session-management scheme (token generation, entropy, binding).",
        "Collect many session tokens and analyse structure/entropy; check binding to user/IP and server-side invalidation. Weak/predictable tokens are the finding.",
        "Burp Sequencer, manual"),
    "WSTG-SESS-02": (
        "Test cookie attributes (HttpOnly, Secure, SameSite, scope, expiry).",
        "Review each session cookie's flags and domain/path scope. Missing HttpOnly/Secure matters when it enables theft; report with concrete impact.",
        "Burp, browser devtools"),
    "WSTG-SESS-03": (
        "Test for session fixation (a pre-auth token surviving authentication).",
        "Set a known session pre-login and check whether it's still valid (unrotated) after login. Rotation-on-auth absence is the finding.",
        "Burp, manual (owned account)"),
    "WSTG-SESS-04": (
        "Find session variables exposed in URLs, logs, referers, or client storage.",
        "Look for session IDs/tokens in query strings, redirects and browser storage that could leak via referer/history. Tie to a theft path.",
        "Burp, devtools, manual"),
    "WSTG-SESS-05": (
        "Test for CSRF on state-changing requests.",
        "Check whether state-changing actions require an unpredictable, bound anti-CSRF token (not just SameSite). Build a PoC form that performs the action cross-site.",
        "Burp (CSRF PoC), manual"),
    "WSTG-SESS-06": (
        "Test that logout actually invalidates the session server-side.",
        "Capture a token, log out, then replay the token and confirm it's rejected server-side (not just cleared client-side).",
        "Burp Repeater, manual"),
    "WSTG-SESS-07": (
        "Test session timeout (idle/absolute) enforcement.",
        "Leave a session idle past the stated timeout and replay; confirm the server expires it. Absent timeout is usually low without chaining.",
        "Burp, manual"),
    "WSTG-SESS-08": (
        "Test for session puzzling (session variables reused across flows to bypass logic).",
        "Trace whether a variable set in one flow (e.g. reset) is honoured to authenticate/authorize in another. Owned accounts.",
        "Burp, manual"),
    "WSTG-SESS-09": (
        "Test for session hijacking exposure (token theft/replay from another context).",
        "Assess whether a captured token is usable from a different IP/UA and how it could be captured (XSS, leak). Chain from an exposure primitive.",
        "Burp, manual"),
    "WSTG-INPV-01": (
        "Test for reflected XSS (input reflected into a response and executed).",
        "Inject context-aware break-out payloads and confirm EXECUTION, not mere reflection — encoded reflection is not XSS. dalfox verifies execution headlessly.",
        "recon-params confirm xss (dalfox), Burp, manual"),
    "WSTG-INPV-02": (
        "Test for stored/persistent XSS (payload stored then executed for other users).",
        "Plant a payload in stored fields and confirm it fires when rendered; blind sinks (admin consoles) need a persistent OOB beacon.",
        "recon-blindxss (interactsh beacon), dalfox, Burp"),
    "WSTG-INPV-03": (
        "Test for HTTP verb tampering (authz/logic that depends on the method).",
        "Swap GET/POST/HEAD/arbitrary methods and method-override headers to bypass access control or reach unintended handlers.",
        "curl -X, Burp Repeater"),
    "WSTG-INPV-04": (
        "Test for HTTP parameter pollution (duplicate params parsed inconsistently).",
        "Send duplicate/array params and observe which layer wins; use it to bypass filters/WAF or alter logic.",
        "Burp, recon-params, manual"),
    "WSTG-INPV-05": (
        "Test for SQL injection.",
        "Use the SAFE `'` vs `''` error/boolean differential to confirm injectability, THEN sqlmap for verification depth (banner/current-db) — never mass-dump third-party PII; rate-limited.",
        "recon-params confirm sqli (diff→sqlmap), Burp"),
    "WSTG-INPV-06": (
        "Test for LDAP injection in directory-backed lookups (login, search).",
        "Inject LDAP metacharacters (*, ), &, |) into fields that feed a directory query and watch for auth bypass or altered result sets.",
        "Burp, manual"),
    "WSTG-INPV-07": (
        "Test for XML injection / XXE where XML is parsed.",
        "Inject XML metacharacters and external entities; confirm XXE via an OUT-OF-BAND callback to a canary — never point entities at internal data.",
        "Burp, interactsh (OOB canary), manual"),
    "WSTG-INPV-08": (
        "Test for Server-Side Includes injection.",
        "Inject SSI directives into inputs reflected by an SSI-enabled server and check for evaluation. Prove execution with a benign directive.",
        "Burp, manual"),
    "WSTG-INPV-09": (
        "Test for XPath injection in XML-query backed features.",
        "Inject XPath metacharacters into search/login params and observe boolean/error differentials or auth bypass.",
        "Burp, manual"),
    "WSTG-INPV-10": (
        "Test for IMAP/SMTP injection in mail-interacting features.",
        "Inject CRLF/command sequences into mail fields (contact, invite) to smuggle commands or headers. Prove with a benign header injection.",
        "Burp, manual"),
    "WSTG-INPV-11": (
        "Test for code injection (input evaluated as server-side code).",
        "Probe params that may reach eval/include with language-specific payloads; confirm code execution with a benign, non-destructive proof — never run RCE-for-harm.",
        "Burp, manual"),
    "WSTG-INPV-12": (
        "Test for OS command injection.",
        "Inject shell metacharacters and confirm via a benign OOB callback or timing; do not run destructive commands. In-scope only.",
        "Burp, interactsh (OOB), manual"),
    "WSTG-INPV-13": (
        "Test for format-string injection.",
        "Feed format specifiers into inputs that may reach a formatting function and observe crashes/leaks. Rare in web stacks.",
        "Burp, manual"),
    "WSTG-INPV-14": (
        "Test for incubated (second-order) vulnerabilities.",
        "Plant tainted data that is stored and later used in a dangerous sink elsewhere; trace the delayed execution path.",
        "Burp, manual"),
    "WSTG-INPV-15": (
        "Test for HTTP response splitting / request smuggling.",
        "Inject CR/LF into reflected headers (splitting) and test desync via crafted CL/TE requests (smuggling). Prove carefully — smuggling can affect other users, keep it benign.",
        "Burp, smuggler, manual"),
    "WSTG-INPV-16": (
        "Analyse how the app handles incoming requests / proxy trust.",
        "Examine trust of forwarded/proxy headers and how the app parses incoming requests. Feeds smuggling/host-header/SSRF testing.",
        "Burp, manual"),
    "WSTG-INPV-17": (
        "Test for Host-header injection (poisoned links, cache, routing).",
        "Send crafted/duplicated Host and X-Forwarded-Host headers and observe reflection into links (password-reset), cache keys or routing.",
        "Burp, curl, recon-wcd"),
    "WSTG-INPV-18": (
        "Test for Server-Side Template Injection.",
        "Inject template syntax like {{7*7}} and confirm evaluation (49) — math only, never RCE. A confirmed evaluation is the primitive; escalate cautiously.",
        "Burp, tplmap (careful), manual"),
    "WSTG-INPV-19": (
        "Test for Server-Side Request Forgery.",
        "Point URL/host params at an interactsh canary and confirm the OOB callback; probe for metadata/internal reach but never exfiltrate internal data. SSRF guard applies.",
        "recon-ai-hunter, interactsh (OOB), Burp"),
    "WSTG-ERRH-01": (
        "Test error handling for information leakage / inconsistent behaviour.",
        "Trigger errors with malformed input and review responses for stack traces, framework details or logic leaks. Report only meaningful disclosure.",
        "Burp, manual"),
    "WSTG-ERRH-02": (
        "Test specifically for stack traces exposing internals.",
        "Force exceptions and capture stack traces revealing paths, versions, queries or secrets. Value depends on what's disclosed.",
        "Burp, manual"),
    "WSTG-CRYP-01": (
        "Test TLS configuration for weak protocols/ciphers/certs.",
        "Scan the endpoint for deprecated protocols, weak ciphers, cert issues and missing forward secrecy. Report exploitable weaknesses, not just scanner noise.",
        "testssl.sh, sslscan, nmap --script ssl-enum-ciphers"),
    "WSTG-CRYP-02": (
        "Test for padding-oracle weaknesses in CBC-mode crypto.",
        "Find tokens/ciphertext the app decrypts and probe for a padding oracle via response differentials. Confirm the oracle before claiming.",
        "padbuster, Burp, manual"),
    "WSTG-CRYP-03": (
        "Find sensitive data sent over unencrypted channels.",
        "Look for credentials/PII/tokens transmitted over HTTP or to non-TLS endpoints/mixed content. Tie to a real interception path.",
        "Burp, testssl.sh, manual"),
    "WSTG-CRYP-04": (
        "Test for weak encryption / bad crypto usage (weak algos, static keys, ECB).",
        "Inspect encrypted tokens/fields for weak algorithms, reused/static keys or ECB patterns. Chain to forgery/decryption for impact.",
        "manual, CyberChef, Burp"),
    "WSTG-BUSL-01": (
        "Test business-logic data validation (server trusts client-side constraints).",
        "Bypass client validation and submit values the server should reject (negative price, oversized qty, skipped fields). Prove a state change with impact.",
        "Burp, manual"),
    "WSTG-BUSL-02": (
        "Test ability to forge requests (guess/craft params the UI never exposes).",
        "Craft requests with hidden/undocumented params or values to trigger unintended behaviour. Owned account, non-destructive proof.",
        "Burp, recon-params arjun, manual"),
    "WSTG-BUSL-03": (
        "Test integrity checks on client-controlled data (hidden fields, totals, signatures).",
        "Tamper hidden/priced/signed fields and see if the server re-validates. A trusted client total is a classic finding.",
        "Burp, manual"),
    "WSTG-BUSL-04": (
        "Test process timing (race conditions, timing-dependent logic).",
        "Fire concurrent requests at limited actions (redeem coupon, withdraw, apply) to exploit TOCTOU races. Keep proofs non-damaging.",
        "Burp Turbo Intruder, manual"),
    "WSTG-BUSL-05": (
        "Test function-usage limits (one-time actions reusable N times).",
        "Replay actions meant to be single-use (coupon, vote, invite) and confirm the limit isn't enforced. Prove without real financial movement.",
        "Burp, manual"),
    "WSTG-BUSL-06": (
        "Test for workflow circumvention (skipping required steps).",
        "Reach a later state directly without completing prerequisite steps (pay-then-ship, verify-then-act). Map the flow first (INFO-07).",
        "Burp, manual"),
    "WSTG-BUSL-07": (
        "Test defenses against application misuse (does the app detect/limit abuse?).",
        "Probe whether abnormal automated/abusive behaviour is detected and throttled. Usually informational unless it enables another attack.",
        "Burp, manual"),
    "WSTG-BUSL-08": (
        "Test upload of unexpected file types.",
        "Upload files with disallowed types/extensions/MIME and check enforcement (extension, magic bytes, content). Chain to storage/exec.",
        "Burp, manual"),
    "WSTG-BUSL-09": (
        "Test upload of malicious files (webshell, polyglot, oversized).",
        "Attempt to upload and reach an executable/dangerous file; confirm it's served/executed. Use a benign marker, never a live shell for harm.",
        "Burp, manual"),
    "WSTG-CLNT-01": (
        "Test for DOM-based XSS (client-side source→sink taint).",
        "Trace tainted sources (location/hash/postMessage) into dangerous sinks (innerHTML/eval); confirm execution headlessly.",
        "recon-domxss, dalfox --deep-domxss, Burp DOM Invader"),
    "WSTG-CLNT-02": (
        "Test for arbitrary JavaScript execution via client-side flaws.",
        "Find client code that executes attacker-controlled strings (eval, Function, setTimeout-string) and prove execution.",
        "recon-domxss, devtools, manual"),
    "WSTG-CLNT-03": (
        "Test for client-side HTML injection.",
        "Inject markup into client-rendered content that isn't script-executable but alters the DOM (phishing, defacement). Distinguish from XSS.",
        "Burp, devtools, manual"),
    "WSTG-CLNT-04": (
        "Test for client-side URL redirect (open redirect via client code).",
        "Feed attacker URLs into client-side redirect logic (location = param) and confirm redirection off-domain. Chain to phishing/OAuth theft.",
        "Burp, recon-params, manual"),
    "WSTG-CLNT-05": (
        "Test for CSS injection.",
        "Inject CSS into style contexts and assess data exfil (attribute selectors) or UI redress. Niche but real in some apps.",
        "Burp, manual"),
    "WSTG-CLNT-06": (
        "Test for client-side resource manipulation (attacker-controlled script/link/src).",
        "Find params that drive script/iframe/link targets on the client and point them at attacker resources. Chain to XSS/exfil.",
        "Burp, devtools, manual"),
    "WSTG-CLNT-07": (
        "Test CORS configuration for over-permissive cross-origin access.",
        "Probe ACAO/ACAC handling with varied Origins; a reflected Origin + credentials true on sensitive data is the finding — reflection alone on public data is N-A.",
        "Burp, curl, manual"),
    "WSTG-CLNT-08": (
        "Test for cross-site flashing (Flash crossdomain / FlashVars issues).",
        "Assess any remaining Flash for insecure crossdomain and injectable FlashVars. Mostly legacy/dead surface.",
        "manual, Burp"),
    "WSTG-CLNT-09": (
        "Test for clickjacking (framing of sensitive actions).",
        "Check X-Frame-Options/CSP frame-ancestors and build a framing PoC that tricks a click on a sensitive action. Needs a real actionable target.",
        "Burp, framing PoC, manual"),
    "WSTG-CLNT-10": (
        "Test WebSocket security (origin checks, auth, message tampering).",
        "Inspect the WS handshake for origin/auth enforcement and tamper messages for authz/injection issues.",
        "Burp (WS), manual"),
    "WSTG-CLNT-11": (
        "Test web messaging (postMessage) for missing origin validation.",
        "Find postMessage handlers that don't validate origin and feed them malicious data reaching a sink. Chain to DOM-XSS/data theft.",
        "recon-domxss, devtools, Burp"),
    "WSTG-CLNT-12": (
        "Test browser storage (localStorage/sessionStorage/IndexedDB) for sensitive data.",
        "Inspect client storage for tokens/PII and assess XSS-reachability. Sensitive tokens in localStorage amplify any XSS.",
        "devtools, Burp, manual"),
    "WSTG-CLNT-13": (
        "Test for Cross-Site Script Inclusion (XSSI) leaking data via script include.",
        "Try including sensitive JS/JSON endpoints cross-origin as <script> and see if data leaks (non-standard JSON, callback params).",
        "Burp, manual"),
    "WSTG-APIT-01": (
        "Recon the API surface: endpoints, schemas, auth model, object references.",
        "Harvest routes from JS/specs (OpenAPI/GraphQL introspection) and brute API paths; map object-ref params for BOLA and injectable args. Feeds IDOR/GraphQL lanes.",
        "recon-jsintel, recon-kr (kiterunner), recon-graphql, recon-idor candidates"),
}


def wstg_reference() -> dict[str, dict[str, str]]:
    """Full static WSTG reference keyed by id: name/category/objective/how_to/tools/wstg_url."""
    out: dict[str, dict[str, str]] = {}
    for cat, cat_name, names in _WSTG_SPEC:
        for i, name in enumerate(names, 1):
            wid = f"WSTG-{cat}-{i:02d}"
            obj, how, tools = _WSTG_REF.get(wid, ("", "", ""))
            out[wid] = {
                "id": wid, "category": cat, "cat_name": cat_name, "name": name,
                "objective": obj, "how_to": how, "tools": tools,
                "wstg_url": _wstg_url(cat, i, name),
            }
    return out


STRIDE_GUIDE: dict[str, dict[str, Any]] = {
    "S": {"name": "Spoofing", "prompt": (
        "Enumerate identity/authentication threats: where can an attacker pretend to be another "
        "user, service, or the server itself? Focus on auth schema, token/JWT forgery, session "
        "fixation, SSO/OAuth flows, and email/host spoofing."), "examples": [
        "Forgeable or unbound session/JWT token (alg=none, weak secret) → impersonation.",
        "Password-reset link honours a spoofed Host header → account takeover.",
        "Missing origin validation on postMessage/SSO callback → identity confusion."]},
    "T": {"name": "Tampering", "prompt": (
        "Enumerate integrity threats: which client-controlled data does the server trust without "
        "re-validation? Focus on hidden/priced fields, mass-assignable attributes, parameter "
        "pollution, and injection into interpreters."), "examples": [
        "Client-side price/quantity trusted at checkout → business-logic tampering.",
        "Mass-assignment of role/tenant on a profile update → privilege change.",
        "SQL/command/template injection where input reaches an interpreter."]},
    "R": {"name": "Repudiation", "prompt": (
        "Enumerate accountability threats: what actions can a user perform without a reliable, "
        "tamper-evident audit trail? Focus on missing logging, forgeable logs, and unverifiable "
        "transactions."), "examples": [
        "Sensitive state-changing action produces no server-side audit record.",
        "User-controllable timestamp/actor fields let an action be denied later.",
        "Log injection via unsanitised input corrupts the audit trail."]},
    "I": {"name": "Information Disclosure", "prompt": (
        "Enumerate confidentiality threats: where can data leak to an unauthorised party? Focus on "
        "IDOR/BOLA, verbose errors, exposed JS secrets/endpoints, open buckets, and directory/backup "
        "exposure."), "examples": [
        "IDOR on an object-ref endpoint returns another tenant's data.",
        "Leaked API key/endpoint in a JS bundle or reconstructed source-map.",
        "Public-read bucket or exposed backup file with sensitive content."]},
    "D": {"name": "Denial of Service", "prompt": (
        "Enumerate availability threats — but keep every probe non-damaging (never actually DoS an "
        "in-scope target). Focus on unbounded/expensive operations and missing rate limits, reported "
        "by reasoning, not by taking the service down."), "examples": [
        "Unbounded query/expansion (GraphQL nesting, large export) with no cost limit.",
        "No rate limit on an expensive endpoint (report the gap, do not flood it).",
        "Amplification via a redirect/callback the app will fetch repeatedly."]},
    "E": {"name": "Elevation of Privilege", "prompt": (
        "Enumerate authorization threats: where can a low-privilege user reach high-privilege "
        "functions or another role/tenant? Focus on vertical/horizontal access-control bypass, "
        "forced browsing to admin, and IDOR-to-privesc chains (test with two owned accounts)."), "examples": [
        "Low-priv session replaying an admin-only request succeeds (Burp Autorize).",
        "Forced-browse to an unauth-reachable admin interface.",
        "Tampering a role/plan attribute elevates privileges server-side."]},
}


def merge_reference(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return WSTG items with the static reference (objective/how_to/tools/wstg_url) merged in."""
    ref = wstg_reference()
    out = []
    for it in items:
        r = ref.get(it.get("id", ""), {})
        out.append({**it, "objective": r.get("objective", ""), "how_to": r.get("how_to", ""),
                    "tools": r.get("tools", ""), "wstg_url": r.get("wstg_url", "")})
    return out


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _slug(s: str) -> str:
    """Sanitize to [A-Za-z0-9_-]; lowercased, collapsed, trimmed, capped."""
    s = re.sub(r"[^A-Za-z0-9_-]+", "-", (s or "").strip()).strip("-_")
    return s[:64].lower()


def _path(key: str) -> Path:
    """Resolve a workspace file path, confined to WORKSPACES_DIR (no traversal)."""
    slug = _slug(key)
    if not slug:
        raise ValueError("invalid workspace key")
    p = (WORKSPACES_DIR / f"{slug}.json").resolve()
    root = WORKSPACES_DIR.resolve()
    if root not in p.parents:
        raise ValueError("path traversal refused")
    return p


def _seed_wstg() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for cat, cat_name, names in _WSTG_SPEC:
        for i, name in enumerate(names, 1):
            items.append({
                "id": f"WSTG-{cat}-{i:02d}", "category": cat, "cat_name": cat_name,
                "name": name, "status": "todo", "note": "", "updated_at": None,
            })
    return items


def _new_workspace(key: str, name: str, platform: str) -> dict[str, Any]:
    ts = _now()
    return {
        "key": key, "name": name or key, "platform": platform or "",
        "added_at": ts, "status": "active", "current": False,
        "wstg": _seed_wstg(),
        "stride": {c: [] for c in _STRIDE_CATS},
        "classes": [{"cls": c, "status": "todo"} for c in _CLASSES],
        "notes": [],
        "history": [{"ts": ts, "event": f"workspace created ({platform or '?'})"}],
    }


# --- persistence -----------------------------------------------------------
def save(ws: dict[str, Any]) -> dict[str, Any]:
    """Atomically write a workspace to disk. Returns the workspace."""
    WORKSPACES_DIR.mkdir(parents=True, exist_ok=True)
    p = _path(ws["key"])
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(ws, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, p)
    return ws


def load(key: str) -> dict[str, Any] | None:
    """Read one workspace by key. Never raises — bad key/missing/corrupt → None."""
    try:
        p = _path(key)
    except ValueError:
        return None
    if not p.exists():
        return None
    try:
        ws = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    ws.setdefault("followups", [])   # added later; older workspaces load without it
    return ws


def list_all() -> list[dict[str, Any]]:
    """All workspaces, oldest-first by added_at. Corrupt files are skipped."""
    out: list[dict[str, Any]] = []
    try:
        for p in WORKSPACES_DIR.glob("*.json"):
            try:
                out.append(json.loads(p.read_text(encoding="utf-8", errors="replace")))
            except Exception:
                continue
    except Exception:
        pass
    out.sort(key=lambda w: w.get("added_at") or "")
    return out


def summarize(ws: dict[str, Any]) -> dict[str, int]:
    """Cheap, offline counts (findings/hosts are joined live by the caller)."""
    wstg = ws.get("wstg", [])
    classes = ws.get("classes", [])
    return {
        "wstg_total": len(wstg),
        "wstg_done": sum(1 for w in wstg if w.get("status") == "done"),
        "wstg_inprogress": sum(1 for w in wstg if w.get("status") == "in-progress"),
        "wstg_findings": sum(1 for w in wstg if w.get("status") == "finding"),
        "findings": 0,  # live-joined by the app layer
        "hosts": 0,     # live-joined by the app layer
        "classes_done": sum(1 for c in classes if c.get("status") not in (None, "", "todo")),
    }


# --- mutations -------------------------------------------------------------
def create(key: str, name: str | None = None, platform: str | None = None) -> dict[str, Any]:
    """Create+seed a workspace, or return the existing one (idempotent).

    The first-ever workspace is marked `current` so the UI always has an active one.
    """
    slug = _slug(key)
    if not slug:
        raise ValueError("invalid workspace key")
    existing = load(slug)
    if existing:
        return existing
    first = not list_all()
    ws = _new_workspace(slug, name or key, platform or "")
    if first:
        ws["current"] = True
        ws["history"].append({"ts": _now(), "event": "marked current"})
    return save(ws)


def update_wstg(key: str, wid: str, status: str, note: str | None = None) -> dict[str, Any]:
    ws = load(key)
    if not ws:
        raise KeyError(key)
    if status not in WSTG_STATUS:
        raise ValueError(f"invalid status: {status} (allowed: {sorted(WSTG_STATUS)})")
    item = next((w for w in ws["wstg"] if w["id"] == wid), None)
    if not item:
        raise KeyError(wid)
    item["status"] = status
    if note is not None:
        item["note"] = str(note)[:2000]
    item["updated_at"] = _now()
    ws["history"].append({"ts": item["updated_at"], "event": f"{wid} → {status}"})
    return save(ws)


def update_stride(key: str, cat: str, threat: str, sid: str | None = None,
                  note: str | None = None, status: str | None = None,
                  hosts: list[str] | None = None) -> dict[str, Any]:
    ws = load(key)
    if not ws:
        raise KeyError(key)
    cat = (cat or "").strip().upper()[:1]
    if cat not in _STRIDE_CATS:
        raise ValueError(f"invalid STRIDE category: {cat} (allowed: {sorted(_STRIDE_CATS)})")
    if not (threat or "").strip():
        raise ValueError("threat text required")
    bucket = ws["stride"].setdefault(cat, [])
    row = next((t for t in bucket if t.get("id") == sid), None) if sid else None
    ts = _now()
    if row is None:
        row = {"id": f"{cat}{len(bucket) + 1}", "threat": "", "note": "",
               "status": "open", "hosts": []}
        bucket.append(row)
        ws["history"].append({"ts": ts, "event": f"STRIDE {cat} threat added"})
    else:
        ws["history"].append({"ts": ts, "event": f"STRIDE {row['id']} updated"})
    row["threat"] = str(threat)[:500]
    if note is not None:
        row["note"] = str(note)[:2000]
    if status is not None:
        row["status"] = str(status)[:40]
    if hosts is not None:
        row["hosts"] = [str(h)[:255] for h in hosts][:50]
    return save(ws)


def set_class(key: str, cls: str, status: str) -> dict[str, Any]:
    ws = load(key)
    if not ws:
        raise KeyError(key)
    cls = (cls or "").strip().lower()
    status = (status or "").strip()
    if not cls or not status:
        raise ValueError("cls and status required")
    row = next((c for c in ws["classes"] if c["cls"] == cls), None)
    if row is None:
        row = {"cls": cls, "status": "todo"}
        ws["classes"].append(row)
    row["status"] = status[:40]
    ws["history"].append({"ts": _now(), "event": f"class {cls} → {status}"})
    return save(ws)


def add_note(key: str, text: str) -> dict[str, Any]:
    ws = load(key)
    if not ws:
        raise KeyError(key)
    text = (text or "").strip()
    if not text:
        raise ValueError("note text required")
    ts = _now()
    ws["notes"].append({"ts": ts, "text": text[:4000]})
    ws["history"].append({"ts": ts, "event": "note added"})
    return save(ws)


def delete_stride(key: str, cat: str, sid: str) -> dict[str, Any]:
    ws = load(key)
    if not ws:
        raise KeyError(key)
    cat = (cat or "").strip().upper()[:1]
    bucket = ws.get("stride", {}).get(cat, [])
    kept = [t for t in bucket if t.get("id") != sid]
    if len(kept) != len(bucket):
        ws["stride"][cat] = kept
        ws["history"].append({"ts": _now(), "event": f"STRIDE {sid} deleted"})
        return save(ws)
    return ws


def delete_note(key: str, index: int) -> dict[str, Any]:
    ws = load(key)
    if not ws:
        raise KeyError(key)
    notes = ws.get("notes", [])
    if 0 <= index < len(notes):
        notes.pop(index)
        ws["history"].append({"ts": _now(), "event": "note deleted"})
        return save(ws)
    return ws


# --- test-account credentials (LOCAL ONLY — never committed/mirrored) ------
# Per-program login/creds for authed testing live under ~/recon/state/private_programs/,
# chmod 600, OUTSIDE the repo. Doctrine: I save creds locally; the operator does the final
# submit. Two owned accounts (a/b) enable the 2-account IDOR swap.
def _accounts_path(key: str) -> Path:
    d = config.STATE_DIR / "private_programs"
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except Exception:
        pass
    return d / f"{_slug(key)}_accounts.json"


def get_accounts(key: str) -> list[dict[str, Any]]:
    """Read the saved test accounts for a program (local-only). Never raises."""
    p = _accounts_path(key)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def set_accounts(key: str, accounts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Persist test accounts for a program to the local, 600-perm creds file."""
    clean: list[dict[str, Any]] = []
    for a in (accounts or [])[:6]:
        if not isinstance(a, dict):
            continue
        row = {k: str(a.get(k, ""))[:400] for k in ("label", "email", "username", "password", "url", "notes")}
        if any(row.values()):
            clean.append(row)
    p = _accounts_path(key)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(clean, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, p)
    try:
        p.chmod(0o600)
    except Exception:
        pass
    return clean


def set_status(key: str, status: str | None = None,
               current: bool | None = None) -> dict[str, Any]:
    ws = load(key)
    if not ws:
        raise KeyError(key)
    ts = _now()
    if status is not None:
        status = str(status).strip().lower()
        if status not in WS_STATUS:
            raise ValueError(f"invalid status: {status} (allowed: {sorted(WS_STATUS)})")
        ws["status"] = status
        ws["history"].append({"ts": ts, "event": f"status → {status}"})
    if current:
        # exactly one current workspace: unset it everywhere else first
        for other in list_all():
            if other.get("key") != ws["key"] and other.get("current"):
                other["current"] = False
                other.setdefault("history", []).append({"ts": ts, "event": "unset current"})
                save(other)
        ws["current"] = True
        ws["history"].append({"ts": ts, "event": "marked current"})
    elif current is False:
        ws["current"] = False
        ws["history"].append({"ts": ts, "event": "unset current"})
    return save(ws)


# --- candidates + seed -----------------------------------------------------
def _existing_names() -> set[str]:
    names: set[str] = set()
    for w in list_all():
        names.add((w.get("name") or "").lower())
        names.add((w.get("key") or "").lower())
    return names


def candidates(limit: int = 20) -> list[dict[str, Any]]:
    """High-scored programs from the target board not yet in a workspace."""
    taken = _existing_names()
    out: list[dict[str, Any]] = []
    try:
        for p in files.target_board().get("programs", []):
            name = (p.get("name") or "").strip()
            if not name or name.lower() in taken or _slug(name) in taken:
                continue
            out.append({
                "key": _slug(name), "name": name,
                "platform": p.get("platform") or "",
                "score": p.get("score"),
            })
            if len(out) >= limit:
                break
    except Exception:
        pass
    return out


def _discover_glassdoor() -> tuple[str, str]:
    """(name, platform) for Glassdoor from the target board, with a safe fallback."""
    try:
        for p in files.target_board().get("programs", []):
            if "glass" in (p.get("name") or "").lower():
                return (p["name"], p.get("platform") or GLASSDOOR_PLATFORM)
    except Exception:
        pass
    return (GLASSDOOR_NAME, GLASSDOOR_PLATFORM)


def ensure_seeded() -> dict[str, Any] | None:
    """One-time: if there are no workspaces yet, seed Glassdoor as the current one.

    Best-effort — a read-only FS or any error is swallowed so a read never fails.
    """
    try:
        if list_all():
            return None
        name, platform = _discover_glassdoor()
        return create("glassdoor", name, platform)
    except Exception:
        return None


# --- AI-guidance prompt (Claude co-pilot) ----------------------------------
_DOCTRINE = (
    "DOCTRINE (hard lines): only in-scope + paying hosts; IDOR/BAC uses TWO accounts the "
    "researcher OWNS (never guessed/third-party IDs); reflection is NOT XSS (execution must be "
    "proven); PoC-or-GTFO — prove it or move on; never harvest third-party data, move money, or "
    "run destructive/RCE-for-harm; authenticated testing stays operator-overseen. Recommend the "
    "SAFE confirm primitive per class."
)

# The co-pilot runs at cwd = the repo root, so the `burp` and `brave` MCP servers in the repo
# .mcp.json auto-load — its tools are available to DRIVE the test, not just describe it. If a
# backing service is down the tool call fails; degrade to exact manual steps rather than retrying.
_DRIVE_TOOLS = (
    "TOOLS YOU CAN DRIVE (auto-loaded from the repo .mcp.json):\n"
    "  - `burp` MCP → Burp Pro (proxy on 127.0.0.1:9876). Use Repeater to replay/modify the actual "
    "requests, Intruder for controlled fuzzing, and Autorize for cross-role / cross-tenant IDOR/BOLA "
    "diffing. Default to read-only (GET/HEAD/OPTIONS); in-scope + paying only; confirm-then-stop.\n"
    "  - `brave` MCP → the operator's logged-in debug Brave over CDP (chrome-devtools, :9222). Use it "
    "to NAVIGATE to pages, read the live DOM / JS / network requests, and run browser-driven / "
    "client-side checks in the authed session.\n"
    "  - BURP PROJECT: for sustained work on this program/target, RECOMMEND the operator open a "
    "DEDICATED Burp project (one per program) up front, so proxy history / Repeater / Intruder / "
    "Autorize state persists across the whole engagement; then drive it via the burp MCP.\n"
    "If a `burp` call fails, Burp Pro isn't up with its MCP server on :9876; if a `brave` call fails, "
    "debug-Brave isn't running on :9222 (launch: scripts/launch_brave_debug.ps1). In that case say so "
    "plainly and hand the operator the exact manual steps/commands instead of retrying blindly."
)

# When a test needs authentication / owned accounts, drive the signup rather than stopping dead.
_ACCOUNTS = (
    "IF THIS TEST NEEDS AUTH OR TWO ACCOUNTS (IDOR/BOLA, authz, session, most business-logic): STOP "
    "and tell the operator up front that owned accounts are required, then DRIVE the signup — navigate "
    "Brave to the target's registration/signup page, and/or run the provisioner "
    "`python3 scripts/recon_account.py create <name> --url <signup_url> --platform <bugcrowd|hackerone|"
    "yeswehack|gmail> --label <a|b>` (alias `recon-account`; the operator solves the CAPTCHA + final "
    "submit; creds are local-only). Provision TWO accounts the operator OWNS, then confirm with the "
    "2-account swap using ONLY your own object IDs — never a guessed/enumerated third-party ID. "
    "While signing up / logging in, CAPTURE the auth flow in Burp (the login/token/refresh requests, "
    "the session-cookie + auth-header NAMES, the JWT structure, your own user/object IDs) and FLAG "
    "anything interesting for the class you're hunting — predictable/enumerable IDs, JWT alg=none or a "
    "weak secret, an open oauth redirect_uri, IDOR-shaped params. This applies to single targets too."
)

# Depth doctrine: version-aware + exhaustive, grounded in the recorded KB methodology.
_EXHAUSTIVE = (
    "GO EXHAUSTIVE + VERSION-AWARE — do EVERYTHING to find the bug for THIS target:\n"
    "- FINGERPRINT the exact stack + VERSIONS (server, framework, libraries, WAF/CDN) from headers, "
    "JS bundles, error pages, favicon hash, /actuator etc. Map version-specific CVEs / known exploits "
    "and VERSION-REASON whether the running version is genuinely in range — never a tech-class-only P0.\n"
    "- READ the recorded methodology for this class in the docs/knowledge/class-*.md file(s) named "
    "below (use the Read tool) and apply EVERY applicable technique/payload/bypass in it — not just the "
    "happy path. Adapt payloads to the target's framework/encoding/WAF; if standard payloads are "
    "filtered, RESEARCH that framework's specific sinks/bypasses and try those.\n"
    "- A first negative probe is NOT proof of absence: enumerate the untested angles (other params/"
    "endpoints/verbs/content-types/headers, the staging/pre-prod host, an adjacent class) and work them "
    "until suspicion is truly exhausted. When stuck, research disclosed reports / CVE PoCs for a fresh "
    "angle before concluding.\n"
    "- PERSIST what you discover into the pipeline: new subdomains/endpoints + worked-knowledge via "
    "`recon note <host> \"...\"`; a real confirmed primitive rides the normal mint -> verify path."
)

# WSTG category -> KB methodology docs to read for exhaustive, class-specific testing.
_WSTG_KB = {
    "INFO": ["class-unauth-hunting.md"],
    "CONF": ["class-bucket-exposure.md", "class-takeover.md", "class-cache-deception.md", "class-403-bypass.md"],
    "IDNT": ["class-idor.md"], "ATHN": ["class-jwt-attacks.md"], "ATHZ": ["class-idor.md"],
    "SESS": ["class-jwt-attacks.md"],
    "INPV": ["class-xss.md", "class-sqli.md", "class-ssrf.md", "class-domxss.md"],
    "ERRH": ["class-unauth-hunting.md"], "CRYP": ["class-jwt-attacks.md"],
    "BUSL": ["class-race-conditions.md", "class-idor.md"],
    "CLNT": ["class-domxss.md", "class-xss.md", "class-clientside-secrets.md", "class-firebase.md"],
    "APIT": ["class-graphql.md", "class-idor.md", "class-ssrf.md"],
}

# Machine-readable trailer the Auto-drive UI parses to auto-mark the step + write its outcome note.
_STEP_RESULT = (
    "FINALLY, end your reply with EXACTLY ONE machine-readable status line, on its own line, no markdown "
    "or backticks:\n"
    "STEP-RESULT: <done|finding|na|manual> — <one concise sentence: what you drove + the outcome>\n"
    "Use `finding` ONLY if you directly observed/confirmed a real exploitable primitive this step; `na` "
    "if the test does not apply to these assets; `manual` if it needs an action you cannot safely "
    "complete now (owned-account signup, an operator-run target tool, or authed confirmation); otherwise "
    "`done`."
)

# The STEP-RESULT line above tells the auto-driver what happened; this card is what makes the step
# a DECISION SURFACE instead of a wall of prose to read. Three questions, answered with real values
# the UI can act on: what did we FIND, what do we RECORD, what do we PURSUE next.
_STEP_CARD = (
    "AFTER the STEP-RESULT line, append EXACTLY ONE fenced ```json block — the step card. It is what "
    "the operator acts on, so every value must be concrete and copied from THIS engagement:\n"
    "{\n"
    '  "found":  [{"what":"<the specific thing observed>", "evidence":"<real host/url/param/response>",\n'
    '              "why":"<why it matters for THIS test>"}],\n'
    '  "record": {"status":"done|finding|na|manual",\n'
    '             "note":"<1-3 plain sentences of worked-knowledge: what was tested, what was found or\n'
    '                      cleared and WHY, what is left — this is persisted verbatim>"},\n'
    '  "pursue": [{"label":"<the next move, imperative>", "why":"<what it would prove>",\n'
    '              "priority":"high|medium|low", "action":"<lane id or null>",\n'
    '              "target":"<bare host or null>", "cmd":"<exact command when the operator runs it>"}]\n'
    "}\n"
    "RULES:\n"
    "- `found` carries EVIDENCE, not narration. Nothing observed ⇒ empty list, and say so in the note.\n"
    "- `record.note` is written to the checklist verbatim — no markdown, no preamble, never overclaim. "
    "A clean pass is worked-knowledge too: say what was cleared and why, so it is not re-walked.\n"
    "- `pursue` is ranked, most valuable first, and each entry must be a REAL next move — the authed "
    "2-owned-account swap, a specific param to confirm, a host to crawl. No filler.\n"
    "- Set `action` ONLY to a lane that genuinely applies, from exactly: crawl-host, confirm-xss, "
    "confirm-sqli, graphql, buckets, wcd, kr, blindxss, permute, uncover, verify, scope, tech, kev — "
    "and set `target` to the bare host it runs against. Otherwise `action` is null and `cmd` carries "
    "the exact thing for the operator to run or do."
)


def _program_context(ws: dict[str, Any], hosts: list[dict[str, Any]],
                     endpoints: list[str]) -> str:
    name = ws.get("name") or ws.get("key")
    lines = [f"PROGRAM: {name}  (platform: {ws.get('platform') or '?'})"]
    if hosts:
        lines.append("In-scope + paying hosts (sample, host — tech — top classes):")
        for h in hosts[:20]:
            tech = ", ".join((h.get("tech") or [])[:4]) if isinstance(h.get("tech"), list) else ""
            cls = ", ".join((h.get("triage_classes") or [])[:4]) if isinstance(h.get("triage_classes"), list) else ""
            lines.append(f"  - {h.get('host')}  [{tech or 'tech?'}]  {('classes: ' + cls) if cls else ''}".rstrip())
    else:
        lines.append("(no ES hosts joined yet for this program)")
    if endpoints:
        lines.append("Sample discovered endpoints (from jsintel/ES):")
        for e in endpoints[:25]:
            lines.append(f"  - {e}")
    return "\n".join(lines)


def build_guide_prompt(ws: dict[str, Any], phase: str, ident: str, host: str,
                       hosts: list[dict[str, Any]], endpoints: list[str]) -> str:
    """Build the grounded co-pilot prompt for the Guided walkthrough (one step)."""
    ctx = _program_context(ws, hosts, endpoints)
    focus_host = f"\nOperator has selected host to focus on: {host}" if host else ""
    if phase == "wstg":
        ref = wstg_reference().get(ident, {})
        cat = ident.split("-")[1] if ident.count("-") >= 2 else ""
        kb = _WSTG_KB.get(cat, [])
        kb_line = ("KB METHODOLOGY to READ (Read tool) + fully apply for this class: "
                   + ", ".join(f"docs/knowledge/{d}" for d in kb) + "\n\n") if kb else ""
        head = (f"You are the operator's co-pilot DRIVING OWASP WSTG test {ident} — "
                f"\"{ref.get('name', ident)}\" ({ref.get('cat_name', '')}) — on THIS engagement. "
                f"Actively work the test end-to-end with the tools below; do not merely describe it.")
        body = (
            f"Test objective: {ref.get('objective', '')}\n"
            f"General approach: {ref.get('how_to', '')}\n"
            f"Reference tools: {ref.get('tools', '')}\n\n"
            "DRIVE this test on THIS engagement, as a tight sequence — narrate each move briefly:\n"
            "1. Pin the exact surface: name the real in-scope+paying hosts/endpoints/params above this "
            "test applies to. If you need to see the live app, DRIVE Brave to navigate and read the "
            "DOM/JS/network.\n"
            "2. Execute it with the right primitive: use the `burp` MCP (Repeater to replay/modify the "
            "actual request, Intruder for controlled fuzzing, Autorize for cross-role/cross-tenant "
            "IDOR/BOLA) and/or the `brave` MCP for browser-driven & client-side checks; or hand the "
            "exact recon-ctl command (e.g. `recon-params confirm xss <host>`) when a pipeline lane is "
            "the right SAFE confirm primitive. Read-only by default.\n"
            "3. If it needs auth/accounts, follow the ACCOUNTS rule below (prompt + drive signup), then "
            "resume with the 2-owned-account swap.\n"
            "4. Adjudicate: CONFIRMED primitive (state the minimal reproducible PoC), LEAD (name the "
            "operator's authed step to close it), N-A, or clean pass.\n"
            "5. Call out this class's common false-positive / N-A pitfalls so nothing is overclaimed.\n"
            "Be specific to the program context above — no generic WSTG boilerplate.\n\n"
            f"{kb_line}{_ACCOUNTS}\n\n{_DRIVE_TOOLS}")
    else:
        g = STRIDE_GUIDE.get((ident or "").upper()[:1], {})
        head = (f"You are the operator's co-pilot DRIVING STRIDE threat modelling — category "
                f"{ident.upper()[:1]} ({g.get('name', '')}) — for THIS engagement.")
        body = (
            f"Category focus: {g.get('prompt', '')}\n\n"
            "Enumerate CONCRETE threats in this category over the app's actual assets, roles and "
            "data-flows above. For each threat: name the specific host/endpoint/flow, map it to the "
            "WSTG test(s) that confirm it, and state whether it's unauth-testable or needs two owned "
            "accounts. Where a threat is quickly checkable UNAUTH, DRIVE Brave/`burp` to sanity-check "
            "it now (read-only, in-scope+paying). Rank by likely payout/impact and end with the 2-3 to "
            "test first.\n\n"
            f"{_ACCOUNTS}\n\n{_DRIVE_TOOLS}")
    return (f"{head}\n\n{ctx}{focus_host}\n\n{body}\n\n{_EXHAUSTIVE}\n\n{_DOCTRINE}\n\n"
            f"{_STEP_RESULT}\n\n{_STEP_CARD}")


# --- Auto-note prompts (summarize where testing stands into a worked-knowledge note) ----------
# Reasoning over the provided context only (no target packets, no tool-driving) — off-target by
# construction, so the autonote endpoints need no VPN gate. The frontend confirms/edits the draft
# before it is persisted.
_NOTE_STYLE = (
    "Write the note as the operator's worked-knowledge: 1-4 tight sentences, PLAIN TEXT (no markdown "
    "headings, no bullet list, no preamble, no sign-off). Capture what was TESTED, what was FOUND "
    "(confirmed findings or leads, with the class), what was CLEARED and WHY (FP / by-design / "
    "out-of-scope / version-safe), and what is LEFT to test. Be specific to the real hosts/endpoints/"
    "classes below; never overclaim. If little was done, say exactly that. Reply with ONLY the note text."
)


def build_host_note_prompt(host: str, host_doc: dict[str, Any] | None,
                           findings: list[dict[str, Any]], notes: list[dict[str, Any]]) -> str:
    """Grounded prompt asking Claude to draft a concise HOST note (where testing of `host` stands)."""
    d = host_doc or {}
    tech = ", ".join((d.get("tech") or [])[:6]) if isinstance(d.get("tech"), list) else ""
    cls = ", ".join((d.get("triage_classes") or [])[:6]) if isinstance(d.get("triage_classes"), list) else ""
    lines = [f"HOST: {host}"]
    if tech:
        lines.append(f"  tech: {tech}")
    if cls:
        lines.append(f"  candidate classes: {cls}")
    if d.get("triage_program"):
        lines.append(f"  program: {d.get('triage_program')}")
    if findings:
        lines.append("Findings recorded on this host (state — class — verdict — url):")
        for f in findings[:15]:
            lines.append(f"  - {f.get('state')} — {f.get('vuln_class') or '?'} — "
                         f"{f.get('ai_verdict') or '?'}  {f.get('url') or ''}".rstrip())
    else:
        lines.append("No findings recorded on this host.")
    if notes:
        lines.append("Existing host notes (synthesize + add what's new; don't just repeat):")
        for n in notes[:12]:
            txt = n.get("note") if isinstance(n, dict) else str(n)
            if txt:
                lines.append(f"  - {txt}")
    ctx = "\n".join(lines)
    head = ("You are the operator's co-pilot writing a concise HOST NOTE that captures where testing of "
            f"{host} stands — so re-visiting it later starts informed, not from scratch.")
    return f"{head}\n\n{ctx}\n\n{_DOCTRINE}\n\n{_NOTE_STYLE}"


def build_program_note_prompt(ws: dict[str, Any], hosts: list[dict[str, Any]],
                              endpoints: list[str], findings: list[dict[str, Any]]) -> str:
    """Grounded prompt asking Claude to draft a concise ENGAGEMENT-SUMMARY note for the program."""
    ctx = _program_context(ws, hosts, endpoints)
    wstg = ws.get("wstg") or []
    worked = sum(1 for w in wstg if (w.get("status") or "todo") in ("done", "finding", "na"))
    stride = ws.get("stride") or {}
    stride_done = sum(1 for k in ("S", "T", "R", "I", "D", "E") if (stride.get(k) or []))
    extra = [f"Coverage: WSTG {worked}/{len(wstg)} worked; STRIDE {stride_done}/6 categories modeled."]
    if findings:
        extra.append("Findings on this program (state — class — verdict — host):")
        for f in findings[:20]:
            extra.append(f"  - {f.get('state')} — {f.get('vuln_class') or '?'} — "
                         f"{f.get('ai_verdict') or '?'} — {f.get('host')}")
    tail = "\n".join(extra)
    head = ("You are the operator's co-pilot writing a concise ENGAGEMENT-SUMMARY note for this program "
            "— where the testing stands overall and what to pick up next session.")
    return f"{head}\n\n{ctx}\n\n{tail}\n\n{_DOCTRINE}\n\n{_NOTE_STYLE}"


# --- generated model: STRIDE + WSTG derived from the REAL surface -----------
# A seeded workspace is a TEMPLATE, not an engagement: _seed_wstg() stamps the same ~120
# item checklist onto every program and `stride` starts as six empty buckets. The evidence
# we already hold (in-scope+paying ES hosts, tech fingerprints, triage classes, jsintel
# endpoints, worked-knowledge) only ever reached the per-step guide prompt — never the model
# itself. These build the model FROM that evidence, so the threat model is specific to THIS
# app and the WSTG walk is aimed by it instead of walked alphabetically.

MODEL_STATUS = {"open", "testing", "confirmed", "killed"}

_MODEL_CONTRACT = (
    "OUTPUT CONTRACT — reply with ONE fenced ```json block and nothing else after it:\n"
    "{\n"
    '  "stride": [\n'
    '    {"cat":"S|T|R|I|D|E", "threat":"<specific to THIS app, names the real asset/role/flow>",\n'
    '     "rationale":"<the evidence that makes it credible>", "hosts":["<host from the surface>"],\n'
    '     "severity":"high|medium|low"}\n'
    "  ],\n"
    '  "wstg": [\n'
    '    {"id":"WSTG-XXXX-NN", "relevance":"high|medium|low|na",\n'
    '     "reason":"<why it matters here, or why it cannot apply>",\n'
    '     "targets":["<host/endpoint/param this test should be run against>"]}\n'
    "  ]\n"
    "}\n"
    "RULES:\n"
    "- Ground EVERY stride threat in the surface above. No generic textbook threats — if the "
    "evidence does not support it, leave it out. Prefer few, sharp, testable threats over many vague ones.\n"
    "- `hosts` and `targets` must be real values copied from the surface, never invented.\n"
    "- relevance=na REQUIRES a concrete reason the test cannot apply to this stack (e.g. no SOAP "
    "service, no file upload surface). 'Not interesting' is NOT a reason — that is a judgement the "
    "operator makes after testing, and marking it na would erase work that was never done.\n"
    "- Rank by what actually PAYS and is DUP-RESISTANT (the motto: be unique or get duplicated). "
    "A test that everyone runs against a product-class endpoint is low relevance even when applicable; "
    "per-app logic, object references, and auth boundaries are high.\n"
    "- Only emit WSTG ids that exist in the checklist. Omit an id entirely if you have nothing to say."
)


def build_model_prompt(ws: dict[str, Any], hosts: list[dict[str, Any]], endpoints: list[str],
                       killed: dict[str, set[str]] | None = None) -> str:
    """Grounded prompt asking Claude to DERIVE the STRIDE threat model + WSTG relevance
    ranking from this program's actual surface (not the generic seed)."""
    ctx = _program_context(ws, hosts, endpoints)
    lines: list[str] = []
    wstg = ws.get("wstg") or []
    worked = [w for w in wstg if (w.get("status") or "todo") != "todo"]
    if worked:
        lines.append("ALREADY WORKED — do not re-rank or overwrite these, they are settled:")
        for w in worked[:25]:
            lines.append(f"  - {w.get('id')} [{w.get('status')}] {w.get('name')}"
                         + (f" — {w.get('note')}" if w.get("note") else ""))
    existing = ws.get("stride") or {}
    have = [f"{c}:{len(existing.get(c) or [])}" for c in ("S", "T", "R", "I", "D", "E")]
    lines.append(f"Existing STRIDE threats per category: {', '.join(have)} "
                 "(add what the evidence supports; do not duplicate an existing threat).")
    if killed:
        rows = [f"  - {h}: {', '.join(sorted(c)[:6])}" for h, c in list(killed.items())[:15] if c]
        if rows:
            lines.append("WORKED-KNOWLEDGE — classes already KILLED on these hosts "
                         "(do not resurface an angle a note already killed):")
            lines.extend(rows)
    ids = ", ".join(sorted(wstg_reference().keys()))
    lines.append(f"VALID WSTG IDS (use these exactly): {ids}")
    tail = "\n".join(lines)
    head = ("You are threat-modelling a bug-bounty program for its dedicated workspace. Derive the "
            "STRIDE model from the REAL attack surface below — this app's actual assets, roles and "
            "data flows — then use that model to rank which WSTG tests are worth the operator's "
            "evening and which cannot apply. The output aims the engagement; be specific or be silent.")
    return f"{head}\n\n{ctx}\n\n{tail}\n\n{_DOCTRINE}\n\n{_MODEL_CONTRACT}"


def parse_model(text: str) -> dict[str, Any]:
    """Extract the generated model from a Claude reply. Tolerant of prose around the JSON;
    raises ValueError when nothing parseable is present (never returns a partial model)."""
    if not text:
        raise ValueError("empty response")
    blob = None
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        blob = fence.group(1)
    else:
        i, j = text.find("{"), text.rfind("}")
        if i != -1 and j > i:
            blob = text[i:j + 1]
    if not blob:
        raise ValueError("no JSON object in response")
    try:
        data = json.loads(blob)
    except Exception as e:
        raise ValueError(f"unparseable JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("model must be a JSON object")
    out: dict[str, Any] = {"stride": [], "wstg": []}
    for row in (data.get("stride") or []):
        if not isinstance(row, dict):
            continue
        cat = str(row.get("cat") or "").strip().upper()[:1]
        threat = str(row.get("threat") or "").strip()
        if cat not in _STRIDE_CATS or not threat:
            continue
        out["stride"].append({
            "cat": cat, "threat": threat[:500],
            "rationale": str(row.get("rationale") or "")[:2000],
            "hosts": [str(h)[:255] for h in (row.get("hosts") or [])][:50],
            "severity": str(row.get("severity") or "").strip().lower()[:10],
        })
    ref = wstg_reference()
    for row in (data.get("wstg") or []):
        if not isinstance(row, dict):
            continue
        wid = str(row.get("id") or "").strip().upper()
        rel = str(row.get("relevance") or "").strip().lower()
        if wid not in ref or rel not in ("high", "medium", "low", "na"):
            continue
        out["wstg"].append({
            "id": wid, "relevance": rel,
            "reason": str(row.get("reason") or "")[:2000],
            "targets": [str(t)[:255] for t in (row.get("targets") or [])][:25],
        })
    if not out["stride"] and not out["wstg"]:
        raise ValueError("model contained no usable stride or wstg rows")
    return out


# --- follow-up queue --------------------------------------------------------
# A step surfaces leads worth pursuing, but chasing one immediately is how a systematic walk turns
# into a rabbit hole and coverage silently stops. PICKING a lead parks it here — bound to the step
# that produced it — so the STRIDE/WSTG walk continues and nothing is lost. The queue is the
# worked-vs-left record for everything the walk turned up but did not do yet.

FOLLOWUP_STATUS = {"open", "done", "dropped"}


def add_followup(key: str, wid: str | None, row: dict[str, Any]) -> dict[str, Any]:
    """Pick a pursue-item into the queue. Deduped on (origin, label) so re-running a step and
    picking the same lead twice does not stack duplicates."""
    ws = load(key)
    if not ws:
        raise KeyError(key)
    label = str(row.get("label") or "").strip()
    if not label:
        raise ValueError("label required")
    origin = (wid or "").strip().upper() or "stride"
    q = ws.setdefault("followups", [])
    if any(f.get("origin") == origin and (f.get("label") or "").strip().lower() == label.lower()
           and f.get("status") == "open" for f in q):
        return {**save(ws), "duplicate": True}
    pri = str(row.get("priority") or "medium").strip().lower()
    act = str(row.get("action") or "").strip()
    tgt = _clean_target(str(row.get("target") or ""))
    ts = _now()
    q.append({
        "id": f"F{len(q) + 1}", "origin": origin, "label": label[:200],
        "why": str(row.get("why") or "")[:300],
        "priority": pri if pri in ("high", "medium", "low") else "medium",
        "action": act if (act in {r[1] for r in _ACTION_MAP} and tgt) else None,
        "target": tgt, "cmd": str(row.get("cmd") or "")[:400],
        "status": "open", "created_at": ts,
    })
    ws["history"].append({"ts": ts, "event": f"picked follow-up from {origin}: {label[:60]}"})
    return {**save(ws), "duplicate": False}


def set_followup(key: str, fid: str, status: str) -> dict[str, Any]:
    ws = load(key)
    if not ws:
        raise KeyError(key)
    if status not in FOLLOWUP_STATUS:
        raise ValueError(f"invalid status: {status} (allowed: {sorted(FOLLOWUP_STATUS)})")
    row = next((f for f in ws.get("followups") or [] if f.get("id") == fid), None)
    if not row:
        raise KeyError(fid)
    row["status"] = status
    ts = _now()
    row["updated_at"] = ts
    ws["history"].append({"ts": ts, "event": f"follow-up {fid} → {status}"})
    return save(ws)


def parse_step_card(text: str) -> dict[str, Any] | None:
    """Extract the step card from a guide reply. Returns None (never raises) when the reply has
    no card — an older/prose-only answer must still render, just without the action surface."""
    if not text:
        return None
    blob = None
    for m in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S):
        blob = m.group(1)                      # last fenced block wins (the card is appended last)
    if not blob:
        return None
    try:
        data = json.loads(blob)
    except Exception:
        return None
    if not isinstance(data, dict) or not any(k in data for k in ("found", "record", "pursue")):
        return None
    valid_actions = {r[1] for r in _ACTION_MAP}
    found: list[dict[str, str]] = []
    for row in (data.get("found") or []):
        if not isinstance(row, dict):
            continue
        what = str(row.get("what") or "").strip()
        if not what:
            continue
        found.append({"what": what[:300],
                      "evidence": str(row.get("evidence") or "")[:500],
                      "why": str(row.get("why") or "")[:300]})
    rec = data.get("record") if isinstance(data.get("record"), dict) else {}
    status = str(rec.get("status") or "").strip().lower()
    record = {"status": status if status in WSTG_STATUS or status == "manual" else "",
              "note": str(rec.get("note") or "").strip()[:2000]}
    pursue: list[dict[str, Any]] = []
    for row in (data.get("pursue") or []):
        if not isinstance(row, dict):
            continue
        label = str(row.get("label") or "").strip()
        if not label:
            continue
        act = str(row.get("action") or "").strip()
        tgt = _clean_target(str(row.get("target") or ""))
        pri = str(row.get("priority") or "").strip().lower()
        pursue.append({
            "label": label[:200], "why": str(row.get("why") or "")[:300],
            "priority": pri if pri in ("high", "medium", "low") else "medium",
            # only a lane that exists AND has a usable host survives as a one-click run
            "action": act if (act in valid_actions and tgt) else None,
            "target": tgt, "cmd": str(row.get("cmd") or "")[:400],
        })
    order = {"high": 0, "medium": 1, "low": 2}
    pursue.sort(key=lambda p: order.get(p["priority"], 1))
    if not found and not pursue and not record["note"]:
        return None
    return {"found": found[:12], "record": record, "pursue": pursue[:8]}


def apply_model(key: str, model: dict[str, Any]) -> dict[str, Any]:
    """Persist a generated model onto the workspace.

    Additive and non-destructive by construction: an item the operator has already moved off
    `todo` is NEVER touched (a generated na must not erase work that was actually done), and a
    generated na only lands on a `todo` item when it carries a reason. Relevance/targets are
    stored alongside the item so the checklist can rank by them without losing the WSTG ids."""
    ws = load(key)
    if not ws:
        raise KeyError(key)
    ts = _now()
    added_s = skipped_s = 0
    for row in (model.get("stride") or []):
        bucket = ws["stride"].setdefault(row["cat"], [])
        if any((t.get("threat") or "").strip().lower() == row["threat"].strip().lower()
               for t in bucket):
            skipped_s += 1
            continue
        bucket.append({
            "id": f"{row['cat']}{len(bucket) + 1}", "threat": row["threat"],
            "note": row.get("rationale") or "", "status": "open",
            "hosts": row.get("hosts") or [], "severity": row.get("severity") or "",
            "source": "generated", "created_at": ts,
        })
        added_s += 1
    ranked = na_set = 0
    by_id = {w["id"]: w for w in (ws.get("wstg") or [])}
    for row in (model.get("wstg") or []):
        item = by_id.get(row["id"])
        if not item:
            continue
        settled = (item.get("status") or "todo") != "todo"
        # A settled item keeps its verdict AND its ranking: recording relevance=na on a test the
        # operator already turned into a finding would let a relevance filter hide real work.
        if not (settled and row["relevance"] == "na"):
            item["relevance"] = row["relevance"]
        item["targets"] = row.get("targets") or []
        item["rationale"] = row.get("reason") or ""
        ranked += 1
        if settled:
            continue          # settled work is never re-decided by a generation pass
        if row["relevance"] == "na" and row.get("reason"):
            item["status"] = "na"
            if not item.get("note"):
                item["note"] = f"[generated] {row['reason']}"[:2000]
            item["updated_at"] = ts
            na_set += 1
    ws["model_generated_at"] = ts
    ws["history"].append({
        "ts": ts,
        "event": (f"model generated from surface: +{added_s} STRIDE ({skipped_s} dup), "
                  f"{ranked} WSTG ranked, {na_set} auto-na"),
    })
    saved = save(ws)
    return {**saved, "applied": {"stride_added": added_s, "stride_duplicate": skipped_s,
                                 "wstg_ranked": ranked, "wstg_na": na_set}}


# --- runnable actions per WSTG test ----------------------------------------
# _WSTG_REF already names the lane for every test ("recon-params crawl-host", "recon-graphql",
# …) but only as prose in the guide. This turns that prose into things the operator can RUN
# from the row. The argv is ALWAYS rebuilt server-side from this table — the frontend posts an
# action id, never a command — so a workspace row can never become an arbitrary-exec sink.
# Only subcommands that exist in recon_ctl.sh are listed; a lane without one simply has no button.

# token in _WSTG_REF.tools -> (action id, label, argv template, needs a host)
_ACTION_MAP: list[tuple[str, str, str, list[str], bool]] = [
    ("recon-params crawl-host", "crawl-host", "Crawl host (katana+gau→gf→catalog)",
     ["params", "crawl-host", "{host}"], True),
    ("recon-params confirm", "confirm-xss", "Confirm XSS (dalfox — must EXECUTE)",
     ["params", "confirm", "xss", "{host}"], True),
    ("recon-confirm", "confirm-sqli", "Confirm SQLi (' vs '' differential)",
     ["params", "confirm", "sqli", "{host}"], True),
    ("recon-graphql", "graphql", "GraphQL schema → worklist",
     ["graphql", "{host}"], True),
    ("recon-buckets", "buckets", "Bucket exposure (read-only ACL grading)",
     ["buckets", "{host}"], True),
    ("recon-wcd", "wcd", "Web-cache deception probe (cache-buster safe)",
     ["wcd", "{host}"], True),
    ("recon-kr", "kr", "API-route discovery (kiterunner)",
     ["kr", "{host}"], True),
    ("recon-blindxss", "blindxss", "Blind/stored-XSS plant",
     ["blindxss", "{host}"], True),
    ("recon-permute", "permute", "Permutation-DNS (public resolvers)",
     ["permute"], False),
    ("recon-uncover", "uncover", "Surface expansion (Shodan/Censys, budgeted)",
     ["uncover"], False),
    ("recon-verify", "verify", "Claude verify (multimodal + safe probes)",
     ["verify", "{host}"], True),
    ("recon-scope", "scope", "Scope + per-asset pays check",
     ["scope", "{host}"], True),
    ("recon-tech", "tech", "Tech fingerprint rollup", ["tech"], False),
    ("recon-kev", "kev", "KEV/CVE matches", ["kev"], False),
]

_BAD_HOST_CHARS = set(" ;|&$`\n\t'\"\\")


def _clean_target(t: str) -> str | None:
    """A target is only usable as an argv token if it is a bare hostname."""
    t = (t or "").strip()
    if t.startswith(("http://", "https://")):
        t = t.split("//", 1)[1]
    t = t.split("/", 1)[0].split("?", 1)[0]
    if not t or len(t) > 253 or any(c in _BAD_HOST_CHARS for c in t):
        return None
    return t if re.fullmatch(r"[A-Za-z0-9._:-]+", t) else None


def wstg_actions(wid: str, item: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Runnable lanes for a WSTG test, with the item's generated targets pre-bound.

    Derived from the test's own `tools` grounding, so the buttons track the reference rather
    than a second hand-maintained list. Host-scoped lanes appear once per distinct target."""
    ref = wstg_reference().get(wid)
    if not ref:
        return []
    tools = (ref.get("tools") or "").lower()
    targets = [c for c in (_clean_target(t) for t in ((item or {}).get("targets") or [])) if c]
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for token, aid, label, tmpl, needs_host in _ACTION_MAP:
        if token.lower() not in tools:
            continue
        if needs_host:
            for host in targets[:6]:
                k = f"{aid}:{host}"
                if k in seen:
                    continue
                seen.add(k)
                out.append({"id": aid, "label": label, "target": host,
                            "cmd": " ".join(t.replace("{host}", host) for t in tmpl)})
        else:
            if aid in seen:
                continue
            seen.add(aid)
            out.append({"id": aid, "label": label, "target": None, "cmd": " ".join(tmpl)})
    return out


def resolve_action(wid: str, action_id: str, target: str | None) -> list[str]:
    """Rebuild the argv for an action server-side. Raises ValueError unless the action is
    genuinely offered by this test (never trusts a client-supplied command)."""
    ref = wstg_reference().get(wid)
    if not ref:
        raise ValueError(f"unknown WSTG id: {wid}")
    tools = (ref.get("tools") or "").lower()
    row = next((r for r in _ACTION_MAP if r[1] == action_id and r[0].lower() in tools), None)
    if not row:
        raise ValueError(f"action '{action_id}' is not offered by {wid}")
    _, _, _, tmpl, needs_host = row
    if not needs_host:
        return list(tmpl)
    host = _clean_target(target or "")
    if not host:
        raise ValueError("this action needs a valid host target")
    return [t.replace("{host}", host) for t in tmpl]
