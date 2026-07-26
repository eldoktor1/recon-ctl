#!/usr/bin/env python3
# =============================================================================
# recon_account.py — semi-automated test-account PROVISIONER for the hunt.
#
# WHY: manual account creation is the biggest friction in authed research. This
# AUTOMATES the tedious parts — strong password generation, email-alias selection,
# signup-form field-filling, and credential recording — so the only thing left for
# the operator is the human-verification gate (CAPTCHA) + the final "Create" click.
#
# BOUNDARY (by design): this is a tool the OPERATOR runs. The operator's execution
# fills the fields and the operator performs the CAPTCHA + credential-submit. Claude
# AUTHORS this tool; it never interactively enters credentials itself. (memory:
# feedback_account_passwords / feedback_hunt_authed_docs_and_signup.)
#
# WHAT it does, per `create`:
#   1. resolve the platform EMAIL ALIAS (bugcrowd/hackerone/yeswehack/gmail; +tag for A/B)
#   2. GENERATE a strong unique password (secrets, 22 chars, all classes)
#   3. open the signup URL in a HEADFUL browser (WSLg) and AUTO-FILL email + password
#      (input[type=email] / [type=password]; profile selectors override auto-detect)
#   4. PAUSE — operator solves CAPTCHA, fills any extra fields, clicks Create
#   5. RECORD the credential set to the LOCAL creds store (never mirrored)
#   6. remind: click the email verification link manually (verify = manual by choice)
#
# Config (LOCAL, never committed):
#   ~/recon/state/private_programs/email_aliases.json   platform -> alias patterns
#   ~/recon/state/private_programs/signup_profiles.json  optional per-target field maps
#   ~/recon/state/private_programs/account_creds.md      the credential store (chmod 600)
#
# Usage:
#   recon-account create <name> --url <signup_url> --platform <bugcrowd|hackerone|yeswehack|gmail> [--label a]
#   recon-account create <name>                # uses a saved signup_profiles.json entry
#   recon-account list                         # show stored accounts (emails/usernames, NOT passwords)
#   recon-account create ... --dry-run         # resolve alias + gen password + show plan, NO browser
# =============================================================================
import os, sys, json, argparse, secrets, string, datetime, re

HOME=os.path.expanduser("~")
PRIV=os.path.join(HOME,"recon/state/private_programs")
ALIASES_F=os.path.join(PRIV,"email_aliases.json")
PROFILES_F=os.path.join(PRIV,"signup_profiles.json")
CREDS_F=os.path.join(PRIV,"account_creds.md")

# Built-in PLACEHOLDER alias patterns. Put YOUR real emails in
#   ~/recon/state/private_programs/email_aliases.json
# (same shape as below — kept OUT of the repo); it overrides these at runtime. The
# platform "ninja" domains are each platform's private email-relay for signups.
DEFAULT_ALIASES={
 "bugcrowd":{"base":"you@bugcrowdninja.com","plus":"you+{tag}@bugcrowdninja.com"},
 "hackerone":{"base":"you@wearehackerone.com","plus":"you+{tag}@wearehackerone.com"},
 "yeswehack":{"base":"you@yeswehack.ninja","plus":"you+{tag}@yeswehack.ninja"},
 "intigriti":{"base":"you@example.com","plus":"you+{tag}@example.com"},
 "gmail":{"base":"you@example.com","plus":"you+{tag}@example.com"},
 "default":{"base":"you@example.com","plus":"you+{tag}@example.com"},
}
PW_SYMBOLS="!@#$%^&*-_=+"

def load_json(path, fallback):
    try:
        return json.load(open(path))
    except Exception:
        return fallback

def gen_password(n=22):
    alph=string.ascii_letters+string.digits+PW_SYMBOLS
    while True:
        pw="".join(secrets.choice(alph) for _ in range(n))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in PW_SYMBOLS for c in pw)):
            return pw

def resolve_email(platform, label):
    aliases=load_json(ALIASES_F, DEFAULT_ALIASES)
    spec=aliases.get((platform or "default").lower()) or aliases.get("default") or DEFAULT_ALIASES["default"]
    if label:
        tag=re.sub(r'[^a-z0-9]','',label.lower()) or "x"
        return spec.get("plus","{tag}").replace("{tag}",tag)
    return spec.get("base")

def store_cred(rec):
    os.makedirs(PRIV, exist_ok=True)
    new=not os.path.exists(CREDS_F)
    with open(CREDS_F,"a") as f:
        if new:
            f.write("# Account credentials store (LOCAL ONLY — never commit/mirror)\n"
                    "# Test accounts created for authorized bug-bounty own-account testing.\n\n")
        f.write(f"## {rec['name']}"+(f" ({rec['label']})" if rec.get('label') else "")+f" — {rec['created']}\n")
        for k in ("site","platform","email","username","password","status","note"):
            if rec.get(k): f.write(f"- {k}: {rec[k]}\n")
        f.write("\n")
    try: os.chmod(CREDS_F,0o600)
    except Exception: pass

def cmd_list():
    if not os.path.exists(CREDS_F):
        print("no accounts stored yet."); return 0
    for line in open(CREDS_F):
        if line.startswith("## ") or line.startswith("- site:") or line.startswith("- email:") \
           or line.startswith("- username:") or line.startswith("- status:"):
            print(line.rstrip())
    print(f"\n(passwords are in {CREDS_F} — chmod 600, local only)")
    return 0

def fill_signup(url, email, password, profile, keep_open):
    """Headful Selenium: open signup, auto-fill (or profile-driven) email+password, PAUSE for operator."""
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

    chromedriver=next((p for p in ("/usr/bin/chromedriver",) if os.path.exists(p)), "chromedriver")
    binloc=next((p for p in ("/usr/bin/google-chrome","/usr/bin/chromium","/usr/bin/google-chrome-stable") if os.path.exists(p)), None)
    opts=Options()
    if binloc: opts.binary_location=binloc
    opts.add_argument("--no-first-run"); opts.add_argument("--no-default-browser-check")
    opts.add_argument(f"--user-data-dir=/tmp/recon_acct_{secrets.token_hex(4)}")  # clean per-account profile
    opts.add_argument("--window-size=1280,900")
    opts.add_experimental_option("excludeSwitches",["enable-automation"])
    d=webdriver.Chrome(service=Service(chromedriver), options=opts)
    try:
        d.get(url)
        WebDriverWait(d,20).until(EC.presence_of_element_located((By.TAG_NAME,"body")))
        filled=[]
        def fill(el,val,what):
            try:
                el.clear()
            except Exception: pass
            el.send_keys(val); filled.append(what)
        if profile and profile.get("fields"):
            for fld in profile["fields"]:
                by=getattr(By, fld.get("by","CSS_SELECTOR").upper(), By.CSS_SELECTOR)
                src=fld.get("src"); val=email if src=="email" else password if src=="password" else fld.get("val","")
                try:
                    el=WebDriverWait(d,10).until(EC.presence_of_element_located((by,fld["sel"])))
                    fill(el,val,f"{src or 'literal'}:{fld['sel']}")
                except Exception as e:
                    print(f"  [profile] field {fld.get('sel')} not found ({e.__class__.__name__})")
        else:
            # auto-detect: first email-ish field + all password fields (covers confirm-password)
            em=d.find_elements(By.CSS_SELECTOR,"input[type=email], input[name*=email i], input[id*=email i]")
            if em: fill(em[0],email,"email(auto)")
            pw=d.find_elements(By.CSS_SELECTOR,"input[type=password]")
            for i,e in enumerate(pw[:2]): fill(e,password,f"password(auto#{i+1})")
        print(f"  auto-filled: {', '.join(filled) if filled else 'NOTHING (check selectors / fill manually)'}")
        print("\n  >>> NOW IN THE BROWSER: solve any CAPTCHA, fill any extra fields (username/name),")
        print("      then click CREATE/SIGN UP yourself. (Claude does not click the credential submit.)")
        input("  Press Enter here AFTER the account is created... ")
        if keep_open:
            input("  Browser kept open. Press Enter again to close it... ")
    finally:
        try: d.quit()
        except Exception: pass

def cmd_create(a):
    profiles=load_json(PROFILES_F,{})
    profile=profiles.get(a.name)
    url=a.url or (profile or {}).get("signup_url")
    platform=a.platform or (profile or {}).get("platform") or "default"
    if not url:
        print(f"no signup URL — pass --url <signup_url> or add '{a.name}' to {PROFILES_F}",file=sys.stderr); return 2
    email=resolve_email(platform,a.label)
    password=gen_password()
    host=re.sub(r'^https?://','',url).split('/')[0]
    print(f"[recon-account] create '{a.name}'{(' ['+a.label+']') if a.label else ''}")
    print(f"  site={host}  platform={platform}")
    print(f"  email={email}")
    print(f"  password={password}  (generated, will be stored locally)")
    if a.dry_run:
        print("  --dry-run: not opening a browser, not storing."); return 0
    try:
        fill_signup(url,email,password,profile,a.keep_open)
    except Exception as e:
        print(f"  browser step failed: {e}",file=sys.stderr)
        print("  (creds still recorded so you can finish the signup manually with them.)")
    store_cred({"name":a.name,"label":a.label,"site":host,"platform":platform,"email":email,
                "username":a.username or "","password":password,
                "status":"created (pending manual email verification — click the link in your inbox)",
                "created":datetime.date.today().isoformat()})
    print(f"  stored → {CREDS_F}  (chmod 600, local only)")
    print(f"  NEXT (manual): open your inbox for {email}, click the verification link.")
    return 0

def main():
    ap=argparse.ArgumentParser(prog="recon-account")
    sub=ap.add_subparsers(dest="cmd")
    c=sub.add_parser("create"); c.add_argument("name")
    c.add_argument("--url"); c.add_argument("--platform"); c.add_argument("--label")
    c.add_argument("--username"); c.add_argument("--keep-open",action="store_true")
    c.add_argument("--dry-run",action="store_true")
    sub.add_parser("list")
    a=ap.parse_args()
    if a.cmd=="create": return cmd_create(a)
    if a.cmd=="list": return cmd_list()
    ap.print_help(); return 2

if __name__=="__main__":
    sys.exit(main())
