#!/bin/bash
# ==============================================================================
# Trend Micro Vision One — global account cleanup
#
# Changes from v1.3:
#   • GLOBAL section (S3 + IAM + OIDC) runs FIRST, before per-region work,
#     so the priority cleanup happens before any session timeout
#   • S3 bucket emptying + deletion runs PARALLEL ($PARALLEL_S3 workers, default 8)
#   • Per-region work runs PARALLEL ($PARALLEL_REGIONS workers, default 4)
#   • Per-bucket progress lines instead of per-object spew (s3 rm --quiet)
#   • Auth precheck works for both AWS_PROFILE and CloudShell implicit creds
#   • Empty-region fast-skip: a region with no Trend resources is detected
#     quickly via one Lambda+LogGroup probe and skipped before the full scan
#
# Changes from v1.2 (unchanged from v1.3):
#   • nat-gateway-deleted waiter (was nat-gateway-available)
#   • Proper VPC dismantle: VPC endpoints, route tables, IGW detach+delete,
#     security groups, network ACLs, EIPs
#   • Live EBS volumes (in addition to snapshots)
#   • IAM roles, instance profiles, OIDC provider
#   • CloudTrail trails, KMS aliases (+ schedule key deletion)
#   • EventBridge rules + EventBridge Scheduler schedules/groups
#   • SNS topics, SQS queues, Lambda layers, event-source mappings
#
# Run AFTER prelude_delete_cfn.sh has finished.
#
# USAGE:
#   DRY_RUN=true  ./nuke_all_trendmicro_aws_v1.3.sh   # default: see what would happen
#   DRY_RUN=false ./nuke_all_trendmicro_aws_v1.3.sh   # actually delete
#
#   # Tuning knobs:
#   PARALLEL_REGIONS=6 PARALLEL_S3=12 DRY_RUN=false ./nuke_all_trendmicro_aws_v1.3.sh
#
#   # CloudShell (no SSO, implicit IAM creds):
#   unset AWS_PROFILE
#   DRY_RUN=false ./nuke_all_trendmicro_aws_v1.3.sh
# ==============================================================================

set -u

# ----- SETTINGS ---------------------------------------------------------------
DRY_RUN=${DRY_RUN:-true}                                     # set to false to execute
PARALLEL_REGIONS=${PARALLEL_REGIONS:-4}                      # concurrent regions
PARALLEL_S3=${PARALLEL_S3:-8}                                # concurrent bucket workers
PROFILE_FLAG=""
if [ -n "${AWS_PROFILE:-}" ]; then PROFILE_FLAG="--profile $AWS_PROFILE"; fi
REPORT_FILE=${REPORT_FILE:-deleted_resources_v1.3.csv}

# Patterns
S3_PREFIXES=("dspm" "trendmicro" "v1" "cloud-sentry" "sentrystackset" "v1dspm" "v1fs" "sentrysharedset")
CW_ROOTS=("cloud-sentry" "SentryStackSet" "V1Dspm" "V1FS" "SentrySharedSet" "v1-common" "StackSet-V1FSStackSet" "StackSet-V1DspmStackSet" "Vision-One")
VPC_NAME_PATTERNS=("v1-avtd-scanner-vpc" "v1-")
SECRET_ROOTS=("V1CS" "v1-common" "V1FS" "SentryAPI")
LAMBDA_ROOTS=("cloud-sentry" "v1-common" "StackSet-V1FSStackSet" "StackSet-V1DspmStackSet" "Vision-One")
SNAPSHOT_DESC_PART="Trend Micro Cloud Sentry"
IAM_ROLE_PATTERNS=("Vision-One-Cloud-Account" "Cloud-One-Cloud-Account" "FSSStackSetsExecutionRole" "DSPMStackSetsExecutionRole" "FSSStackSetsAdministrationRole" "DSPMStackSetsAdministrationRole" "SentryScannerEC2Role" "SentryStackSet" "StackSet-V1FSStackSet" "StackSet-V1DspmStackSet" "StackSet-SentryStackSet" "VisionOneRole" "CloudOneAccount")
IAM_PROFILE_PATTERNS=("Vision-One" "SentryScanner" "StackSet-V1FSStackSet" "StackSet-V1DspmStackSet")
CLOUDTRAIL_PATTERNS=("dspm" "v1-" "trendmicro" "Vision-One")
KMS_ALIAS_PATTERNS=("alias/dspm" "alias/v1-" "alias/trendmicro" "alias/Vision-One" "alias/cloud-sentry")
EVENTS_RULE_PATTERNS=("Sentry" "v1-" "StackSet-V1FSStackSet" "StackSet-V1DspmStackSet")
SCHEDULER_GROUP_PATTERNS=("FSSScheduleGroup" "V1" "Sentry")
SNS_TOPIC_PATTERNS=("StackSet-V1FSStackSet" "StackSet-V1DspmStackSet" "v1-" "Sentry")
SQS_QUEUE_PATTERNS=("StackSet-V1FSStackSet" "StackSet-V1DspmStackSet" "v1-" "Sentry")
OIDC_URL_PATTERNS=("visionone" "trendmicro")
EBS_TAG_PATTERNS=("dspm" "v1-" "Sentry" "trendmicro")

# ----- HELPERS ----------------------------------------------------------------
AWS="aws $PROFILE_FLAG"

# Auth precheck — fail loudly if SSO is dead instead of silently no-op'ing.
# Works for both SSO profiles AND CloudShell (where AWS_PROFILE is unset and
# credentials come from the instance metadata).
if ! $AWS sts get-caller-identity --query Account --output text >/dev/null 2>&1; then
  if [ -n "${AWS_PROFILE:-}" ]; then
    echo "FATAL: AWS auth failed. Run: aws sso login --profile $AWS_PROFILE" >&2
  else
    echo "FATAL: AWS auth failed. In CloudShell, ensure you're signed in. Locally, run: aws sso login --profile <name>" >&2
  fi
  exit 2
fi

# Append to CSV (preserve history across re-runs); write header only if new file.
if [ ! -f "$REPORT_FILE" ]; then
  echo "Resource_Type,Resource_Name,Region,Status,Detail" > "$REPORT_FILE"
fi
# log() — POSIX guarantees small (<PIPE_BUF, ~4KB) writes via O_APPEND are atomic,
# so this is safe to call from concurrent subshells.
log() { echo "$1,$2,$3,$4,${5:-}" >> "$REPORT_FILE"; }

dry() {
  if [ "$DRY_RUN" = true ]; then
    echo "  [DRY RUN] $*"
    return 0
  fi
  return 1
}

lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

match_any() {
  local hay; hay=$(lc "$1"); shift
  local n nl
  for n in "$@"; do
    nl=$(lc "$n")
    case "$hay" in *"$nl"*) return 0 ;; esac
  done
  return 1
}

match_prefix() {
  local hay; hay=$(lc "$1"); shift
  local n nl
  for n in "$@"; do
    nl=$(lc "$n")
    case "$hay" in "$nl"*) return 0 ;; esac
  done
  return 1
}

# Wait for a batch of PIDs to finish (portable across bash 3.2+; CloudShell has modern bash too).
wait_batch() {
  local pid
  for pid in "$@"; do wait "$pid" 2>/dev/null; done
}

echo "============================================================"
echo "  Trend Micro nuke (v1.3 / parallel)"
echo "  Profile          : ${AWS_PROFILE:-<default / CloudShell>}"
echo "  Dry run          : $DRY_RUN"
echo "  Parallel regions : $PARALLEL_REGIONS"
echo "  Parallel S3      : $PARALLEL_S3"
echo "  Report           : $REPORT_FILE"
echo "============================================================"

# ============================================================================
# PHASE 1 — GLOBAL (non-regional) RESOURCES — runs FIRST because S3 buckets
# are typically where the most work remains, and we want that done before
# any session timeout.
# ============================================================================
echo ""
echo "================ PHASE 1: GLOBAL ================"

# Empty a versioned S3 bucket — one server page (≤1000 keys, mixed
# Versions + DeleteMarkers) per iteration. S3 delete-objects max is 1000.
empty_versioned_bucket() {
  local B=$1 R=$2
  while :; do
    local PAGE
    PAGE=$($AWS --region "$R" s3api list-object-versions --bucket "$B" \
      --no-paginate --max-keys 1000 --output json 2>/dev/null)
    [ -z "$PAGE" ] && break
    local PAYLOAD
    PAYLOAD=$(echo "$PAGE" | jq -c '{Objects: ((.Versions // []) + (.DeleteMarkers // []) | map({Key, VersionId})), Quiet: true}')
    local COUNT
    COUNT=$(echo "$PAYLOAD" | jq -r '.Objects | length')
    [ -z "$COUNT" ] || [ "$COUNT" = "0" ] && break
    echo "$PAYLOAD" | $AWS --region "$R" s3api delete-objects --bucket "$B" --delete file:///dev/stdin >/dev/null 2>&1 || break
  done
}

# Empty + delete one bucket (intended to be backgrounded for parallelism)
process_bucket() {
  local BUCKET=$1
  if dry "s3 rm + delete-bucket $BUCKET"; then return 0; fi
  local B_REG
  B_REG=$($AWS s3api get-bucket-location --bucket "$BUCKET" --query "LocationConstraint" --output text 2>/dev/null)
  [ -z "$B_REG" ] || [ "$B_REG" = "None" ] && B_REG="us-east-1"
  # Strip blocking configs
  $AWS --region "$B_REG" s3api delete-bucket-policy --bucket "$BUCKET" 2>/dev/null
  $AWS --region "$B_REG" s3api put-bucket-notification-configuration --bucket "$BUCKET" --notification-configuration '{}' 2>/dev/null
  $AWS --region "$B_REG" s3api delete-bucket-replication --bucket "$BUCKET" 2>/dev/null
  # Current objects (fast path) — --quiet suppresses per-object spew
  $AWS --region "$B_REG" s3 rm "s3://$BUCKET" --recursive --quiet 2>/dev/null
  # Versioned objects + delete markers
  empty_versioned_bucket "$BUCKET" "$B_REG"
  # Final delete with error capture
  local OUT
  OUT=$($AWS --region "$B_REG" s3api delete-bucket --bucket "$BUCKET" 2>&1)
  if [ -z "$OUT" ]; then
    log "S3Bucket" "$BUCKET" "$B_REG" "Deleted"
    echo "  ✓ $BUCKET ($B_REG)"
  else
    log "S3Bucket" "$BUCKET" "$B_REG" "FAILED" "$(echo "$OUT" | head -1 | tr ',' ' ' | tr -d '\n')"
    echo "  ✗ $BUCKET ($B_REG) → $(echo "$OUT" | head -1)"
  fi
}

# Collect matching buckets
echo "  Listing S3 buckets…"
ALL_BUCKETS=$($AWS s3api list-buckets --query "Buckets[].Name" --output text 2>/dev/null)
MATCHING_BUCKETS=()
for B in $ALL_BUCKETS; do
  if match_prefix "$B" "${S3_PREFIXES[@]}"; then
    MATCHING_BUCKETS+=("$B")
  fi
done
echo "  Found ${#MATCHING_BUCKETS[@]} Trend-pattern buckets. Processing with $PARALLEL_S3 workers…"

PIDS=()
for BUCKET in "${MATCHING_BUCKETS[@]}"; do
  process_bucket "$BUCKET" &
  PIDS+=("$!")
  if [ "${#PIDS[@]}" -ge "$PARALLEL_S3" ]; then
    wait_batch "${PIDS[@]}"
    PIDS=()
  fi
done
wait_batch "${PIDS[@]}"

# --- IAM roles (sequential — fast) -------------------------------------------
echo ""
echo "  IAM roles…"
for ROLE in $($AWS iam list-roles --query 'Roles[].RoleName' --output text 2>/dev/null); do
  if match_any "$ROLE" "${IAM_ROLE_PATTERNS[@]}"; then
    if dry "iam delete-role $ROLE"; then continue; fi
    for POL in $($AWS iam list-attached-role-policies --role-name "$ROLE" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); do
      $AWS iam detach-role-policy --role-name "$ROLE" --policy-arn "$POL" 2>/dev/null
    done
    for INLINE in $($AWS iam list-role-policies --role-name "$ROLE" --query 'PolicyNames' --output text 2>/dev/null); do
      $AWS iam delete-role-policy --role-name "$ROLE" --policy-name "$INLINE" 2>/dev/null
    done
    for IP in $($AWS iam list-instance-profiles-for-role --role-name "$ROLE" --query 'InstanceProfiles[].InstanceProfileName' --output text 2>/dev/null); do
      $AWS iam remove-role-from-instance-profile --instance-profile-name "$IP" --role-name "$ROLE" 2>/dev/null
    done
    if $AWS iam delete-role --role-name "$ROLE" 2>/dev/null; then
      log "IAMRole" "$ROLE" "global" "Deleted"
      echo "  ✓ role $ROLE"
    else
      log "IAMRole" "$ROLE" "global" "FAILED"
      echo "  ✗ role $ROLE"
    fi
  fi
done

# --- IAM instance profiles ---------------------------------------------------
for IP in $($AWS iam list-instance-profiles --query 'InstanceProfiles[].InstanceProfileName' --output text 2>/dev/null); do
  if match_any "$IP" "${IAM_PROFILE_PATTERNS[@]}"; then
    if dry "iam delete-instance-profile $IP"; then continue; fi
    for ROLE in $($AWS iam get-instance-profile --instance-profile-name "$IP" --query 'InstanceProfile.Roles[].RoleName' --output text 2>/dev/null); do
      $AWS iam remove-role-from-instance-profile --instance-profile-name "$IP" --role-name "$ROLE" 2>/dev/null
    done
    $AWS iam delete-instance-profile --instance-profile-name "$IP" 2>/dev/null && log "IAMInstanceProfile" "$IP" "global" "Deleted"
  fi
done

# --- OIDC providers ----------------------------------------------------------
for OIDC in $($AWS iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn' --output text 2>/dev/null); do
  URL=$($AWS iam get-open-id-connect-provider --open-id-connect-provider-arn "$OIDC" --query 'Url' --output text 2>/dev/null)
  if match_any "$URL" "${OIDC_URL_PATTERNS[@]}"; then
    dry "iam delete-open-id-connect-provider $OIDC ($URL)" || { $AWS iam delete-open-id-connect-provider --open-id-connect-provider-arn "$OIDC" 2>/dev/null && log "OIDCProvider" "$OIDC" "global" "Deleted" "$URL"; echo "  ✓ OIDC $URL"; }
  fi
done

# ============================================================================
# PHASE 2 — PER-REGION WORK (parallelized across regions)
# ============================================================================
echo ""
echo "================ PHASE 2: PER-REGION ================"

# Fast-skip detection: probe Lambda + log groups for matching names. If neither
# region has any Trend resources, return non-zero so the caller skips the full
# expensive scan. Cheap two-call probe.
region_has_trend() {
  local REGION=$1
  local R="$AWS --region $REGION"
  if $R lambda list-functions --query "Functions[?contains(FunctionName,'cloud-sentry') || contains(FunctionName,'v1-common') || contains(FunctionName,'StackSet-V1')] | length(@)" --output text 2>/dev/null | grep -qE '^[1-9]'; then
    return 0
  fi
  if $R logs describe-log-groups --query "logGroups[?contains(logGroupName,'cloud-sentry') || contains(logGroupName,'v1-common') || contains(logGroupName,'StackSet-V1') || contains(logGroupName,'StackSet-Sentry')] | length(@)" --output text 2>/dev/null | grep -qE '^[1-9]'; then
    return 0
  fi
  return 1
}

# Per-region cleanup. Called in a backgrounded subshell — inherits all arrays
# and helper functions from the parent shell.
process_region() {
  local REGION=$1
  local R="$AWS --region $REGION"
  local TAG="[$REGION]"

  if ! region_has_trend "$REGION"; then
    echo "  $TAG no Trend resources detected — skipping"
    return 0
  fi
  echo "  $TAG Trend resources present, processing…"

  # 1. Lambda functions
  for FN in $($R lambda list-functions --query "Functions[].FunctionName" --output text 2>/dev/null); do
    if match_any "$FN" "${LAMBDA_ROOTS[@]}"; then
      dry "$TAG lambda delete-function $FN" || { $R lambda delete-function --function-name "$FN" 2>/dev/null && log "Lambda" "$FN" "$REGION" "Deleted"; }
    fi
  done

  # 1b. Lambda event-source mappings
  for ESM in $($R lambda list-event-source-mappings --query 'EventSourceMappings[].UUID' --output text 2>/dev/null); do
    FN_ARN=$($R lambda get-event-source-mapping --uuid "$ESM" --query 'FunctionArn' --output text 2>/dev/null)
    if match_any "$FN_ARN" "${LAMBDA_ROOTS[@]}"; then
      dry "$TAG lambda delete-event-source-mapping $ESM" || { $R lambda delete-event-source-mapping --uuid "$ESM" 2>/dev/null && log "LambdaESM" "$ESM" "$REGION" "Deleted" "$FN_ARN"; }
    fi
  done

  # 1c. Lambda layers
  for LAYER in $($R lambda list-layers --query 'Layers[].LayerName' --output text 2>/dev/null); do
    if match_any "$LAYER" "${LAMBDA_ROOTS[@]}"; then
      for V in $($R lambda list-layer-versions --layer-name "$LAYER" --query 'LayerVersions[].Version' --output text 2>/dev/null); do
        dry "$TAG lambda delete-layer-version $LAYER:$V" || { $R lambda delete-layer-version --layer-name "$LAYER" --version-number "$V" 2>/dev/null && log "LambdaLayer" "$LAYER:$V" "$REGION" "Deleted"; }
      done
    fi
  done

  # 2. Secrets Manager (replication-aware)
  local SECRETS_DATA
  SECRETS_DATA=$($R secretsmanager list-secrets --output json 2>/dev/null)
  for SECRET in $(echo "$SECRETS_DATA" | jq -r '.SecretList[].Name' 2>/dev/null); do
    if ! match_any "$SECRET" "${SECRET_ROOTS[@]}"; then continue; fi
    local PRIMARY
    PRIMARY=$(echo "$SECRETS_DATA" | jq -r ".SecretList[] | select(.Name==\"$SECRET\") | .PrimaryRegion // \"\"")
    if [ -n "$PRIMARY" ] && [ "$PRIMARY" != "$REGION" ]; then
      echo "  $TAG [INFO] $SECRET is replica (primary=$PRIMARY), skipping"
      continue
    fi
    if dry "$TAG secret + replicas: $SECRET"; then continue; fi
    for REP_REG in $($R secretsmanager describe-secret --secret-id "$SECRET" --query "ReplicationStatus[].Region" --output text 2>/dev/null); do
      $R secretsmanager remove-regions-from-replication --secret-id "$SECRET" --remove-replica-regions "$REP_REG" >/dev/null 2>&1 \
        && log "SecretReplica" "$SECRET" "$REP_REG" "Removed"
    done
    $R secretsmanager delete-secret --secret-id "$SECRET" --force-delete-without-recovery >/dev/null 2>&1 \
      && log "SecretPrimary" "$SECRET" "$REGION" "Deleted"
  done

  # 3. CloudWatch log groups
  for LG in $($R logs describe-log-groups --query 'logGroups[].logGroupName' --output text 2>/dev/null); do
    if match_any "$LG" "${CW_ROOTS[@]}"; then
      dry "$TAG logs delete-log-group $LG" || { $R logs delete-log-group --log-group-name "$LG" 2>/dev/null && log "LogGroup" "$LG" "$REGION" "Deleted"; }
    fi
  done

  # 4. EBS snapshots
  for SNAP in $($R ec2 describe-snapshots --owner-ids self --query "Snapshots[?contains(Description, '$SNAPSHOT_DESC_PART')].SnapshotId" --output text 2>/dev/null); do
    dry "$TAG ec2 delete-snapshot $SNAP" || { $R ec2 delete-snapshot --snapshot-id "$SNAP" 2>/dev/null && log "Snapshot" "$SNAP" "$REGION" "Deleted"; }
  done

  # 4b. Live EBS volumes (tag-filtered, only 'available' or detached)
  local VOLS
  VOLS=$($R ec2 describe-volumes --query 'Volumes[].{Id:VolumeId,State:State,Tags:Tags}' --output json 2>/dev/null)
  for ROW in $(echo "$VOLS" | jq -c '.[]?' 2>/dev/null); do
    local VID STATE TAGS
    VID=$(echo "$ROW" | jq -r '.Id')
    STATE=$(echo "$ROW" | jq -r '.State')
    TAGS=$(echo "$ROW" | jq -r '[.Tags[]?|.Value]|join(",")')
    if match_any "$TAGS" "${EBS_TAG_PATTERNS[@]}"; then
      if [ "$STATE" = "available" ]; then
        dry "$TAG ec2 delete-volume $VID" || { $R ec2 delete-volume --volume-id "$VID" 2>/dev/null && log "EBSVolume" "$VID" "$REGION" "Deleted" "tags=$TAGS"; }
      else
        echo "  $TAG [SKIP] EBS $VID state=$STATE (still in-use) tags=$TAGS"
        log "EBSVolume" "$VID" "$REGION" "SkippedInUse" "state=$STATE"
      fi
    fi
  done

  # 5. VPC dismantle
  local VPCS_JSON
  VPCS_JSON=$($R ec2 describe-vpcs --query "Vpcs[].{Id:VpcId,Tags:Tags}" --output json 2>/dev/null)
  for V_ROW in $(echo "$VPCS_JSON" | jq -c '.[]?' 2>/dev/null); do
    local VID NAME HIT
    VID=$(echo "$V_ROW" | jq -r '.Id')
    NAME=$(echo "$V_ROW" | jq -r '[.Tags[]?|select(.Key=="Name")|.Value][0] // ""')
    HIT=false
    for P in "${VPC_NAME_PATTERNS[@]}"; do [[ "$NAME" == "$P" || "$NAME" == "$P"* ]] && HIT=true; done
    if [ "$HIT" != true ]; then continue; fi
    if dry "$TAG VPC dismantle $VID (Name=$NAME)"; then continue; fi
    echo "  $TAG Dismantling VPC $VID (Name=$NAME)"
    # NAT gateways
    for NAT in $($R ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$VID" --query 'NatGateways[?State!=`deleted`].NatGatewayId' --output text 2>/dev/null); do
      $R ec2 delete-nat-gateway --nat-gateway-id "$NAT" >/dev/null 2>&1 \
        && log "NatGateway" "$NAT" "$REGION" "DeleteSubmitted"
      timeout 600s $R ec2 wait nat-gateway-deleted --nat-gateway-ids "$NAT" 2>/dev/null
    done
    # Unattached EIPs
    for ALLOC in $($R ec2 describe-addresses --query 'Addresses[?AssociationId==null].AllocationId' --output text 2>/dev/null); do
      $R ec2 release-address --allocation-id "$ALLOC" 2>/dev/null \
        && log "EIP" "$ALLOC" "$REGION" "Released"
    done
    # Instances
    local INSTANCES
    INSTANCES=$($R ec2 describe-instances --filters "Name=vpc-id,Values=$VID" \
      --query 'Reservations[].Instances[?State.Name!=`terminated`].InstanceId' --output text 2>/dev/null)
    if [ -n "$INSTANCES" ]; then
      $R ec2 terminate-instances --instance-ids $INSTANCES >/dev/null 2>&1
      timeout 600s $R ec2 wait instance-terminated --instance-ids $INSTANCES 2>/dev/null
      for I in $INSTANCES; do log "EC2Instance" "$I" "$REGION" "Terminated"; done
    fi
    # VPC endpoints
    for EP in $($R ec2 describe-vpc-endpoints --filters "Name=vpc-id,Values=$VID" --query 'VpcEndpoints[].VpcEndpointId' --output text 2>/dev/null); do
      $R ec2 delete-vpc-endpoints --vpc-endpoint-ids "$EP" >/dev/null 2>&1 \
        && log "VPCEndpoint" "$EP" "$REGION" "Deleted"
    done
    # ENIs
    for ENI in $($R ec2 describe-network-interfaces --filters "Name=vpc-id,Values=$VID" --query 'NetworkInterfaces[?Status==`available`].NetworkInterfaceId' --output text 2>/dev/null); do
      $R ec2 delete-network-interface --network-interface-id "$ENI" 2>/dev/null \
        && log "ENI" "$ENI" "$REGION" "Deleted"
    done
    # Subnets
    for SN in $($R ec2 describe-subnets --filters "Name=vpc-id,Values=$VID" --query 'Subnets[].SubnetId' --output text 2>/dev/null); do
      $R ec2 delete-subnet --subnet-id "$SN" 2>/dev/null && log "Subnet" "$SN" "$REGION" "Deleted"
    done
    # Route tables (non-main)
    for RT in $($R ec2 describe-route-tables --filters "Name=vpc-id,Values=$VID" \
        --query 'RouteTables[?Associations[?Main!=`true`]||length(Associations)==`0`].RouteTableId' --output text 2>/dev/null); do
      for ASSOC in $($R ec2 describe-route-tables --route-table-ids "$RT" \
          --query 'RouteTables[0].Associations[?Main!=`true`].RouteTableAssociationId' --output text 2>/dev/null); do
        $R ec2 disassociate-route-table --association-id "$ASSOC" 2>/dev/null
      done
      $R ec2 delete-route-table --route-table-id "$RT" 2>/dev/null && log "RouteTable" "$RT" "$REGION" "Deleted"
    done
    # SGs (non-default)
    for SG in $($R ec2 describe-security-groups --filters "Name=vpc-id,Values=$VID" \
        --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text 2>/dev/null); do
      $R ec2 revoke-security-group-ingress --group-id "$SG" --ip-permissions "$($R ec2 describe-security-groups --group-ids "$SG" --query 'SecurityGroups[0].IpPermissions' --output json)" 2>/dev/null
      $R ec2 revoke-security-group-egress  --group-id "$SG" --ip-permissions "$($R ec2 describe-security-groups --group-ids "$SG" --query 'SecurityGroups[0].IpPermissionsEgress' --output json)" 2>/dev/null
      $R ec2 delete-security-group --group-id "$SG" 2>/dev/null && log "SecurityGroup" "$SG" "$REGION" "Deleted"
    done
    # NACLs (non-default)
    for ACL in $($R ec2 describe-network-acls --filters "Name=vpc-id,Values=$VID" \
        --query 'NetworkAcls[?IsDefault==`false`].NetworkAclId' --output text 2>/dev/null); do
      $R ec2 delete-network-acl --network-acl-id "$ACL" 2>/dev/null && log "NetworkAcl" "$ACL" "$REGION" "Deleted"
    done
    # IGWs
    for IGW in $($R ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VID" \
        --query 'InternetGateways[].InternetGatewayId' --output text 2>/dev/null); do
      $R ec2 detach-internet-gateway --internet-gateway-id "$IGW" --vpc-id "$VID" 2>/dev/null
      $R ec2 delete-internet-gateway --internet-gateway-id "$IGW" 2>/dev/null \
        && log "InternetGateway" "$IGW" "$REGION" "Deleted"
    done
    $R ec2 delete-vpc --vpc-id "$VID" 2>/dev/null && log "VPC" "$VID" "$REGION" "Deleted"
  done

  # 6. CloudTrail trails
  for TRAIL in $($R cloudtrail list-trails --query 'Trails[].Name' --output text 2>/dev/null); do
    if match_any "$TRAIL" "${CLOUDTRAIL_PATTERNS[@]}"; then
      dry "$TAG cloudtrail delete-trail $TRAIL" || { $R cloudtrail delete-trail --name "$TRAIL" 2>/dev/null && log "CloudTrail" "$TRAIL" "$REGION" "Deleted"; }
    fi
  done

  # 7. KMS aliases + schedule key deletion
  local ALIASES_JSON
  ALIASES_JSON=$($R kms list-aliases --query 'Aliases[].{Name:AliasName,Key:TargetKeyId}' --output json 2>/dev/null)
  for ROW in $(echo "$ALIASES_JSON" | jq -c '.[]?' 2>/dev/null); do
    local ALIAS KEY
    ALIAS=$(echo "$ROW" | jq -r '.Name')
    KEY=$(echo   "$ROW" | jq -r '.Key // ""')
    if match_any "$ALIAS" "${KMS_ALIAS_PATTERNS[@]}"; then
      dry "$TAG kms delete-alias $ALIAS" || { $R kms delete-alias --alias-name "$ALIAS" 2>/dev/null && log "KMSAlias" "$ALIAS" "$REGION" "Deleted"; }
      if [ -n "$KEY" ] && [ "$KEY" != "null" ]; then
        dry "$TAG kms schedule-key-deletion $KEY (7d)" || { $R kms schedule-key-deletion --key-id "$KEY" --pending-window-in-days 7 >/dev/null 2>&1 && log "KMSKey" "$KEY" "$REGION" "Scheduled7d"; }
      fi
    fi
  done

  # 8. EventBridge rules
  for BUS in default; do
    for RULE in $($R events list-rules --event-bus-name "$BUS" --query 'Rules[].Name' --output text 2>/dev/null); do
      if match_any "$RULE" "${EVENTS_RULE_PATTERNS[@]}"; then
        if ! dry "$TAG events remove targets+delete-rule $RULE"; then
          local TIDS
          TIDS=$($R events list-targets-by-rule --rule "$RULE" --event-bus-name "$BUS" --query 'Targets[].Id' --output text 2>/dev/null)
          [ -n "$TIDS" ] && $R events remove-targets --rule "$RULE" --event-bus-name "$BUS" --ids $TIDS >/dev/null 2>&1
          $R events delete-rule --name "$RULE" --event-bus-name "$BUS" 2>/dev/null \
            && log "EventBridgeRule" "$RULE" "$REGION" "Deleted"
        fi
      fi
    done
  done

  # 8b. EventBridge Scheduler
  for GRP in $($R scheduler list-schedule-groups --query 'ScheduleGroups[].Name' --output text 2>/dev/null); do
    if match_any "$GRP" "${SCHEDULER_GROUP_PATTERNS[@]}"; then
      for SCH in $($R scheduler list-schedules --group-name "$GRP" --query 'Schedules[].Name' --output text 2>/dev/null); do
        dry "$TAG scheduler delete-schedule $SCH ($GRP)" || { $R scheduler delete-schedule --name "$SCH" --group-name "$GRP" 2>/dev/null && log "Schedule" "$SCH" "$REGION" "Deleted" "group=$GRP"; }
      done
      dry "$TAG scheduler delete-schedule-group $GRP" || { $R scheduler delete-schedule-group --name "$GRP" 2>/dev/null && log "ScheduleGroup" "$GRP" "$REGION" "Deleted"; }
    fi
  done

  # 9. SNS topics
  for TOPIC in $($R sns list-topics --query 'Topics[].TopicArn' --output text 2>/dev/null); do
    if match_any "$TOPIC" "${SNS_TOPIC_PATTERNS[@]}"; then
      dry "$TAG sns delete-topic $TOPIC" || { $R sns delete-topic --topic-arn "$TOPIC" 2>/dev/null && log "SNSTopic" "$TOPIC" "$REGION" "Deleted"; }
    fi
  done

  # 10. SQS queues
  for QURL in $($R sqs list-queues --query 'QueueUrls' --output text 2>/dev/null); do
    if match_any "$QURL" "${SQS_QUEUE_PATTERNS[@]}"; then
      dry "$TAG sqs delete-queue $QURL" || { $R sqs delete-queue --queue-url "$QURL" 2>/dev/null && log "SQSQueue" "$QURL" "$REGION" "Deleted"; }
    fi
  done

  echo "  $TAG done"
}

# Discover region order (US first)
ALL_REGIONS=$($AWS ec2 describe-regions --query "Regions[].RegionName" --output text 2>/dev/null)
US_REGIONS=$(echo "$ALL_REGIONS" | tr '\t' '\n' | grep '^us-' || true)
OTHER_REGIONS=$(echo "$ALL_REGIONS" | tr '\t' '\n' | grep -v '^us-' || true)
ORDERED_REGIONS=$(echo -e "$US_REGIONS\n$OTHER_REGIONS" | grep -v '^$' || true)

# Parallel region processing
PIDS=()
for REGION in $ORDERED_REGIONS; do
  [ -z "$REGION" ] && continue
  ( process_region "$REGION" ) &
  PIDS+=("$!")
  if [ "${#PIDS[@]}" -ge "$PARALLEL_REGIONS" ]; then
    wait_batch "${PIDS[@]}"
    PIDS=()
  fi
done
wait_batch "${PIDS[@]}"

echo ""
echo "============================================================"
echo "  Cleanup complete. Report: $REPORT_FILE"
echo "============================================================"
