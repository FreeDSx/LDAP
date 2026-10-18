#!/usr/bin/env bash
# One-command fair LDAP benchmark.

# NOTE: Not storage-parity. Each server uses its own native backend.
#
# Usage (from the repo root):
#
#   composer compare-ldap -- [--source=freedsx|openldap|opendj|389ds] [--target=freedsx|openldap|opendj|389ds]
#       [--seed-entries=2000] [--seed-groups=0] [--seed-group-size=0] [--cpus=4] [--storage=sqlite] [--runner=pcntl] [--mix=default]
#       [--search-value=seed-1] [--duration=15] [--warmup=3] [--clients=8] [--driver-processes=1] [--keep-up]
#       [--swoole-workers=0] [--server-cpuset=0-3] [--driver-cpuset=4-7] [--jit=function]
#
# --storage/--runner/--jit apply only to a freedsx side.
# --jit (function, tracing, or off) is the same for every runner, so a runner comparison is not also a JIT one.
# --search-value is the cn prefix the subtree searches filter on (--search-value=seed- matches all).
#
# Every side seeds as its root identity but runs the workload as a non-root bench administrator held to its own access
# control: a group with full access and userPassword withheld from everyone, mirroring FreeDSx's secure default.
#
# Examples:
#
#   # FreeDSx (sqlite) vs OpenDJ at 25k, with search-sub kept selective on OpenDJ's substring index
#   composer compare-ldap -- --target=opendj --seed-entries=25000 --search-value=seed-12
#
#   # FreeDSx vs 389DS
#   composer compare-ldap -- --target=389ds --seed-entries=25000 --search-value=seed-12
#
#   # Any-vs-any: neither side is FreeDSx (both seeded over LDAP)
#   composer compare-ldap -- --source=openldap --target=opendj
#
set -euo pipefail

cd "$(dirname "$0")/../.."
COMPOSE="tests/profile/docker-compose.yml"

SOURCE=freedsx
TARGET=openldap
SEED=2000
SEED_GROUPS=0
SEED_GROUP_SIZE=0
CPUS=4
STORAGE=sqlite
RUNNER=pcntl
MIX=default
SEARCHVAL=seed-1
DURATION=15
WARMUP=3
CLIENTS=8
DRIVER_PROCS=1
KEEP_UP=0
WORKERS=0
SERVER_CPUSET=0-3
DRIVER_CPUSET=4-7
JIT=function

for arg in "$@"; do
    case "$arg" in
        --source=*)           SOURCE="${arg#*=}" ;;
        --target=*)           TARGET="${arg#*=}" ;;
        --seed-entries=*)     SEED="${arg#*=}" ;;
        --seed-groups=*)      SEED_GROUPS="${arg#*=}" ;;
        --seed-group-size=*)  SEED_GROUP_SIZE="${arg#*=}" ;;
        --cpus=*)             CPUS="${arg#*=}" ;;
        --storage=*)          STORAGE="${arg#*=}" ;;
        --runner=*)           RUNNER="${arg#*=}" ;;
        --mix=*)              MIX="${arg#*=}" ;;
        --search-value=*)     SEARCHVAL="${arg#*=}" ;;
        --duration=*)         DURATION="${arg#*=}" ;;
        --warmup=*)           WARMUP="${arg#*=}" ;;
        --clients=*)          CLIENTS="${arg#*=}" ;;
        --driver-processes=*) DRIVER_PROCS="${arg#*=}" ;;
        --swoole-workers=*)   WORKERS="${arg#*=}" ;;
        --server-cpuset=*)    SERVER_CPUSET="${arg#*=}" ;;
        --driver-cpuset=*)    DRIVER_CPUSET="${arg#*=}" ;;
        --jit=*)              JIT="${arg#*=}" ;;
        --keep-up)            KEEP_UP=1 ;;
        -h|--help)            sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)                    echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

# A bad value would otherwise reach php as an opcache setting and only surface as a server that will not start.
case "$JIT" in
    off|function|tracing) ;;
    *) echo "unknown --jit value: $JIT (expected off, function, or tracing)" >&2; exit 2 ;;
esac

# The non-root identity a reference side runs the workload as, created by its setup hook.
BENCH_RUN_PW="P@ssword12345"
# Pre-encoded {SSHA} of BENCH_RUN_PW: every side verifies binds with a hash as cheap as FreeDSx's {SHA} admin.
BENCH_RUN_PW_HASH="{SSHA}sSdiTIT0MbdlzPesoNF+lJtOcJRmZHhiZW5jaA=="
# Setup hook output, kept for when a run identity check fails.
SETUP_LOG="tests/profile/out/compare-setup.log"

# Resolve a service key to its compose service, container, internal LDAP port, root bind, run bind, base DN, display
# label, and per-service setup hook. Sets ${prefix}_SVC / _CONT / _PORT / _BIND / _PW / _RUN_BIND / _RUN_PW / _BASE /
# _LABEL / _SETUP.
resolve_svc() {
    local key="$1" p="$2"
    case "$key" in
        freedsx)
            # The admin is a member of cn=admins and held to the rules, unlike the privileged manager.
            declare -g "${p}_SVC=freedsx-server" "${p}_CONT=freedsx-profile-server" "${p}_PORT=10389" \
                "${p}_BIND=cn=admin,dc=foo,dc=bar" "${p}_PW=12345" "${p}_BASE=dc=foo,dc=bar" \
                "${p}_RUN_BIND=cn=admin,dc=foo,dc=bar" "${p}_RUN_PW=12345" \
                "${p}_LABEL=FreeDSx/$STORAGE" "${p}_SETUP=none" ;;
        openldap)
            declare -g "${p}_SVC=openldap" "${p}_CONT=freedsx-profile-openldap" "${p}_PORT=389" \
                "${p}_BIND=cn=admin,dc=example,dc=com" "${p}_PW=P@ssword12345" "${p}_BASE=dc=example,dc=com" \
                "${p}_RUN_BIND=cn=bench-admin,dc=example,dc=com" "${p}_RUN_PW=$BENCH_RUN_PW" \
                "${p}_LABEL=OpenLDAP" "${p}_SETUP=openldap" ;;
        opendj)
            declare -g "${p}_SVC=opendj" "${p}_CONT=freedsx-profile-opendj" "${p}_PORT=1389" \
                "${p}_BIND=cn=Directory Manager" "${p}_PW=P@ssword12345" "${p}_BASE=dc=example,dc=com" \
                "${p}_RUN_BIND=cn=bench-admin,dc=example,dc=com" "${p}_RUN_PW=$BENCH_RUN_PW" \
                "${p}_LABEL=OpenDJ" "${p}_SETUP=opendj" ;;
        389ds)
            declare -g "${p}_SVC=389ds" "${p}_CONT=freedsx-profile-389ds" "${p}_PORT=3389" \
                "${p}_BIND=cn=Directory Manager" "${p}_PW=P@ssword12345" "${p}_BASE=dc=example,dc=com" \
                "${p}_RUN_BIND=cn=bench-admin,dc=example,dc=com" "${p}_RUN_PW=$BENCH_RUN_PW" \
                "${p}_LABEL=389DS" "${p}_SETUP=389ds" ;;
        *) echo "unknown service: $key (expected freedsx, openldap, opendj, or 389ds)" >&2; exit 2 ;;
    esac
}

# The bench administrator and its group, its password and limits replaced on every replay of a reused container.
bench_identity_ldif() {
    local base="$1"
    cat <<EOF
dn: cn=bench-admin,$base
changetype: add
objectClass: inetOrgPerson
cn: bench-admin
sn: Bench
userPassword: $BENCH_RUN_PW_HASH

dn: cn=bench-admins,$base
changetype: add
objectClass: groupOfNames
cn: bench-admins
member: cn=bench-admin,$base

dn: cn=bench-admin,$base
changetype: modify
replace: userPassword
userPassword: $BENCH_RUN_PW_HASH
EOF
}

# Root bound without the size, lookthrough and time limits a plain identity gets, and FreeDSx runs without them too.
bench_unlimited_ldif() {
    local base="$1" flavor="$2"
    echo ""
    echo "dn: cn=bench-admin,$base"
    echo "changetype: modify"

    case "$flavor" in
        389ds)
            printf 'replace: %s\n%s: -1\n-\n' nsSizeLimit nsSizeLimit nsLookThroughLimit nsLookThroughLimit \
                nsPagedSizeLimit nsPagedSizeLimit nsTimeLimit nsTimeLimit ;;
        opendj)
            printf 'replace: %s\n%s: 0\n-\n' ds-rlim-size-limit ds-rlim-size-limit \
                ds-rlim-lookthrough-limit ds-rlim-lookthrough-limit ds-rlim-time-limit ds-rlim-time-limit
            printf 'replace: ds-privilege-name\nds-privilege-name: unindexed-search\n-\n' ;;
    esac
}

# Full access through the group and userPassword withheld from everyone.
bench_aci_ldif() {
    local base="$1"
    cat <<EOF

dn: $base
changetype: modify
add: aci
aci: (targetattr="userPassword")(version 3.0; acl "freedsx-bench password reads"; deny (read,search,compare) userdn="ldap:///anyone";)
aci: (targetattr="*")(version 3.0; acl "freedsx-bench administrators"; allow (all) groupdn="ldap:///cn=bench-admins,$base";)
EOF
}

# Logs every loader message, since entries and values that already exist are expected errors on a reused container.
load_ldif() {
    local label="$1"
    shift
    echo "--- $label" >>"$SETUP_LOG"
    "$@" >>"$SETUP_LOG" 2>&1 || true
}

# slapd.conf already grants the group write and lifts its limits, while withholding userPassword.
setup_openldap() {
    local bind="$1" pw="$2" base="$3"
    echo "==> adding the bench administrator to openldap"
    bench_identity_ldif "$base" \
        | load_ldif openldap docker exec -i freedsx-profile-openldap ldapmodify -x -c -H ldap://localhost -D "$bind" -w "$pw"
}

if [[ "$SOURCE" == "$TARGET" ]]; then
    echo "--source and --target must differ (got '$SOURCE' for both)" >&2
    exit 2
fi

resolve_svc "$SOURCE" SRC
resolve_svc "$TARGET" TGT

# Resolve the 'default' mix to a portable representative mix (the harness DEFAULT_MIX minus search-sort, which
# needs server-side sort vanilla slapd does not load; pass a custom --mix with search-sort for servers that support it).
if [[ "$MIX" == "default" ]]; then
    MIX="bind=5,search-read=50,search-eq=25,search-sub=10,search-list=5,add=2,modify=2,delete=1"
fi

# OpenDJ does not create the base entry and defaults are noisy/entry-limited for a benchmark: create the base entry,
# silence the per-op access log, and raise objectClass's index-entry-limit so search-list (which matches every entry
# via objectClass) stays indexed past the default 4000. search-sub is kept selective via --search-value.
setup_opendj() {
    local bind="$1" pw="$2" base="$3"
    if ! docker exec freedsx-profile-opendj /opt/opendj/bin/ldapsearch \
        -h localhost -p 1389 -D "$bind" -w "$pw" -b "$base" -s base "(objectClass=*)" 1.1 >/dev/null 2>&1; then
        echo "==> creating base entry $base in opendj"
        local dc="${base#dc=}"; dc="${dc%%,*}"
        printf 'dn: %s\nobjectClass: top\nobjectClass: domain\ndc: %s\n' "$base" "$dc" \
            | docker exec -i freedsx-profile-opendj /opt/opendj/bin/ldapmodify -a \
                -h localhost -p 1389 -D "$bind" -w "$pw"
    fi

    echo "==> tuning opendj (disable access log; raise objectClass index-entry-limit)"
    docker exec freedsx-profile-opendj /opt/opendj/bin/dsconfig set-log-publisher-prop \
        --publisher-name "Json File-Based Access Logger" --set enabled:false \
        -h localhost -p 4444 -D "$bind" -w "$pw" -X -n >/dev/null 2>&1 \
    || docker exec freedsx-profile-opendj /opt/opendj/bin/dsconfig set-log-publisher-prop \
        --publisher-name "File-Based Access Logger" --set enabled:false \
        -h localhost -p 4444 -D "$bind" -w "$pw" -X -n >/dev/null 2>&1 \
    || echo "   (access-log tweak skipped)"
    docker exec freedsx-profile-opendj /opt/opendj/bin/dsconfig set-backend-index-prop \
        --backend-name userRoot --index-name objectClass --set index-entry-limit:200000 \
        -h localhost -p 4444 -D "$bind" -w "$pw" -X -n >/dev/null 2>&1 \
    || echo "   (index-limit tweak skipped)"

    # The seeded people carry {SSHA} values, which the default policy refuses as pre-encoded.
    docker exec freedsx-profile-opendj /opt/opendj/bin/dsconfig set-password-policy-prop \
        --policy-name "Default Password Policy" --set allow-pre-encoded-passwords:true \
        -h localhost -p 4444 -D "$bind" -w "$pw" -X -n >/dev/null 2>&1 \
    || echo "   (pre-encoded password tweak skipped)"

    echo "==> adding the bench administrator and its ACIs to opendj"
    { bench_identity_ldif "$base"; bench_unlimited_ldif "$base" opendj; bench_aci_ldif "$base"; } \
        | load_ldif opendj docker exec -i freedsx-profile-opendj /opt/opendj/bin/ldapmodify -c \
            -h localhost -p 1389 -D "$bind" -w "$pw"
}

# The image creates the instance but not the suffix, so create the backend, silence the per-op access log, and raise
# the scan limits past the 4000 default so search-list stays indexed.
setup_389ds() {
    local bind="$1" pw="$2" base="$3" uri="ldap://localhost:3389"
    if ! docker exec freedsx-profile-389ds dsconf -D "$bind" -w "$pw" "$uri" backend suffix list 2>/dev/null \
        | grep -qi "$base"; then
        echo "==> creating 389ds backend for $base"
        docker exec freedsx-profile-389ds dsconf -D "$bind" -w "$pw" "$uri" backend create \
            --suffix "$base" --be-name userRoot --create-suffix
    fi

    # Shipped off, and a membership mix against it measures an empty result rather than the work.
    local needs_restart=0
    if ! docker exec freedsx-profile-389ds dsconf -D "$bind" -w "$pw" "$uri" plugin memberof show 2>/dev/null \
        | grep -qi "nsslapd-pluginEnabled: on"; then
        echo "==> enabling the 389ds memberOf plugin"
        docker exec freedsx-profile-389ds dsconf -D "$bind" -w "$pw" "$uri" plugin memberof enable
        needs_restart=1
    fi

    # The bench OpenLDAP indexes memberOf, so without this one side seeks where the other scans.
    docker exec freedsx-profile-389ds dsconf -D "$bind" -w "$pw" "$uri" backend index add \
        --attr memberOf --index-type eq --be-name userRoot >/dev/null 2>&1 \
    || true

    echo "==> tuning 389ds (disable access log; raise ID list + lookthrough limits)"
    docker exec freedsx-profile-389ds dsconf -D "$bind" -w "$pw" "$uri" \
        config replace nsslapd-accesslog-logging-enabled=off >/dev/null 2>&1 \
    || echo "   (access-log tweak skipped)"
    docker exec freedsx-profile-389ds dsconf -D "$bind" -w "$pw" "$uri" backend config set \
        --idlistscanlimit 200000 --lookthroughlimit 200000 >/dev/null 2>&1 \
    || echo "   (scan-limit tweak skipped)"
    # A bind otherwise rewrites the bench administrator's {SSHA} as PBKDF2, which every later bind then pays for.
    docker exec freedsx-profile-389ds dsconf -D "$bind" -w "$pw" "$uri" \
        config replace nsslapd-enable-upgrade-hash=off >/dev/null 2>&1 \
    || echo "   (hash-upgrade tweak skipped)"

    # A plugin only loads at startup, and the bench seeds after this returns...
    if [[ "$needs_restart" -eq 1 ]]; then
        echo "==> restarting 389ds so the plugin loads"
        docker restart freedsx-profile-389ds >/dev/null
        await_389ds "$bind" "$pw" "$uri"
    fi

    echo "==> adding the bench administrator and its ACIs to 389ds"
    { bench_identity_ldif "$base"; bench_unlimited_ldif "$base" 389ds; bench_aci_ldif "$base"; } \
        | load_ldif 389ds docker exec -i freedsx-profile-389ds ldapmodify -x -c -H "$uri" -D "$bind" -w "$pw"
}

await_389ds() {
    local bind="$1" pw="$2" uri="$3" i
    for i in $(seq 1 60); do
        if docker exec freedsx-profile-389ds dsconf -D "$bind" -w "$pw" "$uri" backend suffix list >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done

    echo "389ds did not answer again after the restart" >&2
    exit 1
}

run_setup() {
    case "$1" in
        openldap) setup_openldap "${@:2}" ;;
        opendj)   setup_opendj "${@:2}" ;;
        389ds)    setup_389ds "${@:2}" ;;
    esac
}

# The OpenLDAP image bakes in its bootstrap, whose access rules a stale image would not have.
if [[ "$SOURCE" == "openldap" || "$TARGET" == "openldap" ]]; then
    docker compose -f "$COMPOSE" build openldap
fi

echo "==> up $SRC_LABEL ($SRC_SVC) + $TGT_LABEL ($TGT_SVC) (cpuset=$SERVER_CPUSET each, driver on $DRIVER_CPUSET, seed=$SEED)"
# Sharing cores with the driver can reverse which server looks faster, so each side is pinned to its own.
PROFILE_CPUS="$CPUS" FREEDSX_STORAGE="$STORAGE" FREEDSX_RUNNER="$RUNNER" SEED_ENTRIES=0 \
SERVER_CPUSET="$SERVER_CPUSET" SWOOLE_WORKERS="$WORKERS" FREEDSX_JIT="$JIT" \
    docker compose -f "$COMPOSE" up -d --wait "$SRC_SVC" "$TGT_SVC"

mkdir -p "$(dirname "$SETUP_LOG")"
: >"$SETUP_LOG"
run_setup "$SRC_SETUP" "$SRC_BIND" "$SRC_PW" "$SRC_BASE"
run_setup "$TGT_SETUP" "$TGT_BIND" "$TGT_PW" "$TGT_BASE"
echo "==> setup loader output is in $SETUP_LOG"

NET=$(docker inspect -f '{{range $k,$_ := .NetworkSettings.Networks}}{{$k}}{{end}}' "$SRC_CONT")

echo "==> running comparison (driver container on '$NET')"
# An invalid or failed comparison still tears the stack down, then exits with the driver's status.
STATUS=0
docker run --rm --network "$NET" --cpuset-cpus="$DRIVER_CPUSET" -v "$PWD":/app -w /app --entrypoint php \
    freedsx-profile:latest -d xdebug.mode=off -d opcache.enable_cli=1 -d opcache.jit=off \
    tests/bin/ldap-bench-compare.php \
    --source-host="$SRC_SVC" --source-port="$SRC_PORT" --source-bind-dn="$SRC_BIND" --source-bind-password="$SRC_PW" --source-base-dn="$SRC_BASE" --source-label="$SRC_LABEL" \
    --source-run-bind-dn="$SRC_RUN_BIND" --source-run-bind-password="$SRC_RUN_PW" \
    --target-host="$TGT_SVC" --target-port="$TGT_PORT" --target-bind-dn="$TGT_BIND" --target-bind-password="$TGT_PW" --target-base-dn="$TGT_BASE" --target-label="$TGT_LABEL" \
    --target-run-bind-dn="$TGT_RUN_BIND" --target-run-bind-password="$TGT_RUN_PW" \
    --seed-entries="$SEED" --seed-groups="$SEED_GROUPS" --seed-group-size="$SEED_GROUP_SIZE" \
    --mix="$MIX" --search-value="$SEARCHVAL" --duration="$DURATION" --warmup="$WARMUP" \
    --clients="$CLIENTS" --driver-processes="$DRIVER_PROCS" \
|| STATUS=$?

if [[ "$KEEP_UP" -eq 0 ]]; then
    echo "==> tearing down (pass --keep-up to skip)"
    docker compose -f "$COMPOSE" down
fi

exit "$STATUS"
