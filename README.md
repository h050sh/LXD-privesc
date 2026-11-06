# LXD Privilege Escalation

CTF easy script — pre-built Alpine image included, just install and run if you're in the `lxd` group.

## Usage

```bash
chmod +x priv.sh
./priv.sh
```

Or with the included Alpine rootfs:

```bash
./priv.sh alpine-minirootfs-3.18.0-x86_64.tar.gz
```

## What it does

1. Detects `lxc`/`lxd` on the system
2. Creates a privileged container with the host filesystem mounted at `/mnt/root`
3. Reads flags and `/etc/shadow`
4. Drops you into a root shell on the host

## Requirements

- Member of the `lxd` group
- LXD/LXC installed on the target

## Files

- `priv.sh` — the privesc script
- `alpine-minirootfs-3.18.0-x86_64.tar.gz` — pre-built Alpine rootfs (no internet needed on target)
