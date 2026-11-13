# LXD Privilege Escalation - OSCP Compliant

Command guide for LXD group privilege escalation. This tool does NOT execute any exploit commands automatically. It enumerates the target environment and prints the exact commands for you to run manually.

## Usage

```bash
chmod +x priv.sh
./priv.sh
```

Or specify an Alpine rootfs tarball:

```bash
./priv.sh alpine-minirootfs-3.18.0-x86_64.tar.gz
```

## What it does

1. Checks if the current user is in the `lxd` group
2. Locates `lxc`/`lxd` binaries on the system
3. Detects existing storage pools and images
4. Prints step-by-step commands to:
   - Create a storage pool (if needed)
   - Import an Alpine image (if needed)
   - Create a privileged container with the host filesystem mounted
   - Read flags and `/etc/shadow`
   - Get a root shell via chroot
   - Clean up after exploitation

## OSCP Compliance

This tool is designed for OSCP exam and lab use:
- No automatic exploitation
- No automatic command execution beyond enumeration
- All exploit commands are displayed for manual execution
- You maintain full control over every action

## Requirements

- Member of the `lxd` group
- LXD/LXC installed on the target

## Files

- `priv.sh` - LXD privilege escalation command guide
- `alpine-minirootfs-3.18.0-x86_64.tar.gz` - pre-built Alpine rootfs (no internet needed on target)
