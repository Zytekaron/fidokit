#!/bin/sh
set -euo pipefail

VC_VOLUME="$1"

OS=$(uname)

if [ "$OS" = "Linux" ]; then
    # Linux: Use /dev/shm
    RAND=$(($(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 900000 + 100000))
    KEYFILE="/dev/shm/keyfile_$RAND.bin"

    echo "Starting fidokit in unlock mode:"
    ./fidokit -U -o "$KEYFILE" "$@" || true

    veracrypt -t --keyfiles "$KEYFILE" "$VC_VOLUME" || true

    srm "$KEYFILE" 2>/dev/null || shred -u "$KEYFILE" 2>/dev/null || rm "$KEYFILE"

elif [ "$OS" = "Darwin" ]; then
    # macOS: Create RAM disk
    DISK=$(hdiutil attach -nomount ram://2048) # 512 bytes × 2048 = 1 MB
    RAMDISK_NAME="ramdisk_$(jot -r 1 100000 999999)"
    diskutil erasevolume HFS+ "$RAMDISK_NAME" $DISK > /dev/null # NOTE: DO NOT QUOTE $DISK
    MOUNTPOINT="/Volumes/$RAMDISK_NAME"
    KEYFILE="$MOUNTPOINT/keyfile.bin"

    echo "Starting fidokit in unlock mode:"
    ./fidokit -U -o "$KEYFILE" "$@" || true

    veracrypt -t --keyfiles "$KEYFILE" "$VC_VOLUME" || true

    srm "$KEYFILE" 2>/dev/null || shred -u "$KEYFILE" 2>/dev/null || rm "$KEYFILE"
    diskutil unmount "$MOUNTPOINT"
    hdiutil detach $DISK # NOTE: DO NOT QUOTE $DISK

else
    echo "Unsupported OS: $OS" >&2
    exit 1
fi
