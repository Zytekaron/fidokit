#!/bin/sh
set -euo pipefail

VC_VOLUME=$1

OS=$(uname)

if [ "$OS" = "Linux" ]; then
    # Linux: Use /dev/shm
    KEYFILE="/dev/shm/keyfile_$$.bin"

    ./fidoutil -o "$KEYFILE" "$@"
    ./veracrypt --keyfiles "$KEYFILE" "$VC_VOLUME"

    srm "$KEYFILE" || shred -u "$KEYFILE" || rm "$KEYFILE"

elif [ "$OS" = "Darwin" ]; then
    # macOS: Create RAM disk
    DISK=$(hdiutil attach -nomount ram://2048) # 512 bytes × 2048 = 1 MB
    RAMDISK_NAME="ramdisk_$(jot -r 1 100000 999999)"
    diskutil erasevolume HFS+ "$RAMDISK_NAME" "$DISK" > /dev/null
    MNT="/Volumes/$RAMDISK_NAME"
    KEYFILE="$MNT/keyfile.bin"

    ./fidoutil -o "$KEYFILE" "$@"
    ./veracrypt --keyfiles "$KEYFILE" "$VC_VOLUME"

    srm "$KEYFILE" || shred -u "$KEYFILE" || rm "$KEYFILE"
    diskutil unmount "$MNT"
    hdiutil detach "$DISK"

else
    echo "Unsupported OS: $OS" >&2
    exit 1
fi
