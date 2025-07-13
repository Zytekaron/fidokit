package utils

import (
	"fmt"
	"os/user"
	"syscall"
)

// CheckPlugdev checks if the user is root or is in the plugdev group.
// This is required on Linux to use the libfido2 API.
// Only call this function on Linux.
func CheckPlugdev() (bool, error) {
	if syscall.Geteuid() == 0 {
		return true, nil
	}

	u, err := user.Current()
	if err != nil {
		return false, fmt.Errorf("could not get current user: %w", err)
	}

	group, err := user.LookupGroup("plugdev")
	if err != nil {
		return false, fmt.Errorf("error looking up plugdev group: %w", err)
	}

	groupIDs, err := u.GroupIds()
	if err != nil {
		return false, fmt.Errorf("error getting user group IDs: %w", err)
	}

	if Debug {
		fmt.Printf("[DEBUG] group.Gid, groupIDs: %s %v\n", group.Gid, groupIDs)
	}

	for _, gid := range groupIDs {
		if gid == group.Gid {
			// user is confirmed to be in the group
			return true, nil
		}
	}

	// user does not appear to be in the group
	return false, nil
}
