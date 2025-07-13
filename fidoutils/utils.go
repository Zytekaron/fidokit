package fidoutils

import (
	"fmt"
	"log"

	"github.com/keys-pub/go-libfido2"
)

func PrintConnectedDevices() {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		fmt.Println("Error getting devices:", err)
		return
	}
	if len(locs) == 0 {
		fmt.Println("No devices connected.")
		return
	}
	fmt.Println("Connected devices:")
	for i, loc := range locs {
		fmt.Println(i+1, "->", FormatDeviceName(loc))
	}
	fmt.Println()
}

func GetConnectedDeviceCount() int {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		log.Fatalln("device locations:", err)
	}
	return len(locs)
}

func FormatDeviceName(dev *libfido2.DeviceLocation) string {
	return fmt.Sprintf("[%s:%d] %s (%d)", dev.Manufacturer, dev.VendorID, dev.Product, dev.ProductID)
}

// Returns a list of devices based on libfido2.DeviceLocations()
func fido2GetDevices() ([]*libfido2.Device, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("getting device locations: %w", err)
	}
	devs := make([]*libfido2.Device, len(locs))
	for i, loc := range locs {
		dev, err := libfido2.NewDevice(loc.Path)
		if err != nil {
			return nil, fmt.Errorf("creating new device: %w", err)
		}
		devs[i] = dev
	}
	return devs, nil
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
