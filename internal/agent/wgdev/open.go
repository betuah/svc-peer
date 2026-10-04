package wgdev

import (
	"fmt"
	"runtime"
)

// Open selects a backend. Prefer kernel on Linux when available; otherwise wireguard-go.
func Open(preference string) (Device, error) {
	switch preference {
	case BackendKernel:
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("kernel WireGuard only supported on linux (got %s)", runtime.GOOS)
		}
		return NewKernelDevice()
	case BackendUserspace:
		return NewUserspaceDevice()
	case BackendAuto, "":
		if runtime.GOOS == "linux" && KernelAvailable() {
			d, err := NewKernelDevice()
			if err == nil {
				return d, nil
			}
		}
		return NewUserspaceDevice()
	default:
		return nil, fmt.Errorf("unknown wg backend %q", preference)
	}
}
