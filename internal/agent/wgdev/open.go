package wgdev

import (
	"fmt"
	"log/slog"
	"runtime"
	"strings"
)

// SelectBackend chooses the WireGuard backend without opening devices.
// Policy (locked): prefer kernel WireGuard when available; wireguard-go only as fallback.
//
//	auto/""  + linux  + kernelOK  → kernel
//	auto/""  + linux  + !kernelOK → userspace (fallback)
//	auto/""  + !linux             → userspace (kernel unavailable on platform)
//	kernel   + linux  + kernelOK  → kernel
//	kernel   + linux  + !kernelOK → error (do not silently fall back)
//	kernel   + !linux             → error
//	userspace                     → userspace (explicit override)
func SelectBackend(preference, goos string, kernelOK bool) (backend, reason string, err error) {
	pref := strings.ToLower(strings.TrimSpace(preference))
	if pref == "" {
		pref = BackendAuto
	}
	switch pref {
	case BackendAuto:
		if goos == "linux" && kernelOK {
			return BackendKernel, "linux with kernel WireGuard available", nil
		}
		if goos == "linux" {
			return BackendUserspace, "linux without kernel WireGuard; falling back to wireguard-go", nil
		}
		return BackendUserspace, fmt.Sprintf("%s has no kernel WireGuard; using wireguard-go", goos), nil

	case BackendKernel:
		if goos != "linux" {
			return "", "", fmt.Errorf("kernel WireGuard only supported on linux (got %s)", goos)
		}
		if !kernelOK {
			return "", "", fmt.Errorf("kernel WireGuard requested but not available (is the wireguard module loaded?)")
		}
		return BackendKernel, "explicit kernel preference", nil

	case BackendUserspace:
		return BackendUserspace, "explicit userspace preference", nil

	default:
		return "", "", fmt.Errorf("unknown wg backend %q (want auto|kernel|userspace)", preference)
	}
}

// Open selects and constructs a backend. Prefer kernel on Linux when available;
// use wireguard-go only when SelectBackend chooses userspace (never as a silent
// substitute when kernel was selected).
func Open(preference string) (Device, error) {
	return openWith(preference, runtime.GOOS, KernelAvailable(), slog.Default())
}

func openWith(preference, goos string, kernelOK bool, log *slog.Logger) (Device, error) {
	if log == nil {
		log = slog.Default()
	}
	backend, reason, err := SelectBackend(preference, goos, kernelOK)
	if err != nil {
		return nil, err
	}
	log.Info("wg backend selected", "backend", backend, "reason", reason, "preference", preference)

	switch backend {
	case BackendKernel:
		d, err := NewKernelDevice()
		if err != nil {
			// Do not fall back to userspace here: kernel was the selected backend.
			return nil, fmt.Errorf("open kernel WireGuard: %w", err)
		}
		return d, nil
	case BackendUserspace:
		return NewUserspaceDevice()
	default:
		return nil, fmt.Errorf("internal: unhandled backend %q", backend)
	}
}
