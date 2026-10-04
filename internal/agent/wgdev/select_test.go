// Unit tests: SelectBackend kernel-first policy (no device open).

package wgdev_test

import (
	"testing"

	"github.com/betuah/svc-peer/internal/agent/wgdev"
)

func TestSelectBackendAutoPrefersKernelOnLinux(t *testing.T) {
	backend, reason, err := wgdev.SelectBackend(wgdev.BackendAuto, "linux", true)
	if err != nil {
		t.Fatal(err)
	}
	if backend != wgdev.BackendKernel {
		t.Fatalf("got %q want kernel; reason=%s", backend, reason)
	}
}

func TestSelectBackendAutoFallsBackWithoutKernel(t *testing.T) {
	backend, reason, err := wgdev.SelectBackend("", "linux", false)
	if err != nil {
		t.Fatal(err)
	}
	if backend != wgdev.BackendUserspace {
		t.Fatalf("got %q want userspace; reason=%s", backend, reason)
	}
}

func TestSelectBackendAutoNonLinuxUsesUserspace(t *testing.T) {
	for _, goos := range []string{"windows", "darwin"} {
		backend, _, err := wgdev.SelectBackend(wgdev.BackendAuto, goos, false)
		if err != nil {
			t.Fatal(err)
		}
		if backend != wgdev.BackendUserspace {
			t.Fatalf("%s: got %q want userspace", goos, backend)
		}
	}
}

func TestSelectBackendKernelForcedRequiresAvailability(t *testing.T) {
	if _, _, err := wgdev.SelectBackend(wgdev.BackendKernel, "linux", false); err == nil {
		t.Fatal("expected error when kernel forced but unavailable")
	}
	if _, _, err := wgdev.SelectBackend(wgdev.BackendKernel, "windows", true); err == nil {
		t.Fatal("expected error for kernel on windows")
	}
	backend, _, err := wgdev.SelectBackend(wgdev.BackendKernel, "linux", true)
	if err != nil || backend != wgdev.BackendKernel {
		t.Fatalf("got backend=%q err=%v", backend, err)
	}
}

func TestSelectBackendExplicitUserspace(t *testing.T) {
	backend, _, err := wgdev.SelectBackend(wgdev.BackendUserspace, "linux", true)
	if err != nil {
		t.Fatal(err)
	}
	if backend != wgdev.BackendUserspace {
		t.Fatalf("got %q", backend)
	}
}

func TestSelectBackendUnknown(t *testing.T) {
	if _, _, err := wgdev.SelectBackend("bogus", "linux", true); err == nil {
		t.Fatal("expected error")
	}
}
