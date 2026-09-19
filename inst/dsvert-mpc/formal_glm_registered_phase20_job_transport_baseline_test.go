package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFormalGLMRegisteredPhase20TransportConcurrentOffsetReplacement(t *testing.T) {
	for _, operation := range []string{"validate", "read"} {
		t.Run(operation, func(t *testing.T) {
			root, _ := formalGLMRegisteredPhase20JobTransportTestRootV1(t)
			binding := formalGLMRegisteredPhase20JobTransportTestBindingV1("atomic-offset")
			transport := formalGLMRegisteredPhase20JobTransportTestOpenV1(t, root, binding, "local-peer-0",
				formalGLMRegisteredPhase20JobTransportTestEpochV1(
					formalGLMRegisteredPhase20JobRunTransportV1, "atomic-offset/basis"))
			head := filepath.Join(transport.scratchPath, "outbound.head")
			stop := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				for {
					select {
					case <-stop:
						done <- nil
						return
					default:
					}
					file, err := os.CreateTemp(transport.scratchPath, ".exact-gc-state-")
					if err != nil {
						done <- err
						return
					}
					name := file.Name()
					_, writeErr := file.WriteString("0")
					closeErr := file.Close()
					if writeErr != nil || closeErr != nil {
						_ = os.Remove(name)
						if writeErr != nil {
							done <- writeErr
						} else {
							done <- closeErr
						}
						return
					}
					if err := os.Rename(name, head); err != nil {
						_ = os.Remove(name)
						done <- err
						return
					}
				}
			}()
			t.Cleanup(func() {
				close(stop)
				if err := <-done; err != nil {
					t.Error(err)
				}
			})
			for iteration := 0; iteration < 3000; iteration++ {
				if operation == "validate" {
					if err := formalGLMRegisteredPhase20JobTransportValidateScratchV1(
						transport.scratch, transport.scratchPath, transport.segmentRoots); err != nil {
						t.Fatalf("valid atomic offset replacement at iteration %d: %v", iteration, err)
					}
				} else {
					if value, err := exactGCReadOffset(head); err != nil || value != 0 {
						t.Fatalf("read valid atomic offset replacement at iteration %d: %d / %v", iteration, value, err)
					}
				}
			}
		})
	}
}
