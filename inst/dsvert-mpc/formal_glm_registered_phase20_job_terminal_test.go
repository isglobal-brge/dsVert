package main

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func formalGLMRegisteredPhase20JobTerminalTestComputeV1(
	t *testing.T, fixture *formalGLMRegisteredPhase20JobComputeTestFixtureV1,
) (func(), <-chan error) {
	t.Helper()
	if _, err := fixture.owners[0].RunTerminalV1(); err == nil {
		t.Fatal("terminal selection ran before the registered compute")
	}
	if err := fixture.owners[0].RunComputeV1(
		fixture.providers[0], fixture.ingress[0]); err == nil {
		t.Fatal("job compute ran before the peer epoch was bound")
	}
	fixture.bind(t)
	stop := make(chan struct{})
	errs := make(chan error, 2)
	for index := range fixture.owners {
		go formalGLMRegisteredPhase20JobComputeTestRelayV1(
			stop, fixture.owners[index], fixture.owners[1-index], errs)
	}
	var run [2]error
	finished := make(chan int, 2)
	for index := range fixture.owners {
		go func(index int) {
			run[index] = fixture.owners[index].RunComputeV1(
				fixture.providers[index], fixture.ingress[index])
			finished <- index
		}(index)
	}
	aborted := false
	abort := func() {
		if !aborted {
			close(stop)
			aborted = true
		}
		for _, owner := range fixture.owners {
			owner.mu.Lock()
			controller := owner.controller
			owner.mu.Unlock()
			if controller != nil {
				go func() { _ = controller.Close() }()
			}
		}
	}
	var first int
	select {
	case first = <-finished:
	case relayErr := <-errs:
		abort()
		select {
		case <-finished:
		case <-time.After(30 * time.Second):
		}
		t.Fatalf("relay failed before compute completed: %v", relayErr)
	}
	if run[first] != nil {
		abort()
		select {
		case second := <-finished:
			t.Fatalf("registered job compute failed: %v / %v", run[first], run[second])
		case <-time.After(30 * time.Second):
			t.Fatalf("registered job compute left peer blocked after: %v", run[first])
		}
	}
	<-finished
	if run[0] != nil || run[1] != nil {
		abort()
		t.Fatalf("registered job compute failed: %v / %v", run[0], run[1])
	}
	return abort, errs
}

func TestFormalGLMRegisteredPhase20JobTerminalK2K3K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase20JobComputeTestBuild(t, custodians, 4)
			stopRelay, errs := formalGLMRegisteredPhase20JobTerminalTestComputeV1(t, fixture)
			defer stopRelay()
			var commits [2]formalGLMPhase20HandoffCommit
			var run [2]error
			finished := make(chan int, 2)
			for index := range fixture.owners {
				go func(index int) {
					commits[index], run[index] = fixture.owners[index].RunTerminalV1()
					finished <- index
				}(index)
			}
			for range fixture.owners {
				select {
				case <-finished:
				case relayErr := <-errs:
					t.Fatalf("relay failed while selecting terminal: %v", relayErr)
				case <-time.After(30 * time.Second):
					t.Fatal("registered terminal selection left a peer blocked")
				}
			}
			for index, owner := range fixture.owners {
				if run[index] != nil || commits[index].Replayed ||
					!formalGLMIsSHA256(commits[index].SHA256) || commits[index].Bytes < 64 {
					t.Fatalf("terminal %d did not commit its handoff: %#v / %v",
						index, commits[index], run[index])
				}
				owner.mu.Lock()
				terminal := owner.terminal
				owner.mu.Unlock()
				if terminal == nil {
					t.Fatalf("terminal %d disappeared after selection", index)
				}
				status, err := terminal.LoadStatusV1()
				if err != nil || !status.draftSealed || status.selected == nil ||
					status.selected.OpeningsPerformed != 0 || status.selected.ProductionReady {
					t.Fatalf("terminal %d status: %#v / %v", index, status, err)
				}
				handoff := formalGLMRegisteredPhase20HandoffAdapterTestOpenV1(t, terminal)
				source, durable, err := handoff.Load()
				if err != nil || durable.SHA256 != commits[index].SHA256 ||
					durable.Bytes != commits[index].Bytes || source.Result.Peer != fixture.owners[index].terminal.peer {
					source.clear()
					t.Fatalf("terminal %d handoff did not rehydrate: %#v / %v", index, durable, err)
				}
				source.clear()
				encoded, err := json.Marshal(owner)
				if err != nil || string(encoded) != "{}" {
					t.Fatalf("terminal %d owner exposed private state: %s / %v", index, encoded, err)
				}
			}
			var replay [2]formalGLMPhase20HandoffCommit
			var replayErr [2]error
			replayed := make(chan int, 2)
			for index := range fixture.owners {
				go func(index int) {
					replay[index], replayErr[index] = fixture.owners[index].RunTerminalV1()
					replayed <- index
				}(index)
			}
			for range fixture.owners {
				select {
				case <-replayed:
				case relayErr := <-errs:
					t.Fatalf("relay failed while replaying terminal selection: %v", relayErr)
				case <-time.After(30 * time.Second):
					t.Fatal("terminal replay left a peer blocked")
				}
			}
			for index := range fixture.owners {
				if replayErr[index] != nil || !replay[index].Replayed ||
					replay[index].SHA256 != commits[index].SHA256 ||
					replay[index].Bytes != commits[index].Bytes {
					t.Fatalf("terminal %d replay changed the sticky handoff: %#v / %v",
						index, replay[index], replayErr[index])
				}
			}
			select {
			case relayErr := <-errs:
				t.Fatalf("relay failed after terminal selection: %v", relayErr)
			default:
			}
		})
	}
}
