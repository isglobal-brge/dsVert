package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func formalTypedFinalizerLifecycleCaptureStdout(t *testing.T,
	run func() error,
) (string, error) {
	t.Helper()
	prior := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	runErr := run()
	_ = writer.Close()
	os.Stdout = prior
	encoded, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(encoded), runErr
}

func formalTypedFinalizerLifecycleTestStateRoot(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(base, "state")
}

func formalTypedFinalizerLifecycleTestConfig(t *testing.T, stateRoot,
	peer, family, action string,
) string {
	t.Helper()
	root := filepath.Join(stateRoot, peer)
	if err := os.MkdirAll(filepath.Join(root, "commands"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{stateRoot, root, filepath.Join(root, "commands")} {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	request := formalTypedFinalizerLifecycleRequest{
		Version: formalTypedFinalizerLifecycleVersion,
		Family:  family, Action: action,
		Operation: json.RawMessage(`{"peer_name":"` + peer +
			`","padding":"0123456789abcdef0123456789abcdef"}`),
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "commands", "request.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFormalTypedFinalizerLifecycleOuterAcceptsOnlyClosedCommands(t *testing.T) {
	stateRoot := formalTypedFinalizerLifecycleTestStateRoot(t)
	valid := []struct {
		family string
		action string
	}{
		{formalFinalizerHandoffFamilyGLM,
			formalGLMPhase21RockActionVerifyCandidate},
		{formalFinalizerHandoffFamilyCox,
			formalCoxBlockwiseRockActionPreparePublication},
	}
	for _, test := range valid {
		path := formalTypedFinalizerLifecycleTestConfig(
			t, stateRoot, "sitea", test.family, test.action)
		request, root, err := formalTypedFinalizerLifecycleReadRequestAtRoot(
			path, stateRoot)
		if err != nil {
			t.Fatalf("valid %s command rejected: %v", test.family, err)
		}
		if request.Family != test.family || request.Action != test.action ||
			root != filepath.Join(stateRoot, "sitea") {
			t.Fatalf("unexpected decoded command: %+v, root=%q", request, root)
		}
	}

	for _, test := range []struct {
		name   string
		family string
		action string
	}{
		{"unknown-family", "formal_other", formalGLMPhase21RockActionStage},
		{"unknown-glm-action", formalFinalizerHandoffFamilyGLM, "run-anything"},
		{"cross-family-action", formalFinalizerHandoffFamilyCox,
			formalGLMPhase21RockActionVerifyCandidate},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := formalTypedFinalizerLifecycleTestConfig(
				t, formalTypedFinalizerLifecycleTestStateRoot(t), "sitea",
				test.family, test.action)
			state := filepath.Dir(filepath.Dir(filepath.Dir(path)))
			if _, _, err := formalTypedFinalizerLifecycleReadRequestAtRoot(
				path, state); err == nil {
				t.Fatal("closed command envelope accepted unknown family/action")
			}
		})
	}
}

func TestFormalTypedFinalizerLifecycleOuterRejectsUnsafeConfig(t *testing.T) {
	writeRaw := func(t *testing.T, body []byte) (string, string) {
		t.Helper()
		state := formalTypedFinalizerLifecycleTestStateRoot(t)
		path := formalTypedFinalizerLifecycleTestConfig(
			t, state, "sitea", formalFinalizerHandoffFamilyGLM,
			formalGLMPhase21RockActionPreflight)
		if body != nil {
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return state, path
	}

	t.Run("outside-state-root", func(t *testing.T) {
		state, path := writeRaw(t, nil)
		other := filepath.Join(t.TempDir(), "outside.json")
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(other, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := formalTypedFinalizerLifecycleReadRequestAtRoot(
			other, state); err == nil {
			t.Fatal("config outside state root was accepted")
		}
	})

	t.Run("unknown-json", func(t *testing.T) {
		state, path := writeRaw(t, []byte(
			`{"version":"dsvert-typed-finalizer-lifecycle-v1",`+
				`"family":"formal_glm","action":"preflight-local",`+
				`"operation":{"padding":"0123456789abcdef0123456789abcdef"},`+
				`"unexpected":"secret-padding-to-exceed-minimum-record-size"}`))
		if _, _, err := formalTypedFinalizerLifecycleReadRequestAtRoot(
			path, state); err == nil {
			t.Fatal("unknown outer JSON field was accepted")
		}
	})

	t.Run("trailing-json", func(t *testing.T) {
		state, path := writeRaw(t, nil)
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, []byte(` {"secret":"must-not-parse"}`)...)
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := formalTypedFinalizerLifecycleReadRequestAtRoot(
			path, state); err == nil {
			t.Fatal("trailing JSON was accepted")
		}
	})

	t.Run("non-object-operation", func(t *testing.T) {
		state, path := writeRaw(t, []byte(
			`{"version":"dsvert-typed-finalizer-lifecycle-v1",`+
				`"family":"formal_glm","action":"preflight-local",`+
				`"operation":"0123456789abcdef0123456789abcdef0123456789abcdef"}`))
		if _, _, err := formalTypedFinalizerLifecycleReadRequestAtRoot(
			path, state); err == nil {
			t.Fatal("non-object operation was accepted")
		}
	})

	for _, mode := range []os.FileMode{0o644, 0o660} {
		t.Run("file-mode-"+mode.String(), func(t *testing.T) {
			state, path := writeRaw(t, nil)
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if _, _, err := formalTypedFinalizerLifecycleReadRequestAtRoot(
				path, state); err == nil {
				t.Fatal("non-owner-only config was accepted")
			}
		})
	}

	t.Run("hardlink", func(t *testing.T) {
		state, path := writeRaw(t, nil)
		link := filepath.Join(filepath.Dir(path), "linked.json")
		if err := os.Link(path, link); err != nil {
			t.Fatal(err)
		}
		if _, _, err := formalTypedFinalizerLifecycleReadRequestAtRoot(
			path, state); err == nil {
			t.Fatal("hard-linked config was accepted")
		}
	})

	t.Run("file-symlink", func(t *testing.T) {
		state, path := writeRaw(t, nil)
		link := filepath.Join(filepath.Dir(path), "linked.json")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, _, err := formalTypedFinalizerLifecycleReadRequestAtRoot(
			link, state); err == nil {
			t.Fatal("symbolic-linked config was accepted")
		}
	})

	t.Run("authority-root-symlink", func(t *testing.T) {
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		state := filepath.Join(base, "state")
		targetState := filepath.Join(base, "target")
		path := formalTypedFinalizerLifecycleTestConfig(
			t, targetState, "sitea", formalFinalizerHandoffFamilyGLM,
			formalGLMPhase21RockActionPreflight)
		if err := os.Mkdir(state, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(targetState, "sitea"),
			filepath.Join(state, "sitea")); err != nil {
			t.Fatal(err)
		}
		redirected := filepath.Join(state, "sitea", "commands", filepath.Base(path))
		if _, _, err := formalTypedFinalizerLifecycleReadRequestAtRoot(
			redirected, state); err == nil {
			t.Fatal("redirected authority root was accepted")
		}
	})

	t.Run("intermediate-state-symlink", func(t *testing.T) {
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		realParent := filepath.Join(base, "real-parent")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		linkParent := filepath.Join(base, "linked-parent")
		if err := os.Symlink(realParent, linkParent); err != nil {
			t.Fatal(err)
		}
		state := filepath.Join(linkParent, "state")
		path := formalTypedFinalizerLifecycleTestConfig(
			t, state, "sitea", formalFinalizerHandoffFamilyGLM,
			formalGLMPhase21RockActionPreflight)
		if _, _, err := formalTypedFinalizerLifecycleReadRequestAtRoot(
			path, state); err == nil {
			t.Fatal("intermediate state-root symlink was accepted")
		}
	})

	t.Run("directory-mode", func(t *testing.T) {
		state, path := writeRaw(t, nil)
		root := filepath.Dir(filepath.Dir(path))
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, _, err := formalTypedFinalizerLifecycleReadRequestAtRoot(
			path, state); err == nil {
			t.Fatal("non-owner-only authority root was accepted")
		}
	})
}

func TestFormalTypedFinalizerLifecycleRequiresMatchingAuthorityRoot(t *testing.T) {
	state := formalTypedFinalizerLifecycleTestStateRoot(t)
	path := formalTypedFinalizerLifecycleTestConfig(
		t, state, "sitea", formalFinalizerHandoffFamilyGLM,
		formalGLMPhase21RockActionPreflight)
	_, root, err := formalTypedFinalizerLifecycleReadRequestAtRoot(path, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalTypedFinalizerLifecycleRequireLocalAuthority(
		root, state, "sitea"); err != nil {
		t.Fatalf("matching authority root rejected: %v", err)
	}
	for _, peer := range []string{"siteb", "../sitea", "sitea/child"} {
		if err := formalTypedFinalizerLifecycleRequireLocalAuthority(
			root, state, peer); err == nil {
			t.Fatalf("authority root accepted peer %q", peer)
		}
	}
}

func TestFormalTypedFinalizerLifecycleDispatchRemovesOnlyAfterSuccess(t *testing.T) {
	for _, family := range []string{
		formalFinalizerHandoffFamilyGLM,
		formalFinalizerHandoffFamilyCox,
	} {
		t.Run(family, func(t *testing.T) {
			state := formalTypedFinalizerLifecycleTestStateRoot(t)
			action := formalGLMPhase21RockActionPreflight
			if family == formalFinalizerHandoffFamilyCox {
				action = formalCoxBlockwiseRockActionPreflight
			}
			path := formalTypedFinalizerLifecycleTestConfig(
				t, state, "sitea", family, action)
			calls := []string{}
			glm := func(root, gotAction string, operation json.RawMessage) error {
				calls = append(calls, formalFinalizerHandoffFamilyGLM)
				if root != filepath.Join(state, "sitea") || gotAction != action ||
					len(operation) == 0 {
					return fmt.Errorf("private glm dispatch mismatch")
				}
				output(map[string]string{"state": "committed"})
				return nil
			}
			cox := func(root, gotAction string, operation json.RawMessage) error {
				calls = append(calls, formalFinalizerHandoffFamilyCox)
				if root != filepath.Join(state, "sitea") || gotAction != action ||
					len(operation) == 0 {
					return fmt.Errorf("private cox dispatch mismatch")
				}
				output(map[string]string{"state": "committed"})
				return nil
			}
			stdout, err := formalTypedFinalizerLifecycleCaptureStdout(t,
				func() error {
					return formalTypedFinalizerLifecycleDispatchAtRoot(
						path, state, glm, cox)
				})
			if err != nil {
				t.Fatal(err)
			}
			if len(calls) != 1 || calls[0] != family {
				t.Fatalf("wrong family handler: %v", calls)
			}
			if fileExists(path) {
				t.Fatal("successful lifecycle config was retained")
			}
			if stdout != "{\"state\":\"committed\"}\n" ||
				strings.Contains(stdout, "padding") {
				t.Fatalf("unexpected lifecycle stdout: %q", stdout)
			}
		})
	}
}

func TestFormalTypedFinalizerLifecycleDispatchRetainsFailedRetry(t *testing.T) {
	state := formalTypedFinalizerLifecycleTestStateRoot(t)
	path := formalTypedFinalizerLifecycleTestConfig(
		t, state, "sitea", formalFinalizerHandoffFamilyGLM,
		formalGLMPhase21RockActionPreflight)
	fail := func(root, action string, operation json.RawMessage) error {
		return fmt.Errorf("private-key-material-must-not-escape")
	}
	unused := func(root, action string, operation json.RawMessage) error {
		t.Fatal("wrong family handler called")
		return nil
	}
	stdout, err := formalTypedFinalizerLifecycleCaptureStdout(t, func() error {
		return formalTypedFinalizerLifecycleDispatchAtRoot(
			path, state, fail, unused)
	})
	if err == nil || err.Error() != "typed-finalizer-lifecycle: action failed" {
		t.Fatalf("failure was not coarse: %v", err)
	}
	if stdout != "" || !fileExists(path) {
		t.Fatal("failed lifecycle leaked output or removed retry config")
	}

	succeed := func(root, action string, operation json.RawMessage) error {
		output(map[string]string{"state": "replayed"})
		return nil
	}
	if err := formalTypedFinalizerLifecycleDispatchAtRoot(
		path, state, succeed, unused); err != nil {
		t.Fatal(err)
	}
	if fileExists(path) {
		t.Fatal("successful retry retained its config")
	}
}
