package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"github.com/markkurossi/mpc/circuit"
)

// Optional server-private acceleration. No source share, mask or noise is cached.
// The key authenticates public topology bytes; it never enters a peer transcript.
type crossGridCircuitCache struct {
	Directory string `json:"directory"`
	Key       string `json:"key"`
}

func crossGridKernelPrepareCached(p crossGridKernelPlan, cache *crossGridCircuitCache) (*crossGridKernelPrepared, error) {
	if cache == nil {
		return crossGridKernelPrepare(p)
	}
	source, err := crossGridKernelSource(p)
	if err != nil {
		return nil, errCrossGridKernel
	}
	key, err := exactGCStrictBase64(cache.Key, 32)
	if err != nil {
		return nil, errCrossGridKernel
	}
	defer clear(key)
	// Bump this domain when compiler/optimizer semantics change. The generated
	// source binds the pinned profile, geometry and every public loss cap.
	digest := sha256.Sum256([]byte("cross-grid-circuit-cache-v1/c911bbd029d1/pw-opt-v2\x00" + source))
	name := hex.EncodeToString(digest[:]) + ".circuit"
	dir := cache.Directory
	info, err := os.Lstat(dir)
	if err != nil || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir ||
		!info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(info) {
		return nil, errCrossGridKernel
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errCrossGridKernel
	}
	defer root.Close()
	mac := func(data []byte) []byte {
		h := hmac.New(sha256.New, key)
		h.Write(digest[:])
		h.Write(data)
		return h.Sum(nil)
	}
	info, err = root.Lstat(name)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
			!exactGCPrivateOwnedRegular(info) || info.Size() < 32 || info.Size() > 512<<20 {
			return nil, errCrossGridKernel
		}
		f, e := root.Open(name)
		if e != nil {
			return nil, errCrossGridKernel
		}
		actual, e := f.Stat()
		if e != nil || !os.SameFile(info, actual) {
			f.Close()
			return nil, errCrossGridKernel
		}
		data, e := io.ReadAll(io.LimitReader(f, (512<<20)+1))
		f.Close()
		if e != nil || len(data) < 32 || len(data) > 512<<20 || !hmac.Equal(data[:32], mac(data[32:])) {
			return nil, errCrossGridKernel
		}
		c, e := circuit.ParseMPCLC(bytes.NewReader(data[32:]))
		if e != nil {
			return nil, errCrossGridKernel
		}
		return crossGridKernelPreparedCircuit(p, c)
	}
	if !os.IsNotExist(err) {
		return nil, errCrossGridKernel
	}
	prepared, err := crossGridKernelPrepare(p)
	if err != nil {
		return nil, errCrossGridKernel
	}
	var data bytes.Buffer
	if prepared.circuit.Marshal(&data) != nil || data.Len()+32 > 512<<20 {
		return nil, errCrossGridKernel
	}
	f, err := os.CreateTemp(dir, ".circuit-")
	if err != nil {
		return nil, errCrossGridKernel
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if _, err = f.Write(mac(data.Bytes())); err == nil {
		_, err = f.Write(data.Bytes())
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || root.Rename(filepath.Base(temporary), name) != nil {
		return nil, errCrossGridKernel
	}
	return prepared, nil
}
