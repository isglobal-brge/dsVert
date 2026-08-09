package main

// The MPCL compiler normally locates its standard-library circuit files from
// a developer checkout.  Packaged dsvert-mpc binaries have no such checkout,
// so the exact joint-DP runner carries the narrowly required, version-pinned
// AES-128, HMAC-SHA256, and SHA-256 assets inside the executable.  They are
// expanded into a process-private directory before compilation.  These files
// contain public circuit definitions only; no peer input is ever written here.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const jointDPMPCLAssetVersion = "markkurossi-mpc-c911bbd029d1"

//go:embed third_party/mpcl-runtime-c911bbd029d1/crypto/*/*.gz
var jointDPMPCLAssetFS embed.FS

type jointDPMPCLAsset struct {
	embeddedPath string
	packagePath  string
	size         int64
	sha256Hex    string
}

var jointDPMPCLAssets = []jointDPMPCLAsset{
	{
		embeddedPath: "third_party/mpcl-runtime-c911bbd029d1/crypto/aes/circuit.mpcl.gz",
		packagePath:  "crypto/aes/circuit.mpcl",
		size:         1651,
		sha256Hex:    "ce4cf917e5d604f278184299004cd61c4d76ebd5f723afc2037cbca642e5f045",
	},
	{
		embeddedPath: "third_party/mpcl-runtime-c911bbd029d1/crypto/aes/aes_128.circ.gz",
		packagePath:  "crypto/aes/aes_128.circ",
		size:         906875,
		sha256Hex:    "f432558c8341a91a695f3a7d1377c78a76e51785a24c0f25ee555aa1319b22bb",
	},
	{
		embeddedPath: "third_party/mpcl-runtime-c911bbd029d1/crypto/hmac/sha256.mpcl.gz",
		packagePath:  "crypto/hmac/sha256.mpcl",
		size:         801,
		sha256Hex:    "d46e09846ffe17dc97a109dcacbb8130f3d4c37dec94a92a870b0bf7ca0fc1f2",
	},
	{
		embeddedPath: "third_party/mpcl-runtime-c911bbd029d1/crypto/sha256/sum.mpcl.gz",
		packagePath:  "crypto/sha256/sum.mpcl",
		size:         1446,
		sha256Hex:    "247e41a0e9a80da2fc93bfcc1647dca26c41e8f0eef7e9cde221406f32700a85",
	},
	{
		embeddedPath: "third_party/mpcl-runtime-c911bbd029d1/crypto/sha256/sha256.circ.gz",
		packagePath:  "crypto/sha256/sha256.circ",
		size:         3557037,
		sha256Hex:    "bd0a91bb7e97bb60c1468fe8caecc546af3f832bd4152d9c8c4e7527412dd11d",
	},
}

func jointDPMPCLManifestDigestFor(assets []jointDPMPCLAsset) [32]byte {
	h := sha256.New()
	write := func(value string) {
		_, _ = fmt.Fprintf(h, "%d:", len(value))
		_, _ = h.Write([]byte(value))
	}
	write(jointDPMPCLAssetVersion)
	for _, asset := range assets {
		write(asset.packagePath)
		write(strconv.FormatInt(asset.size, 10))
		write(asset.sha256Hex)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func jointDPMPCLManifestDigest() [32]byte {
	return jointDPMPCLManifestDigestFor(jointDPMPCLAssets)
}

var jointDPMPCLRuntimeMu sync.Mutex

type jointDPMPCLRuntimeLease struct {
	root        string
	tempParent  string
	previousEnv string
	hadEnv      bool
	closed      bool
}

// jointDPAcquireMPCLRuntime installs a process-global MPCLDIR only while the
// compiler is loading the embedded public circuits. The mutex is intentionally
// held for the complete lease because environment variables are process-wide.
// The lease retains the exact root returned by MkdirTemp; cleanup never trusts
// MPCLDIR or a caller-supplied path.
func jointDPAcquireMPCLRuntime() (*jointDPMPCLRuntimeLease, error) {
	jointDPMPCLRuntimeMu.Lock()
	tempParent, err := filepath.Abs(os.TempDir())
	if err != nil {
		jointDPMPCLRuntimeMu.Unlock()
		return nil, fmt.Errorf("resolve private MPCL parent: %w", err)
	}
	root, err := os.MkdirTemp(tempParent, "dsvert-mpcl-")
	if err != nil {
		jointDPMPCLRuntimeMu.Unlock()
		return nil, fmt.Errorf("create private MPCL root: %w", err)
	}
	cleanupFailure := func(cause error) (*jointDPMPCLRuntimeLease, error) {
		cleanupErr := jointDPRemoveMPCLRoot(root, tempParent)
		jointDPMPCLRuntimeMu.Unlock()
		if cleanupErr != nil {
			return nil, fmt.Errorf("%w; cleanup private MPCL root: %v", cause, cleanupErr)
		}
		return nil, cause
	}

	pkgRoot := filepath.Join(root, "pkg")
	for _, asset := range jointDPMPCLAssets {
		if err := jointDPExpandMPCLAsset(pkgRoot, asset); err != nil {
			return cleanupFailure(err)
		}
	}
	previous, hadPrevious := os.LookupEnv("MPCLDIR")
	if err := os.Setenv("MPCLDIR", root); err != nil {
		return cleanupFailure(fmt.Errorf("install private MPCL root: %w", err))
	}
	return &jointDPMPCLRuntimeLease{
		root: root, tempParent: tempParent,
		previousEnv: previous, hadEnv: hadPrevious,
	}, nil
}

func (lease *jointDPMPCLRuntimeLease) Close() error {
	if lease == nil || lease.closed {
		return fmt.Errorf("close inactive private MPCL runtime")
	}
	lease.closed = true
	var envErr error
	if lease.hadEnv {
		envErr = os.Setenv("MPCLDIR", lease.previousEnv)
	} else {
		envErr = os.Unsetenv("MPCLDIR")
	}
	cleanupErr := jointDPRemoveMPCLRoot(lease.root, lease.tempParent)
	lease.root = ""
	jointDPMPCLRuntimeMu.Unlock()
	if envErr != nil {
		return fmt.Errorf("restore MPCLDIR: %w", envErr)
	}
	if cleanupErr != nil {
		return fmt.Errorf("remove private MPCL root: %w", cleanupErr)
	}
	return nil
}

func jointDPRemoveMPCLRoot(root, tempParent string) error {
	root = filepath.Clean(root)
	tempParent = filepath.Clean(tempParent)
	if root == "." || tempParent == "." || filepath.Dir(root) != tempParent ||
		!strings.HasPrefix(filepath.Base(root), "dsvert-mpcl-") {
		return fmt.Errorf("refuse unsafe private MPCL cleanup target")
	}
	return os.RemoveAll(root)
}

func jointDPWithMPCLRuntime(fn func() error) (returnErr error) {
	lease, err := jointDPAcquireMPCLRuntime()
	if err != nil {
		return err
	}
	defer func() {
		if cleanupErr := lease.Close(); cleanupErr != nil {
			if returnErr == nil {
				returnErr = cleanupErr
			} else {
				returnErr = fmt.Errorf("%w; %v", returnErr, cleanupErr)
			}
		}
	}()
	return fn()
}

func jointDPExpandMPCLAsset(pkgRoot string, asset jointDPMPCLAsset) error {
	compressed, err := jointDPMPCLAssetFS.ReadFile(asset.embeddedPath)
	if err != nil {
		return fmt.Errorf("read embedded MPCL asset %s: %w", asset.packagePath, err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("decompress MPCL asset %s: %w", asset.packagePath, err)
	}
	destination := filepath.Join(pkgRoot, filepath.FromSlash(asset.packagePath))
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		_ = zr.Close()
		return fmt.Errorf("create MPCL package directory: %w", err)
	}
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = zr.Close()
		return fmt.Errorf("create MPCL asset %s: %w", asset.packagePath, err)
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(out, hash),
		io.LimitReader(zr, asset.size+1))
	closeErr := out.Close()
	gzipCloseErr := zr.Close()
	if copyErr != nil {
		return fmt.Errorf("expand MPCL asset %s: %w", asset.packagePath, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close MPCL asset %s: %w", asset.packagePath, closeErr)
	}
	if gzipCloseErr != nil {
		return fmt.Errorf("close compressed MPCL asset %s: %w", asset.packagePath, gzipCloseErr)
	}
	if written != asset.size {
		return fmt.Errorf("MPCL asset %s size mismatch: got %d, want %d",
			asset.packagePath, written, asset.size)
	}
	gotHash := hex.EncodeToString(hash.Sum(nil))
	if gotHash != asset.sha256Hex {
		return fmt.Errorf("MPCL asset %s digest mismatch", asset.packagePath)
	}
	return nil
}
