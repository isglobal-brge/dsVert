package main

// Owner-only provisioning for one live registered GLM job host.  The command
// is server-local: its input is a custodian bootstrap already bound to a
// signed source contract.  It persists that bootstrap in the one derived Rock
// slot and returns only a non-secret selector; it neither starts computation
// nor exposes a socket, path, key, source, or statistical result.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	formalGLMRegisteredPhase20JobControlHostProvisionVersionV1 = "dsvert-formal-glm-registered-phase20-job-host-provision-v1"
	formalGLMRegisteredPhase20JobControlHostProvisionDirV1     = "formal-glm-registered-phase20-job-host-v1"
	formalGLMRegisteredPhase20JobControlHostProvisionFileV1    = "host-config.json"
	formalGLMRegisteredPhase20JobControlHostProvisionTempV1    = ".host-config.next"
	formalGLMRegisteredPhase20JobControlHostProvisionMaxV1     = 16 << 20
)

type formalGLMRegisteredPhase20JobControlHostProvisionV1 struct {
	Version string                                           `json:"version"`
	Config  formalGLMRegisteredPhase20JobControlHostConfigV1 `json:"config"`
}

type formalGLMRegisteredPhase20JobControlHostProvisionReceiptV1 struct {
	Version          string `json:"version"`
	Peer             string `json:"peer"`
	ArtifactID       string `json:"artifact_id"`
	ReceiptSetSHA256 string `json:"receipt_set_sha256"`
	ConfigSHA256     string `json:"config_sha256"`
	Replayed         bool   `json:"replayed"`
	ProductionReady  bool   `json:"production_ready"`
}

func formalGLMRegisteredPhase20JobControlHostProvisionRelativePathV1(
	peer, artifactID, receiptSetSHA256 string,
) (string, error) {
	if !formalGLMRegistryLabelV1(peer, 128) ||
		!formalGLMIsSHA256(artifactID) || !formalGLMIsSHA256(receiptSetSHA256) {
		return "", fmt.Errorf("formal-glm registered Phase20 job host provision: invalid selector")
	}
	return filepath.Join(formalGLMRegisteredPhase20JobControlHostProvisionDirV1,
		peer, artifactID, receiptSetSHA256,
		formalGLMRegisteredPhase20JobControlHostProvisionFileV1), nil
}

func formalGLMRegisteredPhase20JobControlHostProvisionPathV1(
	rockRoot, peer, artifactID, receiptSetSHA256 string,
) (string, error) {
	if !filepath.IsAbs(rockRoot) || filepath.Clean(rockRoot) != rockRoot {
		return "", fmt.Errorf("formal-glm registered Phase20 job host provision: invalid Rock root")
	}
	relative, err := formalGLMRegisteredPhase20JobControlHostProvisionRelativePathV1(
		peer, artifactID, receiptSetSHA256)
	if err != nil {
		return "", err
	}
	return filepath.Join(rockRoot, relative), nil
}

func formalGLMRegisteredPhase20JobControlHostProvisionConfigIdentityV1(
	config formalGLMRegisteredPhase20JobControlHostConfigV1,
) (string, string, string, error) {
	if err := formalGLMRegisteredPhase20JobControlHostValidateV1(config); err != nil {
		return "", "", "", err
	}
	return config.Peer, config.Start.ArtifactID, config.Start.ReceiptSetSHA256, nil
}

func formalGLMRegisteredPhase20JobControlHostProvisionEncodeConfigV1(
	config formalGLMRegisteredPhase20JobControlHostConfigV1,
) ([]byte, error) {
	if _, _, _, err := formalGLMRegisteredPhase20JobControlHostProvisionConfigIdentityV1(config); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(config)
	if err != nil || len(encoded) < 64 || len(encoded) > formalGLMRegisteredPhase20JobControlHostProvisionMaxV1 {
		clear(encoded)
		return nil, fmt.Errorf("formal-glm registered Phase20 job host provision: invalid bootstrap")
	}
	return encoded, nil
}

func formalGLMRegisteredPhase20JobControlHostProvisionDecodeConfigV1(
	encoded []byte,
) (formalGLMRegisteredPhase20JobControlHostConfigV1, error) {
	var config formalGLMRegisteredPhase20JobControlHostConfigV1
	if len(encoded) < 64 || len(encoded) > formalGLMRegisteredPhase20JobControlHostProvisionMaxV1 ||
		encoded[0] != '{' {
		return config, fmt.Errorf("formal-glm registered Phase20 job host provision: invalid bootstrap")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		formalGLMRegisteredPhase20JobControlHostClearConfigV1(&config)
		return formalGLMRegisteredPhase20JobControlHostConfigV1{},
			fmt.Errorf("formal-glm registered Phase20 job host provision: invalid bootstrap")
	}
	var trailing any
	canonical, err := json.Marshal(config)
	if err != nil || decoder.Decode(&trailing) != io.EOF || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		formalGLMRegisteredPhase20JobControlHostClearConfigV1(&config)
		return formalGLMRegisteredPhase20JobControlHostConfigV1{},
			fmt.Errorf("formal-glm registered Phase20 job host provision: non-canonical bootstrap")
	}
	clear(canonical)
	if _, _, _, err := formalGLMRegisteredPhase20JobControlHostProvisionConfigIdentityV1(config); err != nil {
		formalGLMRegisteredPhase20JobControlHostClearConfigV1(&config)
		return formalGLMRegisteredPhase20JobControlHostConfigV1{}, err
	}
	return config, nil
}

func formalGLMRegisteredPhase20JobControlHostProvisionDecodeV1(
	encoded []byte,
) (formalGLMRegisteredPhase20JobControlHostProvisionV1, error) {
	var command formalGLMRegisteredPhase20JobControlHostProvisionV1
	if len(encoded) < 64 || len(encoded) > formalGLMRegisteredPhase20JobControlHostProvisionMaxV1 ||
		encoded[0] != '{' {
		return command, fmt.Errorf("formal-glm registered Phase20 job host provision: invalid command")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		formalGLMRegisteredPhase20JobControlHostClearConfigV1(&command.Config)
		return formalGLMRegisteredPhase20JobControlHostProvisionV1{},
			fmt.Errorf("formal-glm registered Phase20 job host provision: invalid command")
	}
	var trailing any
	canonical, err := json.Marshal(command)
	if err != nil || decoder.Decode(&trailing) != io.EOF || !bytes.Equal(canonical, encoded) ||
		command.Version != formalGLMRegisteredPhase20JobControlHostProvisionVersionV1 {
		clear(canonical)
		formalGLMRegisteredPhase20JobControlHostClearConfigV1(&command.Config)
		return formalGLMRegisteredPhase20JobControlHostProvisionV1{},
			fmt.Errorf("formal-glm registered Phase20 job host provision: non-canonical command")
	}
	clear(canonical)
	if _, _, _, err := formalGLMRegisteredPhase20JobControlHostProvisionConfigIdentityV1(command.Config); err != nil {
		formalGLMRegisteredPhase20JobControlHostClearConfigV1(&command.Config)
		return formalGLMRegisteredPhase20JobControlHostProvisionV1{}, err
	}
	return command, nil
}

func formalGLMRegisteredPhase20JobControlHostProvisionReadConfigV1(
	root *os.Root, relative string,
) (formalGLMRegisteredPhase20JobControlHostConfigV1, []byte, error) {
	var zero formalGLMRegisteredPhase20JobControlHostConfigV1
	if root == nil || filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return zero, nil, fmt.Errorf("formal-glm registered Phase20 job host provision: invalid bootstrap location")
	}
	info, err := root.Lstat(relative)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(info) {
		return zero, nil, fmt.Errorf("formal-glm registered Phase20 job host provision: unsafe bootstrap")
	}
	encoded, err := formalGLMPhase21RootReadRecord(root, relative,
		formalGLMRegisteredPhase20JobControlHostProvisionMaxV1)
	if err != nil {
		return zero, nil, fmt.Errorf("formal-glm registered Phase20 job host provision: unreadable bootstrap")
	}
	config, err := formalGLMRegisteredPhase20JobControlHostProvisionDecodeConfigV1(encoded)
	if err != nil {
		clear(encoded)
		return zero, nil, err
	}
	return config, encoded, nil
}

func formalGLMRegisteredPhase20JobControlHostProvisionPrivateFileV1(
	info os.FileInfo,
) bool {
	return info != nil && info.Mode().IsRegular() &&
		info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o600 &&
		exactGCPrivateOwnedRegular(info)
}

// Commit uses one deterministic temporary in the derived slot.  A crash can
// therefore leave at most that one file; the next holder of the provision lock
// either removes it or finishes the linked target before any config is read.
func formalGLMRegisteredPhase20JobControlHostProvisionCommitV1(
	root *os.Root, relative, artifactID string, encoded []byte,
) (bool, error) {
	if root == nil || !formalGLMIsSHA256(artifactID) ||
		filepath.IsAbs(relative) || filepath.Clean(relative) != relative ||
		len(encoded) < 64 || len(encoded) > formalGLMRegisteredPhase20JobControlHostProvisionMaxV1 {
		return false, fmt.Errorf("formal-glm registered Phase20 job host provision: invalid bootstrap commit")
	}
	lock, err := formalFinalizerHandoffAcquireAuthorityLock(root, artifactID)
	if err != nil {
		return false, fmt.Errorf("formal-glm registered Phase20 job host provision: bootstrap lock unavailable")
	}
	defer func() {
		_ = formalFinalizerHandoffUnlockAuthority(lock)
		_ = lock.Close()
	}()
	temporary := filepath.Join(filepath.Dir(relative),
		formalGLMRegisteredPhase20JobControlHostProvisionTempV1)
	target, targetErr := root.Lstat(relative)
	temp, tempErr := root.Lstat(temporary)
	if targetErr != nil && !os.IsNotExist(targetErr) {
		return false, targetErr
	}
	if tempErr != nil && !os.IsNotExist(tempErr) {
		return false, tempErr
	}
	if tempErr == nil {
		if targetErr == nil && os.SameFile(target, temp) {
			if !target.Mode().IsRegular() || target.Mode()&os.ModeSymlink != 0 ||
				target.Mode().Perm() != 0o600 || !temp.Mode().IsRegular() ||
				temp.Mode()&os.ModeSymlink != 0 || temp.Mode().Perm() != 0o600 {
				return false, fmt.Errorf("formal-glm registered Phase20 job host provision: unsafe linked bootstrap")
			}
		} else if !formalGLMRegisteredPhase20JobControlHostProvisionPrivateFileV1(temp) {
			return false, fmt.Errorf("formal-glm registered Phase20 job host provision: unsafe bootstrap temporary")
		}
		if err := root.Remove(temporary); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		if err := formalGLMPhase21RootSyncDir(root, relative); err != nil {
			return false, err
		}
		target, targetErr = root.Lstat(relative)
		if targetErr != nil && !os.IsNotExist(targetErr) {
			return false, targetErr
		}
	}
	if targetErr == nil {
		if !formalGLMRegisteredPhase20JobControlHostProvisionPrivateFileV1(target) {
			return false, fmt.Errorf("formal-glm registered Phase20 job host provision: unsafe bootstrap")
		}
		return false, nil
	}
	file, err := root.OpenFile(temporary, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	if err := file.Chmod(0o600); err == nil {
		err = exactGCWriteFull(file, encoded)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return false, err
	}
	if closeErr != nil {
		return false, closeErr
	}
	temp, err = root.Lstat(temporary)
	if err != nil || !formalGLMRegisteredPhase20JobControlHostProvisionPrivateFileV1(temp) {
		return false, fmt.Errorf("formal-glm registered Phase20 job host provision: unsafe bootstrap temporary")
	}
	if err := root.Link(temporary, relative); err != nil {
		if !os.IsExist(err) {
			return false, err
		}
		if removeErr := root.Remove(temporary); removeErr != nil && !os.IsNotExist(removeErr) {
			return false, removeErr
		}
		if syncErr := formalGLMPhase21RootSyncDir(root, relative); syncErr != nil {
			return false, syncErr
		}
		return false, nil
	}
	if err := root.Remove(temporary); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := formalGLMPhase21RootSyncDir(root, relative); err != nil {
		return false, err
	}
	return true, nil
}

func formalGLMRegisteredPhase20JobControlHostProvisionRunAtRootV1(
	encoded []byte, rockRoot string,
) (formalGLMRegisteredPhase20JobControlHostProvisionReceiptV1, error) {
	var zero formalGLMRegisteredPhase20JobControlHostProvisionReceiptV1
	command, err := formalGLMRegisteredPhase20JobControlHostProvisionDecodeV1(encoded)
	if err != nil {
		return zero, err
	}
	defer formalGLMRegisteredPhase20JobControlHostClearConfigV1(&command.Config)
	peer, artifactID, receiptSetSHA256, err :=
		formalGLMRegisteredPhase20JobControlHostProvisionConfigIdentityV1(command.Config)
	if err != nil {
		return zero, err
	}
	relative, err := formalGLMRegisteredPhase20JobControlHostProvisionRelativePathV1(
		peer, artifactID, receiptSetSHA256)
	if err != nil {
		return zero, err
	}
	root, err := formalGLMRegisteredPhase18TicketStoreOpenRootV1(rockRoot)
	if err != nil {
		return zero, err
	}
	defer root.Close()
	if err := formalGLMPhase21EnsureRootPrivateDir(root, filepath.Dir(relative)); err != nil {
		return zero, err
	}
	bootstrap, err := formalGLMRegisteredPhase20JobControlHostProvisionEncodeConfigV1(command.Config)
	if err != nil {
		return zero, err
	}
	defer clear(bootstrap)
	sum := sha256.Sum256(bootstrap)
	created, err := formalGLMRegisteredPhase20JobControlHostProvisionCommitV1(
		root, relative, artifactID, bootstrap)
	if err != nil {
		return zero, err
	}
	persisted, persistedBytes, err := formalGLMRegisteredPhase20JobControlHostProvisionReadConfigV1(root, relative)
	if err != nil {
		return zero, err
	}
	defer formalGLMRegisteredPhase20JobControlHostClearConfigV1(&persisted)
	defer clear(persistedBytes)
	if !bytes.Equal(persistedBytes, bootstrap) {
		return zero, fmt.Errorf("formal-glm registered Phase20 job host provision: conflicting bootstrap")
	}
	persistedPeer, persistedArtifactID, persistedReceiptSetSHA256, err :=
		formalGLMRegisteredPhase20JobControlHostProvisionConfigIdentityV1(persisted)
	if err != nil || persistedPeer != peer || persistedArtifactID != artifactID ||
		persistedReceiptSetSHA256 != receiptSetSHA256 {
		return zero, fmt.Errorf("formal-glm registered Phase20 job host provision: conflicting bootstrap")
	}
	return formalGLMRegisteredPhase20JobControlHostProvisionReceiptV1{
		Version:          formalGLMRegisteredPhase20JobControlHostProvisionVersionV1,
		Peer:             peer,
		ArtifactID:       artifactID,
		ReceiptSetSHA256: receiptSetSHA256,
		ConfigSHA256:     fmt.Sprintf("%x", sum),
		Replayed:         !created,
		ProductionReady:  false,
	}, nil
}

func formalGLMRegisteredPhase20JobControlHostOpenProvisionedV1(
	rockRoot string, receipt formalGLMRegisteredPhase20JobControlHostProvisionReceiptV1,
) (*formalGLMRegisteredPhase20JobControlHostV1, error) {
	if receipt.Version != formalGLMRegisteredPhase20JobControlHostProvisionVersionV1 ||
		!formalGLMRegistryLabelV1(receipt.Peer, 128) ||
		!formalGLMIsSHA256(receipt.ArtifactID) ||
		!formalGLMIsSHA256(receipt.ReceiptSetSHA256) ||
		!formalGLMIsSHA256(receipt.ConfigSHA256) || receipt.ProductionReady {
		return nil, fmt.Errorf("formal-glm registered Phase20 job host provision: invalid receipt")
	}
	relative, err := formalGLMRegisteredPhase20JobControlHostProvisionRelativePathV1(
		receipt.Peer, receipt.ArtifactID, receipt.ReceiptSetSHA256)
	if err != nil {
		return nil, err
	}
	root, err := formalGLMRegisteredPhase18TicketStoreOpenRootV1(rockRoot)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	config, encoded, err := formalGLMRegisteredPhase20JobControlHostProvisionReadConfigV1(root, relative)
	if err != nil {
		return nil, err
	}
	defer formalGLMRegisteredPhase20JobControlHostClearConfigV1(&config)
	defer clear(encoded)
	sum := sha256.Sum256(encoded)
	peer, artifactID, receiptSetSHA256, err :=
		formalGLMRegisteredPhase20JobControlHostProvisionConfigIdentityV1(config)
	if err != nil || peer != receipt.Peer || artifactID != receipt.ArtifactID ||
		receiptSetSHA256 != receipt.ReceiptSetSHA256 ||
		fmt.Sprintf("%x", sum) != receipt.ConfigSHA256 {
		return nil, fmt.Errorf("formal-glm registered Phase20 job host provision: receipt mismatch")
	}
	return newFormalGLMRegisteredPhase20JobControlHostV1(rockRoot, config)
}

func formalGLMRegisteredPhase20JobControlHostProvisionReadCommandV1() ([]byte, error) {
	encoded, err := io.ReadAll(io.LimitReader(os.Stdin,
		int64(formalGLMRegisteredPhase20JobControlHostProvisionMaxV1)+1))
	if err != nil || len(encoded) > formalGLMRegisteredPhase20JobControlHostProvisionMaxV1 {
		clear(encoded)
		return nil, fmt.Errorf("formal-glm registered Phase20 job host provision: invalid command input")
	}
	return encoded, nil
}

func handleFormalGLMRegisteredPhase20JobControlHostProvisionV1() {
	encoded, err := formalGLMRegisteredPhase20JobControlHostProvisionReadCommandV1()
	if err != nil {
		mpcFatalError("formal-glm registered Phase20 job host provision failed")
	}
	defer clear(encoded)
	receipt, err := formalGLMRegisteredPhase20JobControlHostProvisionRunAtRootV1(
		encoded, formalFinalizerHandoffStateRoot)
	if err != nil {
		mpcFatalError("formal-glm registered Phase20 job host provision failed")
	}
	output(receipt)
}
