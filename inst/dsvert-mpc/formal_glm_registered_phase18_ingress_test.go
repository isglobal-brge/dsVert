package main

import (
	"bytes"
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

type formalGLMRegisteredPhase18IngressTestFixtureV3 struct {
	source        formalGLMSourceContractTestFixtureV1
	authorization formalGLMRegisteredPhase18AuthorizationV1
	frame         formalGLMRegisteredPhase18IngressFrameV3
	header        formalGLMRegisteredPhase18PrivateBlockHeaderV3
	coordinates   []*big.Int
	validity      []byte
	localKey      [32]byte
	recipientSK   []byte
	plaintext     []byte
	encoded       []byte
}

func TestFormalGLMRegisteredPhase18ValidationContextK2K5RepeatedChecksV3(
	t *testing.T,
) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18IngressTestBuild(t, custodians)
			context, err := formalGLMRegisteredPhase18NewValidationContextV3(
				fixture.source.contract,
				fixture.source.inputs.identities.public)
			if err != nil {
				t.Fatal(err)
			}
			if len(context.authorizations) != custodians {
				t.Fatalf("authorizations=%d, want %d",
					len(context.authorizations), custodians)
			}
			for index := 0; index < 4; index++ {
				frame, err := formalGLMRegisteredPhase18DecodeIngressFrameWithContextV3(
					fixture.encoded, context, fixture.frame.GlobalMaterializationRoot,
					fixture.localKey)
				if err != nil {
					t.Fatal(err)
				}
				plaintext, err := transportDecryptBytes(
					frame.Ciphertext, fixture.recipientSK)
				if err != nil {
					t.Fatal(err)
				}
				_, coordinates, validity, err :=
					formalGLMRegisteredPhase18DecodePrivateBlockWithContextV3(
						plaintext, frame, context,
						fixture.frame.GlobalMaterializationRoot)
				clear(plaintext)
				clear(frame.Ciphertext)
				if err != nil {
					t.Fatal(err)
				}
				for _, coordinate := range coordinates {
					coordinate.SetInt64(0)
				}
				clear(validity)
			}
		})
	}
}

func formalGLMRegisteredPhase18IngressTestSource(t testing.TB,
	custodians int,
) formalGLMSourceContractTestFixtureV1 {
	t.Helper()
	legacy := formalGLMPhase15TestPlan(
		t, "binomial", custodians, 4, 1, 9, 1)
	identities := formalGLMPhase15TestIdentitySet(
		t, legacy.Kernel.CustodianPeers)
	pinsetSHA256, err := formalGLMPhase16PinsetSHA256(identities.public)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Kernel.PinsetSHA256 = pinsetSHA256
	legacy.Kernel.SnapshotSHA256 = sha256Hex(
		[]byte(formalGLMPreSourceDescriptorTestSnapshotJSON))
	if err := validateFormalGLMPhase15Plan(legacy); err != nil {
		t.Fatal(err)
	}
	formula, err := formalGLMCanonicalQualifiedFormulaV1(
		legacy.Kernel.CustodianPeers[0] + "$outcome ~ 1")
	if err != nil {
		t.Fatal(err)
	}
	inputs := formalGLMRegisteredExecutionTestInputsForPlan(
		t, legacy, identities, func(model *formalGLMPreSourceModelCoreV1) {
			model.CanonicalQualifiedFormula = formula.Canonical
			model.FormulaSHA256 = formula.SHA256
			model.CoefficientOrder = []string{"(Intercept)"}
			model.TermMap = []formalGLMPublicTermV1{
				{Index: 0, Coefficient: "(Intercept)", Kind: "intercept"},
			}
			model.UsedColumns = append(
				[]formalGLMPreSourceColumnV1(nil), model.UsedColumns[:1]...)
		}, nil)
	plan := formalGLMRegisteredExecutionTestBuild(t, inputs)
	core, err := formalGLMBuildSourceContractCoreV1(
		inputs.entry, inputs.context.receipts, plan, inputs.contract,
		inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	approvals := make([]jointDPBiomedicalGaussianSignature, 0, custodians)
	for _, peer := range plan.CustodianPeers {
		approval, err := formalGLMSignSourceContractV1(
			core, peer, inputs.identities.private[peer],
			inputs.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		approvals = append(approvals, approval)
	}
	contract, err := formalGLMSealSourceContractV1(
		core, approvals, inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMSourceContractTestFixtureV1{
		inputs: inputs, plan: plan, core: core, contract: contract,
	}
}

func formalGLMRegisteredPhase18IngressTestBuild(t testing.TB,
	custodians int,
) formalGLMRegisteredPhase18IngressTestFixtureV3 {
	t.Helper()
	source := formalGLMRegisteredPhase18IngressTestSource(t, custodians)
	localPeer := source.plan.CustodianPeers[0]
	if custodians == 5 {
		for _, peer := range source.plan.CustodianPeers {
			authorization, err := formalGLMBuildRegisteredPhase18AuthorizationV1(
				source.contract, peer, source.inputs.identities.public)
			if err != nil {
				t.Fatal(err)
			}
			if len(authorization.LocalColumns) == 0 {
				localPeer = peer
				break
			}
		}
	}
	authorization, err := formalGLMBuildRegisteredPhase18AuthorizationV1(
		source.contract, localPeer, source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	recipient := authorization.DesignatedComputePeers[0]
	sourceSlot := -1
	for index, peer := range authorization.CustodianPeers {
		if peer == localPeer {
			sourceSlot = index
		}
	}
	blockIndex := authorization.Geometry.TotalBlocks - 1
	globalSlotOffset := blockIndex * authorization.Geometry.BlockCapacity
	slotsInBlock := authorization.Geometry.BlockCapacity
	coordinateRecords := slotsInBlock * authorization.Geometry.CoordinateCount
	frame := formalGLMRegisteredPhase18IngressFrameV3{
		ArtifactID:                           authorization.ArtifactID,
		SourceContractCoreSHA256:             authorization.SourceContractCoreSHA256,
		SourceContractSHA256:                 authorization.SourceContractSHA256,
		RegisteredExecutionPlanSHA256:        authorization.RegisteredExecutionPlanSHA256,
		RegisteredPhase18AuthorizationSHA256: authorization.AuthorizationSHA256,
		Source:                               localPeer, Recipient: recipient,
		RecipientTicketSHA256: sha256Hex([]byte(
			"registered-phase18/ticket/" + localPeer + "/" + recipient)),
		PairCommitment: sha256Hex([]byte(
			"registered-phase18/pair/" + localPeer)),
		BlockCommitment: sha256Hex([]byte(fmt.Sprintf(
			"registered-phase18/block/%s/%d", localPeer, blockIndex))),
		SourceSlot: sourceSlot, RecipientSlot: 0,
		BlockIndex: blockIndex, TotalBlocks: authorization.Geometry.TotalBlocks,
		GlobalSlotOffset: globalSlotOffset, SlotsInBlock: slotsInBlock,
		CoordinateCount:   authorization.Geometry.CoordinateCount,
		CoordinateRecords: coordinateRecords,
		RingBits:          authorization.Geometry.RingBits,
		RecordBytes:       authorization.Geometry.RecordBytes,
		ValidityRecords:   slotsInBlock,
	}
	coordinates := make([]*big.Int, coordinateRecords)
	for index := range coordinates {
		coordinates[index] = new(big.Int)
	}
	coordinates[0] = new(big.Int).Add(
		new(big.Int).Lsh(big.NewInt(1), 60), big.NewInt(17))
	coordinates[1] = new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), uint(frame.RingBits)), big.NewInt(1))
	validity := make([]byte, slotsInBlock)
	validity[0] = 1
	consensus := sha256.Sum256([]byte(
		"registered-phase18/consensus/" + localPeer))
	header := formalGLMRegisteredPhase18PrivateBlockHeaderV3{
		AlignmentSharing:         formalGLMPhase18AlignmentSharing,
		ArtifactID:               frame.ArtifactID,
		BlockIndex:               frame.BlockIndex,
		CoordinateCount:          frame.CoordinateCount,
		CoordinateEncoding:       authorization.CoordinateEncoding,
		CoordinateShareBytes:     frame.CoordinateRecords * frame.RecordBytes,
		GlobalSlotOffset:         frame.GlobalSlotOffset,
		OpeningsPerformed:        0,
		Phase19RequiredOperation: formalGLMPhase18RequiredOperation,
		PrivateAlignmentConsensusShare: base64.RawURLEncoding.EncodeToString(
			consensus[:]),
		PrivateAlignmentGateShare:            1,
		ProductionReady:                      false,
		Purpose:                              formalGLMRegisteredPhase18PrivateBlockPurposeV3,
		RecipientName:                        frame.Recipient,
		RecipientRole:                        "garbler",
		RecipientTicketSHA256:                frame.RecipientTicketSHA256,
		RecordBytes:                          frame.RecordBytes,
		RegisteredExecutionPlanSHA256:        frame.RegisteredExecutionPlanSHA256,
		RegisteredPhase18AuthorizationSHA256: frame.RegisteredPhase18AuthorizationSHA256,
		RingBits:                             frame.RingBits,
		SlotsInBlock:                         frame.SlotsInBlock,
		SourceContractCoreSHA256:             frame.SourceContractCoreSHA256,
		SourceContractSHA256:                 frame.SourceContractSHA256,
		SourceName:                           frame.Source,
		SourceSlot:                           frame.SourceSlot,
		TotalBlocks:                          frame.TotalBlocks,
		ValidityShareBytes:                   frame.ValidityRecords,
		ValiditySharing:                      formalGLMPhase18ValiditySharing,
		Version:                              formalGLMRegisteredPhase18PrivateBlockVersionV3,
	}
	plaintext, err := formalGLMRegisteredPhase18EncodePrivateBlockV3(
		header, coordinates, validity, frame, source.contract, authorization,
		source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	curve := ecdh.X25519()
	recipientKey, err := curve.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := transportEncryptBytes(
		plaintext, recipientKey.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	frame.GlobalMaterializationRoot = sha256Hex([]byte(
		"registered-phase18/materialization/" + t.Name()))
	frame.Ciphertext = ciphertext
	frame.CiphertextSHA256 = sha256Hex(ciphertext)
	frame.EnvelopeSHA256 = sha256Hex([]byte(
		"registered-phase18/envelope/" + frame.CiphertextSHA256))
	localKey := sha256.Sum256([]byte(
		"registered-phase18/local-key/" + t.Name()))
	encoded, err := formalGLMRegisteredPhase18EncodeIngressFrameV3(
		frame, source.contract, authorization, frame.GlobalMaterializationRoot,
		source.inputs.identities.public, localKey)
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMRegisteredPhase18IngressTestFixtureV3{
		source: source, authorization: authorization, frame: frame,
		header: header, coordinates: coordinates, validity: validity,
		localKey: localKey, recipientSK: append([]byte(nil), recipientKey.Bytes()...),
		plaintext: append([]byte(nil), plaintext...), encoded: encoded,
	}
}

func TestFormalGLMRegisteredPhase18IngressV3K2K5(t *testing.T) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18IngressTestBuild(t, custodians)
			if fixture.frame.GlobalSlotOffset != 8 ||
				fixture.frame.SlotsInBlock != 4 ||
				fixture.frame.SlotsInBlock-
					(fixture.authorization.Geometry.TotalCapacity-
						fixture.frame.GlobalSlotOffset) != 3 {
				t.Fatalf("fixture does not exercise three fixed-shape final padding slots: total=%d block=%d offset=%d slots=%d",
					fixture.authorization.Geometry.TotalCapacity,
					fixture.authorization.Geometry.BlockCapacity,
					fixture.frame.GlobalSlotOffset, fixture.frame.SlotsInBlock)
			}
			if custodians == 5 && len(fixture.authorization.LocalColumns) != 0 {
				t.Fatal("K5 fixture did not select the alignment-only witness")
			}
			decoded, err := formalGLMRegisteredPhase18DecodeIngressFrameV3(
				fixture.encoded, fixture.source.contract, fixture.authorization,
				fixture.frame.GlobalMaterializationRoot,
				fixture.source.inputs.identities.public, fixture.localKey)
			if err != nil || !reflect.DeepEqual(decoded, fixture.frame) {
				t.Fatalf("registered ingress round trip differs: equal=%v err=%v",
					reflect.DeepEqual(decoded, fixture.frame), err)
			}
			replayed, err := formalGLMRegisteredPhase18EncodeIngressFrameV3(
				decoded, fixture.source.contract, fixture.authorization,
				fixture.frame.GlobalMaterializationRoot,
				fixture.source.inputs.identities.public, fixture.localKey)
			if err != nil || !bytes.Equal(replayed, fixture.encoded) {
				t.Fatalf("registered ingress replay bytes differ: %v", err)
			}
			slot, err := formalGLMRegisteredPhase18IngressSlotIDV3(
				decoded, fixture.source.contract, fixture.authorization,
				fixture.frame.GlobalMaterializationRoot,
				fixture.source.inputs.identities.public)
			if err != nil || !formalGLMIsSHA256(slot) {
				t.Fatalf("invalid registered ingress slot: %q %v", slot, err)
			}
			plaintext, err := transportDecryptBytes(
				decoded.Ciphertext, fixture.recipientSK)
			if err != nil {
				t.Fatal(err)
			}
			header, coordinates, validity, err :=
				formalGLMRegisteredPhase18DecodePrivateBlockV3(
					plaintext, decoded, fixture.source.contract,
					fixture.authorization, fixture.frame.GlobalMaterializationRoot,
					fixture.source.inputs.identities.public)
			if err != nil || !reflect.DeepEqual(header, fixture.header) ||
				!bytes.Equal(validity, fixture.validity) ||
				len(coordinates) != len(fixture.coordinates) {
				t.Fatalf("registered private block differs: err=%v", err)
			}
			for index := range coordinates {
				if coordinates[index].Cmp(fixture.coordinates[index]) != 0 {
					t.Fatalf("coordinate %d changed", index)
				}
			}
			if coordinates[0].BitLen() <= 53 ||
				coordinates[1].BitLen() != decoded.RingBits {
				t.Fatal("large exact Ring value was not preserved")
			}
			postRootPrivate, err := formalGLMRegisteredPhase18EncodePrivateBlockV3(
				fixture.header, fixture.coordinates, fixture.validity,
				fixture.frame, fixture.source.contract, fixture.authorization,
				fixture.source.inputs.identities.public)
			if err != nil || !bytes.Equal(postRootPrivate, fixture.plaintext) {
				t.Fatalf("K-derived root changed the pre-root private block: %v", err)
			}
		})
	}
}

func TestFormalGLMRegisteredPhase18IngressV3RejectsTampering(t *testing.T) {
	fixture := formalGLMRegisteredPhase18IngressTestBuild(t, 2)
	pins := fixture.source.inputs.identities.public
	expectFrameReject := func(name string,
		mutate func(*formalGLMRegisteredPhase18IngressFrameV3),
	) {
		t.Run(name, func(t *testing.T) {
			changed := fixture.frame
			changed.Ciphertext = append([]byte(nil), fixture.frame.Ciphertext...)
			mutate(&changed)
			if _, err := formalGLMRegisteredPhase18EncodeIngressFrameV3(
				changed, fixture.source.contract, fixture.authorization,
				fixture.frame.GlobalMaterializationRoot, pins,
				fixture.localKey); err == nil {
				t.Fatal("tampered frame was accepted")
			}
		})
	}
	expectFrameReject("source", func(value *formalGLMRegisteredPhase18IngressFrameV3) {
		value.Source = fixture.authorization.CustodianPeers[1]
	})
	expectFrameReject("recipient", func(value *formalGLMRegisteredPhase18IngressFrameV3) {
		value.Recipient = fixture.authorization.DesignatedComputePeers[1]
	})
	expectFrameReject("source slot", func(value *formalGLMRegisteredPhase18IngressFrameV3) {
		value.SourceSlot++
	})
	expectFrameReject("geometry", func(value *formalGLMRegisteredPhase18IngressFrameV3) {
		value.SlotsInBlock++
	})
	expectFrameReject("authorization", func(value *formalGLMRegisteredPhase18IngressFrameV3) {
		value.RegisteredPhase18AuthorizationSHA256 = sha256Hex([]byte("other authorization"))
	})
	expectFrameReject("root", func(value *formalGLMRegisteredPhase18IngressFrameV3) {
		value.GlobalMaterializationRoot = sha256Hex([]byte("other root"))
	})
	expectFrameReject("ciphertext", func(value *formalGLMRegisteredPhase18IngressFrameV3) {
		value.Ciphertext[0] ^= 1
	})

	for _, testCase := range []struct {
		name   string
		mutate func(*formalGLMRegisteredPhase18IngressFrameV3)
	}{
		{name: "ticket", mutate: func(value *formalGLMRegisteredPhase18IngressFrameV3) {
			value.RecipientTicketSHA256 = sha256Hex([]byte("other ticket"))
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			changed := fixture.frame
			changed.Ciphertext = append([]byte(nil), fixture.frame.Ciphertext...)
			testCase.mutate(&changed)
			encoded, err := formalGLMRegisteredPhase18EncodeIngressFrameV3(
				changed, fixture.source.contract, fixture.authorization,
				fixture.frame.GlobalMaterializationRoot, pins,
				fixture.localKey)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := formalGLMRegisteredPhase18DecodeIngressFrameV3(
				encoded, fixture.source.contract, fixture.authorization,
				fixture.frame.GlobalMaterializationRoot, pins,
				fixture.localKey)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := transportDecryptBytes(
				decoded.Ciphertext, fixture.recipientSK)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := formalGLMRegisteredPhase18DecodePrivateBlockV3(
				plaintext, decoded, fixture.source.contract,
				fixture.authorization, fixture.frame.GlobalMaterializationRoot,
				pins); err == nil {
				t.Fatal("frame/private-header route split was accepted")
			}
		})
	}

	rawTamper := append([]byte(nil), fixture.encoded...)
	rawTamper[len(rawTamper)/2] ^= 1
	if _, err := formalGLMRegisteredPhase18DecodeIngressFrameV3(
		rawTamper, fixture.source.contract, fixture.authorization,
		fixture.frame.GlobalMaterializationRoot, pins,
		fixture.localKey); err == nil {
		t.Fatal("unauthenticated raw tamper was accepted")
	}
	wrongKey := sha256.Sum256([]byte("wrong registered ingress key"))
	if _, err := formalGLMRegisteredPhase18DecodeIngressFrameV3(
		fixture.encoded, fixture.source.contract, fixture.authorization,
		fixture.frame.GlobalMaterializationRoot, pins,
		wrongKey); err == nil {
		t.Fatal("wrong local ingress key was accepted")
	}
	other := formalGLMRegisteredPhase18IngressTestBuild(t, 5)
	if _, err := formalGLMRegisteredPhase18DecodeIngressFrameV3(
		fixture.encoded, other.source.contract, other.authorization,
		fixture.frame.GlobalMaterializationRoot,
		other.source.inputs.identities.public, fixture.localKey); err == nil {
		t.Fatal("cross-contract ingress was accepted")
	}
}

func TestFormalGLMRegisteredPhase18PrivateBlockV3CanonicalAndBounded(t *testing.T) {
	fixture := formalGLMRegisteredPhase18IngressTestBuild(t, 5)
	plaintext, err := transportDecryptBytes(
		fixture.frame.Ciphertext, fixture.recipientSK)
	if err != nil {
		t.Fatal(err)
	}
	headerSize := int(uint32(plaintext[0])<<24 |
		uint32(plaintext[1])<<16 | uint32(plaintext[2])<<8 |
		uint32(plaintext[3]))
	headerJSON := plaintext[4 : 4+headerSize]
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(headerJSON, &keys); err != nil {
		t.Fatal(err)
	}
	if _, exists := keys["global_materialization_root"]; exists {
		t.Fatal("pre-root private header contains the K-derived root")
	}
	if _, exists := keys["materialization_context_sha256"]; exists {
		t.Fatal("private header duplicates the registered authorization hash")
	}
	for _, forbidden := range []string{
		"capsule", "run_id", "pre_execution", "phase15", "path",
	} {
		for key := range keys {
			if strings.Contains(strings.ToLower(key), forbidden) {
				t.Fatalf("forbidden private-header field %q", key)
			}
		}
		for _, field := range reflect.VisibleFields(
			reflect.TypeOf(formalGLMRegisteredPhase18IngressFrameV3{})) {
			if strings.Contains(strings.ToLower(field.Name), forbidden) {
				t.Fatalf("forbidden ingress-frame field %q", field.Name)
			}
			if strings.Contains(strings.ToLower(field.Name),
				"materializationcontext") {
				t.Fatalf("duplicated materialization-context field %q", field.Name)
			}
		}
	}

	packHeader := func(value []byte) []byte {
		var size [4]byte
		size[0] = byte(len(value) >> 24)
		size[1] = byte(len(value) >> 16)
		size[2] = byte(len(value) >> 8)
		size[3] = byte(len(value))
		result := append([]byte(nil), size[:]...)
		result = append(result, value...)
		return append(result, plaintext[4+headerSize:]...)
	}
	body := headerJSON[1 : len(headerJSON)-1]
	firstComma := bytes.IndexByte(body, ',')
	reorderedHeader := append([]byte{'{'}, body[firstComma+1:]...)
	reorderedHeader = append(reorderedHeader, ',')
	reorderedHeader = append(reorderedHeader, body[:firstComma]...)
	reorderedHeader = append(reorderedHeader, '}')
	unknownHeader := append([]byte(nil), headerJSON[:len(headerJSON)-1]...)
	unknownHeader = append(unknownHeader, []byte(`,"unexpected":true}`)...)
	for name, changedHeader := range map[string][]byte{
		"whitespace": append([]byte{' ', '\n'}, headerJSON...),
		"reordered":  reorderedHeader,
		"unknown":    unknownHeader,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := formalGLMRegisteredPhase18DecodePrivateBlockV3(
				packHeader(changedHeader), fixture.frame, fixture.source.contract,
				fixture.authorization, fixture.frame.GlobalMaterializationRoot,
				fixture.source.inputs.identities.public); err == nil {
				t.Fatal("non-canonical private header was accepted")
			}
		})
	}

	invalidValidity := append([]byte(nil), plaintext...)
	invalidValidity[len(invalidValidity)-1] = 2
	if _, _, _, err := formalGLMRegisteredPhase18DecodePrivateBlockV3(
		invalidValidity, fixture.frame, fixture.source.contract,
		fixture.authorization, fixture.frame.GlobalMaterializationRoot,
		fixture.source.inputs.identities.public); err == nil {
		t.Fatal("non-bit validity share was accepted")
	}

	invalidPadding := append([]byte(nil), plaintext...)
	coordinateStart := 4 + headerSize
	invalidPadding[coordinateStart+fixture.frame.RecordBytes-1] |= 0x80
	if fixture.frame.RingBits%8 == 0 {
		invalidPadding[coordinateStart+fixture.frame.RecordBytes-1] = 0
		invalidPadding[coordinateStart+fixture.frame.RecordBytes-2] ^= 0x80
		if fixture.frame.RingBits == fixture.frame.RecordBytes*8 {
			invalidPadding = nil
		}
	}
	if invalidPadding != nil {
		if _, _, _, err := formalGLMRegisteredPhase18DecodePrivateBlockV3(
			invalidPadding, fixture.frame, fixture.source.contract,
			fixture.authorization, fixture.frame.GlobalMaterializationRoot,
			fixture.source.inputs.identities.public); err == nil {
			t.Fatal("non-zero Ring padding was accepted")
		}
	}

	if formalGLMRegisteredPhase18IngressMagicV3 != "DSVFG183" ||
		formalGLMRegisteredPhase18IngressMACDomainV3 !=
			"dsVert/formal-glm/phase18/local-ingress-frame/v3" ||
		formalGLMRegisteredPhase18IngressSlotDomainV3 !=
			"dsVert/formal-glm/phase18/local-ingress-slot/v3" ||
		formalGLMRegisteredPhase18RecordsDirectoryV3 != "records-v3" ||
		!bytes.HasPrefix(fixture.encoded, []byte("DSVFG183")) {
		t.Fatal("registered v3 wire/domain constants differ")
	}
}
