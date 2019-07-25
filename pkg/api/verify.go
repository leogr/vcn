/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/sirupsen/logrus"
	"github.com/vchain-us/vcn/internal/blockchain"
	"github.com/vchain-us/vcn/pkg/meta"
)

// BlockchainVerification represents the notarized data onto the blockchain.
type BlockchainVerification struct {
	Owner     common.Address `json:"owner"`
	Level     meta.Level     `json:"level"`
	Status    meta.Status    `json:"status"`
	Timestamp time.Time      `json:"timestamp"`
}

// Trusted returns true if v.Status is meta.StatusTrusted
func (v *BlockchainVerification) Trusted() bool {
	return v != nil && v.Status == meta.StatusTrusted
}

// Unknown returns true if v is nil or v.Status is meta.StatusUnknown
func (v *BlockchainVerification) Unknown() bool {
	return v == nil || v.Status == meta.StatusUnknown
}

func (v *BlockchainVerification) toMap() map[string]interface{} {
	if v == nil {
		return nil
	}
	return map[string]interface{}{
		"owner":     v.Key(),
		"level":     v.Level,
		"status":    v.Status,
		"timestamp": v.Date(),
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (v *BlockchainVerification) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.toMap())
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (v *BlockchainVerification) UnmarshalJSON(b []byte) error {
	if v == nil {
		v = &BlockchainVerification{}
	}
	data := struct {
		Owner     string
		Level     int64
		Status    int64
		Timestamp string
	}{}
	err := json.Unmarshal(b, &data)
	if err != nil {
		return err
	}
	if data.Owner != "" {
		v.Owner = common.HexToAddress(data.Owner)
	}
	v.Level = meta.Level(data.Level)
	v.Status = meta.Status(data.Status)
	if data.Timestamp != "" {
		v.Timestamp.UnmarshalText([]byte(data.Timestamp))
	}
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (v *BlockchainVerification) MarshalYAML() (interface{}, error) {
	return v.toMap(), nil
}

// MetaHash returns the SHA256 digest of BlockchainVerification's data.
// The returned value uniquely identify a single notarization.
func (v *BlockchainVerification) MetaHash() string {
	if v == nil {
		return ""
	}
	metadata := fmt.Sprintf("%s-%d-%d-%d",
		v.Owner.Hex(),
		int64(v.Level),
		int64(v.Status),
		int64(v.Timestamp.Unix()))
	metadataHashAsBytes := sha256.Sum256([]byte(metadata))
	metahash := fmt.Sprintf("%x", metadataHashAsBytes)
	logger().WithFields(logrus.Fields{
		"metadata": metadata,
		"metahash": metahash,
	}).Trace("Generated metahash")
	return metahash
}

// Key returns signer's key as string for v, if any, otherwise an empty string
func (v *BlockchainVerification) Key() string {
	if v != nil && v.Owner != common.BigToAddress(big.NewInt(0)) {
		return strings.ToLower(v.Owner.Hex())
	}
	return ""
}

// LevelName returns the level's label for v
func (v *BlockchainVerification) LevelName() string {
	if v != nil {
		return meta.LevelName(v.Level)
	}
	return ""
}

// Date returns a RFC3339 formatted string of v's timestamp, if any, otherwise an empty string
func (v *BlockchainVerification) Date() string {
	if v != nil {
		ut := v.Timestamp.UTC()
		if ut.Unix() > 0 {
			return ut.Format(time.RFC3339)
		}
	}
	return ""
}

// BlockChainVerify returns *BlockchainVerification for the hash
func BlockChainVerify(hash string) (*BlockchainVerification, error) {
	logger().WithFields(logrus.Fields{
		"hash": hash,
	}).Trace("BlockChainVerify")
	client, err := ethclient.Dial(meta.MainNetEndpoint())
	if err != nil {
		return nil, err
	}
	contractAddress := common.HexToAddress(meta.AssetsRelayContractAddress())
	instance, err := blockchain.NewAssetsRelay(contractAddress, client)
	if err != nil {
		return nil, err
	}
	address, level, status, timestamp, err := instance.Verify(nil, hash)
	if err != nil {
		return nil, err
	}
	if meta.Status(status.Int64()) != meta.StatusUnknown && address != common.BigToAddress(big.NewInt(0)) {
		verification := &BlockchainVerification{
			Owner:     address,
			Level:     meta.Level(level.Int64()),
			Status:    meta.Status(status.Int64()),
			Timestamp: time.Unix(timestamp.Int64(), 0),
		}
		logger().
			WithField("verification", verification).
			Trace("Blockchain verification found")
		return verification, nil
	}

	logger().Trace("No blockchain verification found")
	return &BlockchainVerification{
		Status: meta.StatusUnknown,
	}, nil
}

// BlockChainVerifyMatchingPublicKey returns *BlockchainVerification for hash matching pubKey.
func BlockChainVerifyMatchingPublicKey(hash string, pubKey string) (*BlockchainVerification, error) {
	return BlockChainVerifyMatchingPublicKeys(hash, []string{pubKey})
}

// BlockChainVerifyMatchingPublicKeys returns *BlockchainVerification for hash
// matching at least one of pubKeys
func BlockChainVerifyMatchingPublicKeys(hash string, pubKeys []string) (*BlockchainVerification, error) {
	logger().WithFields(logrus.Fields{
		"hash": hash,
		"keys": pubKeys,
	}).Trace("BlockChainVerifyMatchingPublicKeys")

	// Connect and get verification count
	client, err := ethclient.Dial(meta.MainNetEndpoint())
	if err != nil {
		return nil, err
	}
	contractAddress := common.HexToAddress(meta.AssetsRelayContractAddress())
	instance, err := blockchain.NewAssetsRelay(contractAddress, client)
	if err != nil {
		return nil, err
	}
	count, err := instance.GetAssetCountForHash(nil, hash)
	if err != nil {
		return nil, err
	}

	// Make a map to lookup pubKey quickly
	keysMap := map[string]bool{}
	for i, pubKey := range pubKeys {
		pubKey = strings.ToLower(pubKey)
		pubKeys[i] = pubKey
		keysMap[pubKey] = true
	}

	// Iterate over verifications
	for i := count.Int64() - 1; i >= 0; i-- {
		address, level, status, timestamp, err := instance.VerifyByIndex(nil, hash, big.NewInt(i))
		if err != nil {
			return nil, err
		}
		if keysMap[strings.ToLower(address.Hex())] {
			verification := &BlockchainVerification{
				Owner:     address,
				Level:     meta.Level(level.Int64()),
				Status:    meta.Status(status.Int64()),
				Timestamp: time.Unix(timestamp.Int64(), 0),
			}
			logger().
				WithField("verification", verification).
				Trace("Blockchain verification found")
			return verification, nil
		}
	}

	logger().Trace("No blockchain verification found")
	return &BlockchainVerification{
		Status: meta.StatusUnknown,
	}, nil
}
