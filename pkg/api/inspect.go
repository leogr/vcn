/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package api

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/sirupsen/logrus"
	"github.com/vchain-us/vcn/internal/blockchain"
	"github.com/vchain-us/vcn/pkg/meta"
)

// BlockChainInspect returns an array of BlockchainVerification containing all verifications found for the given hash
func BlockChainInspect(hash string) ([]BlockchainVerification, error) {
	logger().WithFields(logrus.Fields{
		"hash": hash,
	}).Trace("BlockChainInspect")

	// Connect and get verification count
	client, err := ethclient.Dial(meta.MainNet())
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
	l := count.Int64()

	verifications := make([]BlockchainVerification, l)

	// Iterate over verifications
	for i := int64(0); i < l; i++ {
		address, level, status, timestamp, err := instance.VerifyByIndex(nil, hash, big.NewInt(i))
		if err != nil {
			return nil, err
		}
		verifications[i] = BlockchainVerification{
			Owner:     address,
			Level:     meta.Level(level.Int64()),
			Status:    meta.Status(status.Int64()),
			Timestamp: time.Unix(timestamp.Int64(), 0),
		}
	}
	return verifications, nil
}
