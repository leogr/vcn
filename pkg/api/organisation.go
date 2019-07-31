/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package api

import (
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

// BlockchainOrganisation represents the Organization data stored onto the blockchain.
type BlockchainOrganisation struct {
	Owner     common.Address   `json:"owner"`
	Members   []common.Address `json:"members"`
	Hash      string           `json:"hash"`
	Timestamp time.Time        `json:"timestamp"`
}

// Key returns org owner's key as string for o, if any, otherwise an empty string
func (o *BlockchainOrganisation) Key() string {
	if o != nil && o.Owner != common.BigToAddress(big.NewInt(0)) {
		return strings.ToLower(o.Owner.Hex())
	}
	return ""
}

// MembersKeys returns org members' keys as slice of strings for o, if any, otherwise a zero-len slice
func (o *BlockchainOrganisation) MembersKeys() []string {
	if o != nil && o.Owner != common.BigToAddress(big.NewInt(0)) {
		keys := make([]string, len(o.Members))
		for i, el := range o.Members {
			keys[i] = strings.ToLower(el.Hex())
		}
		return keys
	}
	return []string{}
}

// BlockChainGetOrganisation returns a BlockchainOrganisation for the organization name, if any.
// It returns a nil value and an error if the organization is not found.
func BlockChainGetOrganisation(name string) (*BlockchainOrganisation, error) {
	logger().WithFields(logrus.Fields{
		"name": name,
	}).Trace("BlockChainGetOrganisation")

	// Connect and get organisation data
	client, err := ethclient.Dial(meta.MainNet())
	if err != nil {
		return nil, err
	}
	contractAddress := common.HexToAddress(meta.OrganisationsRelayContractAddress())
	instance, err := blockchain.NewOrganisationsRelay(contractAddress, client)
	if err != nil {
		return nil, err
	}
	owner, memberAddresses, hash, timestamp, err := instance.GetOrganisation(nil, name)
	if err != nil {
		return nil, err
	}

	if owner != common.BigToAddress(big.NewInt(0)) {
		org := &BlockchainOrganisation{
			Owner:     owner,
			Members:   memberAddresses,
			Hash:      hash,
			Timestamp: time.Unix(timestamp.Int64(), 0),
		}
		logger().
			WithField("organisation", org).
			Trace("Blockchain organisation found")
		return org, nil
	}

	return nil, makeError(fmt.Sprintf(`organisation "%s" not found`, name), logrus.Fields{
		"name": name,
	})
}
