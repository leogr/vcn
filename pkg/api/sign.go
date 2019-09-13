/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package api

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/sirupsen/logrus"
	"github.com/vchain-us/vcn/internal/blockchain"
	"github.com/vchain-us/vcn/internal/errors"
	"github.com/vchain-us/vcn/pkg/meta"
)

// Sign is invoked by the User to notarize an artifact with a given state and visibility,
// if successful a BlockchainVerification is returned.
// The passphrase is required to unlock the local stored secret.
func (u User) Sign(artifact Artifact, passphrase string, state meta.Status, visibility meta.Visibility) (*BlockchainVerification, error) {

	if artifact.Hash == "" {
		return nil, makeError("hash is missing", nil)
	}
	if artifact.Size < 0 {
		return nil, makeError("invalid size", nil)
	}

	hasAuth, err := u.IsAuthenticated()
	if err != nil {
		return nil, err
	}
	if !hasAuth {
		return nil, makeAuthRequiredError()
	}

	trialExpired, err := u.trialExpired()
	if err != nil {
		return nil, err
	}
	if trialExpired {
		return nil, fmt.Errorf(errors.TrialExpired)
	}

	opsLeft, err := u.RemainingSignOps()
	if err != nil {
		return nil, err
	}

	if opsLeft < 1 {
		return nil, fmt.Errorf(errors.NoRemainingSignOps)
	}

	if err := u.checkSyncState(); err != nil {
		return nil, err
	}

	keyin, err := u.cfg.OpenSecret()
	if err != nil {
		return nil, err
	}

	return u.commitHash(keyin, passphrase, artifact, state, visibility)
}

func (u User) commitHash(
	keyin io.Reader,
	passphrase string,
	artifact Artifact,
	status meta.Status,
	visibility meta.Visibility,
) (verification *BlockchainVerification, err error) {
	transactor, err := bind.NewTransactor(keyin, passphrase)
	if err != nil {
		return
	}

	transactor.GasLimit = meta.GasLimit()
	transactor.GasPrice = meta.GasPrice()
	client, err := ethclient.Dial(meta.MainNet())
	if err != nil {
		err = makeError(
			errors.BlockchainCannotConnect,
			logrus.Fields{
				"error":   err,
				"network": meta.MainNet(),
			})
		return
	}
	address := common.HexToAddress(meta.AssetsRelayContractAddress())
	instance, err := blockchain.NewAssetsRelay(address, client)
	if err != nil {
		err = makeFatal(
			errors.BlockchainContractErr,
			logrus.Fields{
				"error":    err,
				"contract": meta.AssetsRelayContractAddress(),
			},
		)
		return
	}
	tx, err := instance.Sign(transactor, artifact.Hash, big.NewInt(int64(status)))
	if err != nil {
		err = makeFatal(
			errors.SignFailed,
			logrus.Fields{
				"error": err,
				"hash":  artifact.Hash,
			},
		)
		return
	}
	timeout, err := waitForTx(tx.Hash(), meta.TxVerificationRounds(), meta.PollInterval())
	if err != nil {
		err = makeFatal(
			errors.BlockchainPermission,
			logrus.Fields{
				"error": err,
			},
		)
		return
	}
	if timeout {
		err = makeFatal(
			errors.BlockchainTimeout,
			logrus.Fields{
				"error": err,
			},
		)
		return
	}

	signerID := transactor.From.Hex()
	verification, err = VerifyMatchingSignerID(artifact.Hash, signerID)
	if err != nil {
		return
	}

	err = u.createArtifact(verification, strings.ToLower(signerID), artifact, visibility, status)
	return
}

func waitForTx(tx common.Hash, maxRounds uint64, pollInterval time.Duration) (timeout bool, err error) {
	client, err := ethclient.Dial(meta.MainNet())
	if err != nil {
		return false, err
	}
	for i := uint64(0); i < maxRounds; i++ {
		_, pending, err := client.TransactionByHash(context.Background(), tx)
		if err != nil {
			return false, err
		}
		if !pending {
			return false, nil
		}
		time.Sleep(pollInterval)
	}
	return true, nil
}
