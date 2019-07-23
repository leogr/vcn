/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package mnemonic

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jbenet/go-base58"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// DerivationPath for menemonic generated seed.
const DerivationPath = "m/0'/0"

// ToECDSA creates a private key from a BIP39 mnemonic.
// Provided mnemonic must not protected with any passphrase.
// The resulting private key is derived in accordance to DerivationPath.
func ToECDSA(mnemonic string) (privateKeyECDSA *ecdsa.PrivateKey, err error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		return
	}

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return
	}

	paths, err := accounts.ParseDerivationPath(DerivationPath)
	if err != nil {
		return
	}
	key := masterKey
	for _, p := range paths {
		key, err = key.NewChildKey(p)
		if err != nil {
			return
		}
	}

	decoded := base58.Decode(key.B58Serialize())
	privateKey := decoded[46:78]
	return crypto.ToECDSA(privateKey)
}
