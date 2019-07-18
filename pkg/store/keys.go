/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package store

import (
	"crypto/ecdsa"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jbenet/go-base58"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// AddKeystore adds a keystore dir to the User
func (u *User) AddKeystore(keydir string) (*Keystore, error) {

	if u == nil || u.Email == "" {
		return nil, fmt.Errorf("user has not been initialized")
	}

	path, err := filepath.Abs(keydir)
	if err != nil {
		return nil, err
	}

	// Check if already exists
	for _, k := range u.Keystores {
		if k.Path == path {
			return k, nil
		}
	}

	k := &Keystore{
		Path: path,
	}

	u.Keystores = append(u.Keystores, k)

	return k, nil
}

// DefaultKeystore returns the default keystore
func (u *User) DefaultKeystore() (*Keystore, error) {
	return u.AddKeystore(
		filepath.Join(dir, "u", u.Email, "keystore"),
	)
}

func ksInstance(keydir string) *keystore.KeyStore {
	return keystore.NewKeyStore(keydir, keystore.StandardScryptN, keystore.StandardScryptP)
}

// OpenKey opens the named pubKey for reading
func (u User) OpenKey(pubKey string) (io.Reader, error) {
	for _, ks := range u.Keystores {
		ksi := ksInstance(ks.Path)
		for _, a := range ksi.Accounts() {
			if strings.ToLower(a.Address.Hex()) == pubKey {
				return os.Open(a.URL.Path)
			}
		}
	}
	return nil, fmt.Errorf("no key found matching %s", pubKey)
}

// HasPubKey returns true if the User has at least one public key
func (u User) HasPubKey() bool {
	for _, ks := range u.Keystores {
		ksi := ksInstance(ks.Path)
		if len(ksi.Accounts()) > 0 {
			return true
		}
	}
	return false
}

// PubKeys returns all User's public keys found
func (u User) PubKeys() []string {
	pubs := []string{}
	for _, ks := range u.Keystores {
		ksi := ksInstance(ks.Path)
		for _, a := range ksi.Accounts() {
			pubs = append(pubs, strings.ToLower(a.Address.Hex()))
		}
	}
	return pubs
}

// LastPubKey returns the last added User's public key
func (u User) LastPubKey() string {
	pubs := u.PubKeys()
	l := len(pubs)
	if l > 0 {
		return pubs[l-1]
	}
	return ""
}

func generateKey() *ecdsa.PrivateKey {

	// Mnemonic:  correct involve excuse person brave reject patrol trust shove crater shed fan swift note slide census artefact carry shaft sausage beef lady lazy hard

	// Generate a mnemonic for memorization or user-friendly seeds
	// entropy, _ := bip39.NewEntropy(256)
	// mnemonic, _ := bip39.NewMnemonic(entropy)

	mnemonic := "correct involve excuse person brave reject patrol trust shove crater shed fan swift note slide census artefact carry shaft sausage beef lady lazy hard"

	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	seed := bip39.NewSeed(mnemonic, "")

	masterKey, _ := bip32.NewMasterKey(seed)
	publicKey := masterKey.PublicKey()

	decoded := base58.Decode(masterKey.B58Serialize())
	privateKey := decoded[46:78]
	fmt.Println(hexutil.Encode(privateKey))

	// Hex private key to ECDSA private key
	privateKeyECDSA, err := crypto.ToECDSA(privateKey)
	if err != nil {
		panic(err)
	}

	// ECDSA private key to hex private key
	privateKey = crypto.FromECDSA(privateKeyECDSA)
	fmt.Println(hexutil.Encode(privateKey))

	// Display mnemonic and keys
	fmt.Println("Mnemonic: ", mnemonic)
	fmt.Println("Master private key: ", masterKey)
	fmt.Println("Master public key: ", publicKey)

	return privateKeyECDSA
}

// CreateKey generates a new key and stores it into the Keystore directory,
// encrypting it with the passphrase.
func (k Keystore) CreateKey(passphrase string) (pubKey string, err error) {
	if passphrase == "" {
		err = fmt.Errorf("passphrase cannot be empty")
		return
	}

	if err = ensureDir(k.Path); err != nil {
		return
	}

	privateKey := generateKey()

	account, err := ksInstance(k.Path).ImportECDSA(privateKey, passphrase)

	// account, err := ksInstance(k.Path).NewAccount(passphrase)
	if err != nil {
		return
	}

	pubKey = strings.ToLower(account.Address.Hex())

	return pubKey, nil
}
