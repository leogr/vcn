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

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
)

func (u *User) keystore() (ks *keystore.KeyStore, err error) {
	if u == nil || u.Email == "" {
		return nil, fmt.Errorf("user has not been initialized")
	}

	if u.KeyStore == "" {
		u.KeyStore = filepath.Join(dir, "u", u.Email, "k")
	}

	path, err := filepath.Abs(u.KeyStore)
	if err != nil {
		return
	}

	if err = ensureDir(path); err != nil {
		return
	}
	u.KeyStore = path

	return keystore.NewKeyStore(path, keystore.StandardScryptN, keystore.StandardScryptP), nil
}

func (u *User) defaultAccount() (acc *accounts.Account, err error) {
	ks, err := u.keystore()
	if err != nil {
		return
	}

	accs := ks.Accounts()
	if len(accs) == 0 {
		return
	}

	return &accs[0], nil
}

// PublicAddress returns the public key address for the User's secret, if any, otherwise an empty string.
func (u *User) PublicAddress() string {
	if acc, _ := u.defaultAccount(); acc != nil {
		return strings.ToLower(acc.Address.Hex())
	}
	return ""
}

// OpenSecret opens the user's Web3 Secret Storage JSON file for reading.
func (u *User) OpenSecret() (io.Reader, error) {
	acc, err := u.defaultAccount()
	if err != nil {
		return nil, fmt.Errorf("cannot open the keystore: %s", err)
	}
	if acc == nil {
		return nil, fmt.Errorf("no secret found in the keystore")
	}
	return os.Open(acc.URL.Path)
}

// ImportSecret imports the user's secret from a ECDSA private key and,
// if successful, any pre-existing secret will be removed.
// The provided passphrase is used to encrypt the secret.
func (u *User) ImportSecret(privateKey ecdsa.PrivateKey, passphrase string) error {
	ks, err := u.keystore()
	if err != nil {
		return fmt.Errorf("cannot open the keystore: %s", err)
	}

	// todo(leogr): go-ethereum does not allow to overwrite an existing account,
	// so we need to remove the stored secret if matches.
	// But the previous stored account could be lost, although it can be still recovered
	// by using the provided privateKey.
	acc, err := ks.Find(accounts.Account{
		Address: crypto.PubkeyToAddress(privateKey.PublicKey),
	})
	if err == nil {
		if err := os.Remove(acc.URL.Path); err != nil {
			return err
		}
		ks, _ = u.keystore() // reloads the keystore from disk
	}

	account, err := ks.ImportECDSA(&privateKey, passphrase)
	if err != nil {
		return err
	}

	// Cleanup other secrets, if any
	for _, a := range ks.Accounts() {
		if a.URL.Path == account.URL.Path {
			continue
		}
		if err := os.Remove(a.URL.Path); err != nil {
			return err
		}
	}
	return nil
}
