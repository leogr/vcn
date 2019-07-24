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

func (u *User) PublicAddress() string {
	ks, err := u.keystore()
	if err != nil {
		return ""
	}
	accs := ks.Accounts()
	if len(accs) == 0 {
		return ""
	}
	return strings.ToLower(accs[0].Address.Hex())
}

// OpenSecret opens the user's Web3 Secret Storage JSON file for reading.
func (u *User) OpenSecret() (io.Reader, error) {
	ks, err := u.keystore()
	if err != nil {
		return nil, fmt.Errorf("cannot open the keystore: %s", err)
	}
	accs := ks.Accounts()
	if len(accs) == 0 {
		return nil, fmt.Errorf("no secret found in the keystore")
	}
	return os.Open(accs[0].URL.Path)
}

// ImportSecret imports the user's secret from a ECDSA private key and,
// if successful, any pre-existing secret will be removed.
// The provided passphrase is used to encrypt the secret.
func (u *User) ImportSecret(privateKey ecdsa.PrivateKey, passphrase string) error {
	ks, err := u.keystore()
	if err != nil {
		return fmt.Errorf("cannot open the keystore: %s", err)
	}

	account, err := ks.ImportECDSA(&privateKey, passphrase)
	if err != nil {
		return err
	}

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
