/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"github.com/vchain-us/vcn/internal/logs"
	"github.com/vchain-us/vcn/pkg/meta"
)

func PromptMnemonic() (mnemonic string, err error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Mnemonic code:")
	if mnemonic, err = reader.ReadString('\n'); err == nil {
		mnemonic = strings.TrimSpace(mnemonic)
	} else {
		mnemonic = ""
	}
	return
}

func PromptPassphrase() (passphrase string, err error) {

	color.Set(meta.StyleAffordance())
	fmt.Print(`
Attention: Please pick a strong passphrase and keep it safe.
The passphrase is needed to encrypt your secret that will be stored locally.
You will have to provide this passphrase everytime you want to notirize an asset.
`)
	color.Unset()
	fmt.Println()

	var keystorePassphrase string
	var keystorePassphrase2 string

	match := false
	counter := 0
	for match == false {

		counter++

		if counter == 4 {
			return "", fmt.Errorf("too many failed attemps")
		}

		keystorePassphrase, _ = readPassword("Keystore passphrase: ")
		keystorePassphrase2, _ = readPassword("Keystore passphrase (reenter): ")
		fmt.Println()

		if keystorePassphrase == "" {
			fmt.Println("Your passphrase must not be empty.")
		} else if keystorePassphrase != keystorePassphrase2 {
			fmt.Println("Your two inputs did not match. Please try again.")
		} else {
			match = true
		}

	}
	return keystorePassphrase, nil
}

func ProvidePassphrase() (passphrase string, err error) {
	passphrase = os.Getenv(meta.KeyStorePasswordEnv)
	if passphrase != "" {
		logs.LOG.Trace("Keystore password provided (environment)")
		return passphrase, nil
	}
	passphrase, err = readPassword("Keystore passphrase: ")
	if err != nil {
		return "", err
	}
	logs.LOG.Trace("Keystore password provided (interactive)")
	return passphrase, nil
}

func ProvidePlatformUsername() (user string, err error) {
	user = os.Getenv(meta.VcnUserEnv)
	if user != "" {
		logs.LOG.WithFields(logrus.Fields{
			"username": user,
		}).Trace("Platform user provided (environment)")
		return user, nil
	}
	fmt.Print("Email address: ")
	n, err := fmt.Scanln(&user)
	if err != nil {
		return "", err
	}
	if n <= 0 {
		return "", fmt.Errorf("username must not be empty")
	}
	user = strings.TrimSpace(user)
	logs.LOG.WithFields(logrus.Fields{
		"username": user,
	}).Trace("Platform user provided (interactive)")
	return user, nil
}

func ProvidePlatformPassword() (password string, err error) {
	password = os.Getenv(meta.VcnPasswordEnv)
	if password != "" {
		logs.LOG.Trace("Platform password provided (environment)")
		return password, nil
	}
	password, err = readPassword("Password: ")
	if err != nil {
		return "", err
	}
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	logs.LOG.Trace("Platform password provided (interactive)")
	return password, nil
}
