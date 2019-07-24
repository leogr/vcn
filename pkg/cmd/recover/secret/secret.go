/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package secret

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/cmd/internal/cli"
	"github.com/vchain-us/vcn/pkg/mnemonic"
	"github.com/vchain-us/vcn/pkg/store"
)

// NewCmdSecret returns the cobra command for `vcn recover secret`
func NewCmdSecret() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Recover an user secret from a mnemonic code",
		Long: `Recover the user's secret from a given mnemonic code and,
if successful, any pre-existing secret will be removed.
The provided passphrase is used to encrypt the secret.
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return Execute()
		},
		Args: cobra.NoArgs,
	}

	return cmd
}

// Execute recover secret action
func Execute() error {

	u := api.NewUser(store.Config().CurrentContext)
	hasAuth, err := u.IsAuthenticated()
	if err != nil {
		return err
	}
	if !hasAuth {
		return fmt.Errorf("you need to be logged in, please use <vcn login>")
	}

	userCfg := u.Config()
	fmt.Println("Please, provide your mnemonic code in order to recover your secret.")
	code, err := cli.PromptMnemonic()
	if err != nil {
		return err
	}

	privKey, err := mnemonic.ToECDSA(code)
	if err != nil {
		return err
	}

	passphrase, err := cli.PromptPassphrase()
	if err != nil {
		return err
	}

	if err := userCfg.ImportSecret(*privKey, passphrase); err != nil {
		return err
	}

	fmt.Println("Secret successfully imported.")
	fmt.Println("Keystore path:\t", userCfg.KeyStore)
	fmt.Println("Public address:\t", userCfg.PublicAddress())
	return nil
}
