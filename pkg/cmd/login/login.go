/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package login

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/cmd/internal/cli"
	"github.com/vchain-us/vcn/pkg/meta"
	"github.com/vchain-us/vcn/pkg/mnemonic"
	"github.com/vchain-us/vcn/pkg/store"
)

// NewCmdLogin returns the cobra command for `vcn login`
func NewCmdLogin() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign-in to codenotary.io",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			output, err := cmd.Flags().GetString("output")
			if err != nil {
				return err
			}

			if err := Execute(); err != nil {
				return err
			}
			if output == "" {
				fmt.Println("Login successful.")
			}
			return nil
		},
		Args: cobra.NoArgs,
	}

	return cmd
}

// Execute the login action
func Execute() error {

	cfg := store.Config()

	email, err := cli.ProvidePlatformUsername()
	if err != nil {
		return err
	}

	user := api.NewUser(email)
	isExist, err := user.IsExist()
	if err != nil {
		return err
	}
	if !isExist {
		return fmt.Errorf("no such user, please create an account at: %s", meta.DashboardURL())
	}

	password, err := cli.ProvidePlatformPassword()
	if err != nil {
		return err
	}

	cfg.ClearContext()
	if err := user.Authenticate(password); err != nil {
		return err
	}
	cfg.CurrentContext = user.Email()

	_ = api.TrackPublisher(user, meta.VcnLoginEvent)

	userCfg := user.Config()
	if pubAddr := userCfg.PublicAddress(); pubAddr == "" {

		fmt.Print(`
You have no secret set up yet.
Please, provide your mnemonic code in order to recover your secret.
`)

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

		fmt.Printf("Secret successfully imported.")
		fmt.Println("Keystore path:\t", userCfg.KeyStore)
		fmt.Println("Public address:\t", userCfg.PublicAddress())
		fmt.Println()
	}

	if err := store.SaveConfig(); err != nil {
		return err
	}

	return nil
}
