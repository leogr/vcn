/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package inspect

import (
	"fmt"

	"github.com/vchain-us/vcn/pkg/meta"

	"github.com/vchain-us/vcn/pkg/cmd/internal/cli"

	"github.com/spf13/cobra"
	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/cmd/internal/types"
	"github.com/vchain-us/vcn/pkg/extractor"
	"github.com/vchain-us/vcn/pkg/store"
)

// NewCmdInspect returns the cobra command for `vcn inspect`
func NewCmdInspect() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"i"},
		Short:   "Return the asset history with low-level information",
		Long:    ``,
		RunE:    runInspect,
		Args: func(cmd *cobra.Command, args []string) error {
			if hash, _ := cmd.Flags().GetString("hash"); hash != "" {
				if len(args) > 0 {
					return fmt.Errorf("cannot use arg(s) with --hash")
				}
				return nil
			}
			return cobra.MinimumNArgs(1)(cmd, args)
		},
	}

	cmd.Flags().String("hash", "", "specify a hash to inspect, if set no arg can be used")

	return cmd
}

func runInspect(cmd *cobra.Command, args []string) error {
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	hash, err := cmd.Flags().GetString("hash")
	if err != nil {
		return err
	}
	cmd.SilenceUsage = true

	if hash == "" {
		if len(args) < 1 {
			return fmt.Errorf("no argument")
		}
		a, err := extractor.Extract(args[0])
		if err != nil {
			return err
		}
		hash = a.Hash
		if output == "" {
			fmt.Printf("Inferred data for: %s\n\n", args[0])
			cli.Print("", types.NewResult(a, nil, nil))
			fmt.Println()
		}
	}

	u := api.NewUser(store.Config().CurrentContext)
	if hasAuth, _ := u.IsAuthenticated(); hasAuth && output == "" {
		fmt.Printf("Current user: %s\n", u.Email())
	}

	return inspect(hash, u, output)
}

func inspect(hash string, u *api.User, output string) error {
	verifications, err := api.BlockChainInspect(hash)
	if err != nil {
		return err
	}
	l := len(verifications)

	if output == "" {
		fmt.Printf(
			`%d signatures found for "%s"

`,
			l, hash)
	}

	results := make([]types.Result, l)
	for i, v := range verifications {
		ar, err := api.LoadArtifact(u, hash, v.MetaHash())
		results[i] = *types.NewResult(nil, ar, &v)
		if err != nil {
			results[i].AddError(err)
		}
		// check if artifact is synced, if any
		if ar != nil {
			if meta.StatusName(v.Status) != ar.Status {
				results[i].AddError(fmt.Errorf(
					"status not in sync (blockchain: %s, platform: %s)", meta.StatusName(v.Status), ar.Status,
				))
			}
			if int64(v.Level) != ar.Level {
				results[i].AddError(fmt.Errorf(
					"level not in sync (blockchain: %d, platform: %d)", v.Level, ar.Level,
				))
			}
		}
	}

	return cli.PrintSlice(output, results)
}
