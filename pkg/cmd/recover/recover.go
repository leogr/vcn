/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package recover

import (
	"github.com/spf13/cobra"
	"github.com/vchain-us/vcn/pkg/cmd/recover/secret"
)

// NewCmdRecover returns the cobra command for `vcn recover`
func NewCmdRecover() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "recover",
		Short:   "Recover an user secret",
		Example: "  vcn recover secret",
		Long:    ``,
		Args:    cobra.NoArgs,
	}

	cmd.AddCommand(secret.NewCmdSecret())
	return cmd
}
