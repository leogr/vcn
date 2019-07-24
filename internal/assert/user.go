/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package assert

import (
	"fmt"

	"github.com/vchain-us/vcn/pkg/cmd/login"

	"github.com/inconshreveable/mousetrap"
	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/store"
)

const vcnLoginMsg = "Proceed by authenticating yourself using <vcn login>"
const loginMsg = "You need to be logged in"

func UserLogin() error {
	// check for token
	hasAuth, err := api.NewUser(store.Config().CurrentContext).IsAuthenticated()
	if err != nil {
		return err
	}

	if !hasAuth {
		// Windows only - when trying to sign an asset with right click
		// and user has not logged in, prompt the login action directly
		// without having to open a new cmd line and log in there
		if mousetrap.StartedByExplorer() {
			fmt.Println(loginMsg)
			if err := login.Execute(); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("%s.\n%s", loginMsg, vcnLoginMsg)
		}
	}

	return nil
}

func UserKeystore() error {
	u := api.NewUser(store.Config().CurrentContext)
	if u.Config().PublicAddress() == "" {
		return fmt.Errorf("You need to import a secret prior to notarize an asset.\n%s", loginMsg)
	}
	return nil
}
