/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package serve

import (
	"net/http"

	"github.com/vchain-us/vcn/pkg/api"
)

func getCredential(r *http.Request) (user *api.User, passphrase string, err error) {
	if email, password, ok := r.BasicAuth(); ok {
		user = api.NewUser(email)
		err = user.Authenticate(password)
		if err == nil {
			passphrase = r.Header.Get("x-notarization-password")
			if passphrase == "" {
				passphrase = password
			}
		}
	}
	return
}
