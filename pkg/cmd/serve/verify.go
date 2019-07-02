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
	"strings"

	"github.com/gorilla/mux"
	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/cmd/internal/types"
)

func verify(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hash := vars["hash"]
	user, _ := currentUser()

	var keys []string
	org := r.URL.Query().Get("org")
	if org != "" {
		bo, err := api.BlockChainGetOrganisation(org)
		if err != nil {
			writeErrorResponse(w, "organization error", err, http.StatusBadRequest)
			return
		}
		keys = bo.MembersKeys()
	} else {
		ks := r.URL.Query().Get("keys")
		if ks != "" {
			keys = strings.Split(ks, ",")
			// add 0x if missing, lower case
			for i, k := range keys {
				if !strings.HasPrefix(k, "0x") {
					keys[i] = "0x" + k
				}
				keys[i] = strings.ToLower(keys[i])
			}
		}
	}

	var verification *api.BlockchainVerification
	var err error
	// if keys have been passed, check for a verification matching them
	if len(keys) > 0 {
		verification, err = api.BlockChainVerifyMatchingPublicKeys(hash, keys)
	} else {
		// if we have an user, check for verification matching user's keys first
		if user != nil {
			if hasAuth, _ := user.IsAuthenticated(); hasAuth {
				if userKeys := user.Keys(); len(userKeys) > 0 {
					verification, err = api.BlockChainVerifyMatchingPublicKeys(hash, userKeys)
				}
			}
		}
		// if no user nor verification matching the user has found,
		// fallback to the last with highest level available verification
		if verification.Unknown() {
			verification, err = api.BlockChainVerify(hash)
		}
	}

	if err != nil {
		writeErrorResponse(w, "verification error", err, http.StatusBadRequest)
		return
	}

	var artifact *api.ArtifactResponse
	if !verification.Unknown() {
		artifact, _ = api.LoadArtifactForHash(user, hash, verification.MetaHash())
	}

	writeResponse(w, types.NewResult(nil, artifact, verification))
}
