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

	"github.com/gorilla/mux"
	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/cmd/internal/types"
)

func verify(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hash := vars["hash"]
	user, _ := currentUser()

	verification, err := api.BlockChainVerify(hash)
	if err != nil {
		panic(err)
	}

	var artifact *api.ArtifactResponse
	if !verification.Unknown() {
		artifact, _ = api.LoadArtifactForHash(user, hash, verification.MetaHash())
	}

	writeResponse(w, types.NewResult(nil, artifact, verification))
}
