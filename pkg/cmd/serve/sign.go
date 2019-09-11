/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package serve

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/cmd/internal/types"
	"github.com/vchain-us/vcn/pkg/meta"
)

func signHander(state meta.Status) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		s := state
		sign(s, w, r)
	}
}

func sign(state meta.Status, w http.ResponseWriter, r *http.Request) {

	visibility := meta.VisibilityPrivate
	if _, public := r.URL.Query()["public"]; public {
		visibility = meta.VisibilityPublic
	}

	decoder := json.NewDecoder(r.Body)
	var artifact api.Artifact
	err := decoder.Decode(&artifact)

	if err != nil {
		writeErrorResponse(w, "invalid request body", err, http.StatusBadRequest)
		return
	}

	if artifact.Name == "" {
		writeErrorResponse(w, "name cannot be empty", nil, http.StatusBadRequest)
		return
	}

	user, err := currentUser()
	if user == nil || err != nil {
		writeErrorResponse(w, "no such user", err, http.StatusBadRequest)
		return
	}

	verification, err := user.Sign(artifact, os.Getenv(meta.VcnNotarizationPassword), state, visibility)
	if err != nil {
		writeErrorResponse(w, "sign error", err, http.StatusBadRequest)
		return
	}

	var ar *api.ArtifactResponse
	if !verification.Unknown() {
		ar, _ = api.LoadArtifact(user, artifact.Hash, verification.MetaHash())
	}

	writeResponse(w, types.NewResult(&artifact, ar, verification))
}
