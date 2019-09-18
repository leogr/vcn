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
	"fmt"
	"net/http"

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

func sign(status meta.Status, w http.ResponseWriter, r *http.Request) {
	user, passphrase, err := getCredential(r)
	fmt.Println(passphrase)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if user == nil {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("bad or missing credentials"))
		return
	}

	keyin, err := user.DownloadSecret()
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}

	opts := []api.SignOption{
		api.SignWithKey(keyin, passphrase),
		api.SignWithStatus(status),
	}

	if _, public := r.URL.Query()["public"]; public {
		opts = append(opts, api.SignWithVisibility(meta.VisibilityPublic))
	}

	decoder := json.NewDecoder(r.Body)
	var artifact api.Artifact
	err = decoder.Decode(&artifact)

	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if artifact.Name == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("name cannot be empty"))
		return
	}

	verification, err := user.SignWithOptions(
		artifact,
		opts...,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	var ar *api.ArtifactResponse
	if !verification.Unknown() {
		ar, _ = api.LoadArtifact(user, artifact.Hash, verification.MetaHash())
	}

	writeResult(w, http.StatusOK, types.NewResult(&artifact, ar, verification))
}
