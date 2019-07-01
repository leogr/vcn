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

func signHander(state meta.Status, pubKey string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		s := state
		p := pubKey
		sign(s, p, w, r)
	}
}

func sign(state meta.Status, pubKey string, w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var jsonRequest api.ArtifactRequest
	err := decoder.Decode(&jsonRequest)

	if err != nil {
		writeErrorResponse(w, "invalid request body", err, http.StatusBadRequest)
		return
	}

	// check hash in request
	if jsonRequest.Hash == "" {
		writeErrorResponse(w, "hash cannot be empty", nil, http.StatusBadRequest)
		return
	}
	if jsonRequest.Name == "" {
		writeErrorResponse(w, "name cannot be empty", nil, http.StatusBadRequest)
		return
	}

	user, err := currentUser()
	if user == nil || err != nil {
		writeErrorResponse(w, "no such user", err, http.StatusBadRequest)
		return
	}

	if pubKey == "" {
		pubKey = user.DefaultKey()
	}
	if pubKey == "" {
		writeErrorResponse(w, "no key available", nil, http.StatusBadRequest)
		return
	}

	// Make the artifact to be signed
	var a api.Artifact
	a.Hash = jsonRequest.Hash
	a.Name = jsonRequest.Name
	a.Size = jsonRequest.Size
	a.Kind = jsonRequest.Kind
	a.ContentType = jsonRequest.ContentType
	a.Metadata = jsonRequest.Metadata

	verification, err := user.Sign(a, pubKey, os.Getenv(meta.KeyStorePasswordEnv), state, parseVisibility(jsonRequest.Visibility))
	if err != nil {
		writeErrorResponse(w, "sign error", err, http.StatusBadRequest)
		return
	}

	writeResponse(w, types.NewResult(&a, nil, verification))
}

func parseVisibility(value string) meta.Visibility {
	switch value {
	case "0":
		return meta.VisibilityPublic
	case "1":
		return meta.VisibilityPrivate
	case "PUBLIC":
		return meta.VisibilityPublic
	case "PRIVATE":
		return meta.VisibilityPrivate
	default:
		return meta.VisibilityPrivate
	}
}
