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

	"github.com/vchain-us/vcn/internal/logs"
	"github.com/vchain-us/vcn/pkg/cmd/internal/types"
)

type errorResponse struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Error   string `json:"error"`
}

func writeResponse(w http.ResponseWriter, code int, b []byte) {
	headers := w.Header()
	headers.Set("Access-Control-Allow-Origin", "*")
	headers.Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, err := w.Write(b)
	if err != nil {
		logs.LOG.Error(err)
	}
}

func writeResult(w http.ResponseWriter, code int, r *types.Result) {
	b, err := json.Marshal(r)
	if err != nil || b == nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeResponse(w, code, b)
}

func writeError(w http.ResponseWriter, code int, err error) {
	eR := errorResponse{
		Message: http.StatusText(code),
		Code:    code,
		Error:   err.Error(),
	}
	b, _ := json.Marshal(eR)

	writeResponse(w, code, b)
}
