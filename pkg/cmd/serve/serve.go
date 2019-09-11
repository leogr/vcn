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
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/cmd/internal/types"
	"github.com/vchain-us/vcn/pkg/meta"
	"github.com/vchain-us/vcn/pkg/store"
)

type errorResponse struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Error   string `json:"error"`
}

// NewCmdServe returns the cobra command for `vcn serve`
func NewCmdServe() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start a web server",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runServe(cmd)
		},
		Args: cobra.NoArgs,
	}
	cmd.Flags().String("host", "", "host address to serve the application")
	cmd.Flags().String("port", "8080", "port to serve the application")
	return cmd
}

func runServe(cmd *cobra.Command) error {
	passphrase := os.Getenv(meta.VcnNotarizationPassword)
	if passphrase == "" {
		log.Printf(`%s not set: /notarize, /untrust, and /unsupport won't work.`, meta.VcnNotarizationPassword)
	}

	host, err := cmd.Flags().GetString("host")
	if err != nil {
		return nil
	}
	port, err := cmd.Flags().GetString("port")
	if err != nil {
		return nil
	}
	host += ":" + port

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", index)
	router.HandleFunc("/notarize", signHander(meta.StatusTrusted)).Methods("POST")
	router.HandleFunc("/untrust", signHander(meta.StatusUntrusted)).Methods("POST")
	router.HandleFunc("/unsupport", signHander(meta.StatusUnsupported)).Methods("POST")
	router.HandleFunc("/authenticate/{hash}", verify).Methods("GET")

	log.Println("Starting server " + host)
	return http.ListenAndServe(host, router)
}

func currentUser() (*api.User, error) {
	email := store.Config().CurrentContext
	if email == "" {
		return nil, fmt.Errorf("no user has been set for current context")
	}
	u := api.NewUser(email)
	hasAuth, err := u.IsAuthenticated()
	if err != nil {
		return u, fmt.Errorf("current user is not authenticated")
	}
	if !hasAuth {
		return u, fmt.Errorf("current user is not authenticated")
	}
	return u, nil
}

func writeErrorResponse(w http.ResponseWriter, message string, err error, code int) {
	eR := errorResponse{
		Message: message,
		Code:    code,
	}
	if err != nil {
		eR.Error = err.Error()
	}

	b, _ := json.Marshal(eR)

	w.WriteHeader(code)
	headers := w.Header()
	headers.Set("Access-Control-Allow-Origin", "*")
	headers.Set("Content-Type", "application/json")
	w.Write(b)
}

func writeResponse(w http.ResponseWriter, r *types.Result) {
	b, err := json.Marshal(r)
	if err != nil || b == nil {
		writeErrorResponse(w, "internal json marshal error", err, http.StatusInternalServerError)
		return
	}

	headers := w.Header()
	headers.Set("Access-Control-Allow-Origin", "*")
	headers.Set("Content-Type", "application/json")
	w.Write(b)
}

func index(w http.ResponseWriter, r *http.Request) {
	// can be used for healthcheck
	fmt.Fprintln(w, "OK")
}
