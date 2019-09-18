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
	"github.com/spf13/cobra"
	"github.com/vchain-us/vcn/internal/logs"
	"github.com/vchain-us/vcn/pkg/meta"
)

// NewCmdServe returns the cobra command for `vcn serve`
func NewCmdServe() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start an API server",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runServe(cmd)
		},
		Args: cobra.NoArgs,
	}
	cmd.Flags().String("host", "", "host address")
	cmd.Flags().String("port", "8080", "port")
	return cmd
}

func runServe(cmd *cobra.Command) error {
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

	logs.LOG.Infof("Starting server %s", host)
	return http.ListenAndServe(host, router)
}

func index(w http.ResponseWriter, r *http.Request) {
	// can be used for healthcheck
	writeResponse(w, http.StatusOK, []byte("OK"))
}
