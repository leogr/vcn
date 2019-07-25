/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package api

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vchain-us/vcn/internal/errors"
	"github.com/vchain-us/vcn/pkg/meta"
	"github.com/vchain-us/vcn/pkg/store"
)

// User represent a CodeNotary platform user.
type User struct {
	cfg *store.User
}

// NewUser returns a new User instance for the given email.
func NewUser(email string) *User {
	return &User{
		cfg: store.Config().User(email),
	}
}

// Email returns the User's email, if any, otherwise an empty string.
func (u User) Email() string {
	if u.cfg != nil {
		return u.cfg.Email
	}
	return ""
}

// Authenticate the User against the CodeNotary platform.
// If successful the auth token in stored within the User's config and used for subsequent API call.
func (u *User) Authenticate(password string) (err error) {
	if u == nil || u.Email() == "" {
		return makeFatal("user not initialized", nil)
	}

	token, err := authenticateUser(u.Email(), password)
	if err != nil {
		return err
	}

	u.cfg.Token = token
	return nil
}

// ClearAuth deletes the stored authentication token.
func (u *User) ClearAuth() {
	if u != nil && u.cfg != nil {
		u.cfg.Token = ""
	}
}

func (u *User) token() string {
	if u != nil && u.cfg != nil {
		return u.cfg.Token
	}
	return ""
}

// IsAuthenticated returns true if the stored auth token is still valid.
func (u User) IsAuthenticated() (bool, error) {
	if u.cfg == nil || u.cfg.Token == "" {
		return false, nil
	}

	return checkToken(u.cfg.Token)
}

// IsExist returns true if the User's was registered on the CodeNotary platform.
func (u User) IsExist() (bool, error) {
	email := u.Email()
	if email != "" {
		return checkUserExists(email)
	}
	return false, nil
}

// Config returns the User configuration object (see store.User), if any.
// It returns nil if the User is not properly initialized.
func (u User) Config() *store.User {
	if u.cfg != nil {
		return u.cfg
	}
	return nil
}

// RemainingSignOps returns the number of remaining notarizations in the User's account subscription.
func (u User) RemainingSignOps() (uint64, error) {
	response := new(struct {
		Count uint64 `json:"count"`
	})
	restError := new(Error)
	r, err := newSling(u.token()).
		Get(meta.RemainingSignOpsEndpoint()).
		Receive(&response, restError)
	logger().WithFields(logrus.Fields{
		"response":  response,
		"err":       err,
		"restError": restError,
	}).Trace("RemainingSignOps")
	if err != nil {
		return 0, err
	}
	switch r.StatusCode {
	case 200:
		return response.Count, nil
	}
	return 0, fmt.Errorf("count remaining sign operations failed: %+v", restError)
}

func (u User) checkSyncState() (err error) {
	address := u.cfg.PublicAddress()
	if address == "" {
		return fmt.Errorf("no secret has been imported for %s", u.Email())
	}

	authError := new(Error)
	pagedWalletResponse := new(struct {
		Content []struct {
			Address             string `json:"address"`
			CreatedAt           string `json:"createdAt"`
			Name                string `json:"name"`
			PermissionSyncState string `json:"permissionSyncState"`
			LevelSyncState      string `json:"levelSyncState"`
		} `json:"content"`
	})
	r, err := newSling(u.token()).
		Get(meta.WalletEndpoint()).
		Receive(pagedWalletResponse, authError)
	if err != nil {
		return err
	}
	if r.StatusCode != 200 {
		return fmt.Errorf(
			"request failed: %s (%d)", authError.Message,
			authError.Status)
	}

	wallets := pagedWalletResponse.Content
	if len(wallets) == 0 {
		return fmt.Errorf("no secret found for %s", u.Email())
	}
	for _, wallet := range (*pagedWalletResponse).Content {
		if wallet.Address == strings.ToLower(address) {
			if wallet.PermissionSyncState == "SYNCED" && wallet.LevelSyncState == "SYNCED" {
				return nil // everything is ok
			}
			return fmt.Errorf(errors.AccountNotSynced)
		}
	}
	return fmt.Errorf("public address of local secret does not match your account: %s", address)
}
