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

type User struct {
	cfg *store.User
}

func NewUser(email string) *User {
	return &User{
		cfg: store.Config().User(email),
	}
}

func (u User) Email() string {
	if u.cfg != nil {
		return u.cfg.Email
	}
	return ""
}

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

func (u User) IsAuthenticated() (bool, error) {
	if u.cfg == nil || u.cfg.Token == "" {
		return false, nil
	}

	return checkToken(u.cfg.Token)
}

func (u User) IsExist() (bool, error) {
	email := u.Email()
	if email != "" {
		return checkUserExists(email)
	}
	return false, nil
}

func (u User) Config() *store.User {
	if u.cfg != nil {
		return u.cfg
	}
	return nil
}

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
