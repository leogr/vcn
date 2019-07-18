/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package store

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func mkTmpForKeys(t *testing.T) string {
	tdir, err := ioutil.TempDir("", "vcn-test-store-keys")
	if err != nil {
		t.Fatal(err)
	}
	return tdir
}
func TestUserAddKeystore(t *testing.T) {

	u := User{
		Email: "testuser",
	}
	keydir := mkTmpForKeys(t)

	k, err := u.AddKeystore(keydir)
	if err != nil {
		t.Fatal(err)
	}

	assert.Len(t, u.Keystores, 1)
	assert.Equal(t, k, u.Keystores[0])
	assert.Equal(t, keydir, k.Path)
}

func TestKeystoreErrWhenEmptyPassphrase(t *testing.T) {
	k := Keystore{
		Path: mkTmpForKeys(t),
	}
	p, err := k.CreateKey("")
	assert.Equal(t, "", p)
	assert.Error(t, err)
}

func TestKeystoreCreateKey(t *testing.T) {
	k := Keystore{
		Path: mkTmpForKeys(t),
	}

	p, err := k.CreateKey("12345")

	assert.NoError(t, err)
	assert.NotEmpty(t, p)

	pp, err := k.CreateKey("67890")

	assert.NoError(t, err)
	assert.NotEmpty(t, pp)

	assert.NotEqual(t, p, pp)

	u := User{
		Keystores: []*Keystore{&k},
	}

	pks := u.PubKeys()
	assert.Len(t, pks, 2)
	assert.Equal(t, []string{p, pp}, pks)
}

func TestGenerateKey(t *testing.T) {
	generateKey()
}
