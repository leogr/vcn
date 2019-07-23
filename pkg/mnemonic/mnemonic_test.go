/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package mnemonic

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

func TestToECSDA(t *testing.T) {
	privateKeyECDSA, err := ToECDSA("attend polar kite inner harvest solar answer proud best donor twenty space plunge repeat virus")
	assert.NoError(t, err)
	assert.NotNil(t, privateKeyECDSA)
	privateKey := crypto.FromECDSA(privateKeyECDSA)

	assert.Equal(
		t,
		[]byte{0x83, 0x9e, 0xc2, 0x6c, 0x5b, 0x76, 0xfb, 0x1b, 0xa, 0xf1, 0x3, 0xee, 0xb7, 0xeb, 0x11, 0x79, 0xc1, 0x4d, 0x9f, 0x56, 0x61, 0x9b, 0x88, 0x1d, 0xea, 0xa3, 0x8f, 0x46, 0x25, 0x8, 0xcc, 0xf9},
		privateKey)
}
