/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBlockchainOrganisation(t *testing.T) {
	var bo *BlockchainOrganisation

	// Nil
	assert.Empty(t, bo.Key())
	assert.Len(t, bo.MembersKeys(), 0)

	bo = &BlockchainOrganisation{}

	// Zero value
	assert.Empty(t, bo.Key())
	assert.Len(t, bo.MembersKeys(), 0)
}
