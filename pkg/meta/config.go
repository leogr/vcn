/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 */

package meta

import (
	"math/big"
	"os"
	"time"
)

func DashboardURL() string {
	switch StageEnvironment() {
	case StageProduction:
		return "https://dashboard.codenotary.io"
	case StageStaging:
		return "https://dashboard.staging.codenotary.io"
	case StageTest:
		return os.Getenv("VCN_TEST_DASHBOARD")
	default:
		return "https://dashboard.codenotary.io"
	}
}

func MainNetEndpoint() string {
	switch StageEnvironment() {
	case StageProduction:
		return "https://main.codenotary.io"
	case StageStaging:
		return "https://main.staging.codenotary.io"
	case StageTest:
		return os.Getenv("VCN_TEST_NET")
	default:
		return "https://main.codenotary.io"
	}
}

func FoundationEndpoint() string {
	switch StageEnvironment() {
	case StageProduction:
		return "https://api.codenotary.io/foundation"
	case StageStaging:
		return "https://api.staging.codenotary.io/foundation"
	case StageTest:
		return os.Getenv("VCN_TEST_API")
	default:
		return "https://api.codenotary.io/foundation"
	}
}

func AssetsRelayContractAddress() string {
	switch StageEnvironment() {
	case StageProduction:
		return "0x3222c50e1917c3551c7b6ee10d8e1bb00b84062b"
	case StageStaging:
		return "0x05ce69454a13c8ac0bd20fdc48b09068f5c0a5ed"
	case StageTest:
		return os.Getenv("VCN_TEST_CONTRACT")
	default:
		return "0x3222c50e1917c3551c7b6ee10d8e1bb00b84062b"
	}
}

func OrganisationsRelayContractAddress() string {
	switch StageEnvironment() {
	case StageProduction:
		return "0x258e39ff07e6e3a2430aa951f387cfbd808835bc"
	case StageStaging:
		return "0x4a9a0547949ec55ecbf06738e8c2bad747f410bb"
	case StageTest:
		return os.Getenv("VCN_TEST_CONTRACT_ORG")
	default:
		return "0x258e39ff07e6e3a2430aa951f387cfbd808835bc"
	}
}

func WalletEndpoint() string {
	return FoundationEndpoint() + "/v1/wallet"
}

func RemainingSignOpsEndpoint() string {
	return FoundationEndpoint() + "/v1/artifact/remaining-sign-operations"
}

func ArtifactEndpoint() string {
	return FoundationEndpoint() + "/v1/artifact"
}

func ArtifactEndpointForWallet(walletAddress string) string {
	return FoundationEndpoint() + "/v1/artifact?wallet-address=" + walletAddress
}

func TxVerificationRounds() uint64 {
	return 30
}

func PollInterval() time.Duration {
	return 2 * time.Second
}

func GasPrice() *big.Int {
	return big.NewInt(0)
}

func GasLimit() uint64 {
	return 20000000
}
