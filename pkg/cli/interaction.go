/*
 * Copyright (c) 2018-2019 vChain, Inc. All Rights Reserved.
 * This software is released under GPL3.
 * The full license information can be found under:
 * https://www.gnu.org/licenses/gpl-3.0.en.html
 *
 *
 * User Interaction
 *
 * This part of the vcn code handles the concern of interaction (the *V*iew)
 *
 */

package cli

import (
	"bufio"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/dustin/go-humanize"
	"github.com/ethereum/go-ethereum/common"
	"github.com/fatih/color"
	"github.com/pkg/browser"
	"github.com/sirupsen/logrus"
	"github.com/vchain-us/vcn/internal/docker"
	"github.com/vchain-us/vcn/internal/errors"
	"github.com/vchain-us/vcn/pkg/api"
	"github.com/vchain-us/vcn/pkg/logs"
	"github.com/vchain-us/vcn/pkg/meta"
)

func Dashboard() {
	// open dashboard
	// we intentionally do not read the customer's token from disk
	// and GET the dashboard => this would be insecure as tokens would
	// be visible in server logs. in case the anyhow long-running web session
	// has expired the customer will have to log in
	url := meta.DashboardURL()
	fmt.Println(fmt.Sprintf("Taking you to <%s>", url))
	browser.OpenURL(url)
}

func Login() {
	token, _ := api.LoadToken()
	tokenValid, err := api.CheckToken(token)
	if err != nil {
		log.Fatal(err)
	}
	if !tokenValid {
		email, err := ProvidePlatformUsername()
		if err != nil {
			log.Fatal(err)
		}
		publisherExists, err := api.CheckPublisherExists(email)
		if err != nil {
			log.Fatal(err)
		}
		if publisherExists {
			password, err := ProvidePlatformPassword()
			if err != nil {
				log.Fatal(err)
			}
			err = api.Authenticate(email, password)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			log.Fatal("no such user. please create an account at: ", meta.DashboardURL())
		}
	}

	_ = api.TrackPublisher(meta.VcnLoginEvent)

	hasKeystore, err := api.HasKeystore()
	if err != nil {
		logs.LOG.WithFields(logrus.Fields{
			"error": err,
		}).Fatal("Could not access keystore directory")
	}
	if hasKeystore == false {

		fmt.Println("You have no keystore set up yet.")
		fmt.Println("<vcn> will now do this for you and upload the public key to the platform.")

		color.Set(meta.StyleAffordance())
		fmt.Print("Attention: Please pick a strong passphrase. There is no recovery possible.")
		color.Unset()
		fmt.Println()

		var keystorePassphrase string
		var keystorePassphrase2 string

		match := false
		counter := 0
		for match == false {

			counter++

			if counter == 4 {
				fmt.Println("Too many attempts failed.")
				errors.PrintErrorURLCustom("password", 404)
				os.Exit(1)

			}

			// TODO: solution for reading from file inputs whose compilation does not fail on windows
			// if terminal.IsTerminal(syscall.Stdin) {

			keystorePassphrase, _ = readPassword("Keystore passphrase: ")
			keystorePassphrase2, _ = readPassword("Keystore passphrase (reenter): ")
			fmt.Println("")
			/*} else {

				keystorePassphrase, _ = reader.ReadString('\n')
				keystorePassphrase = strings.TrimSuffix(keystorePassphrase, "\n")

				keystorePassphrase2, _ = reader.ReadString('\n')
				keystorePassphrase2 = strings.TrimSuffix(keystorePassphrase2, "\n")
			}*/

			if keystorePassphrase == "" {
				fmt.Println("Your passphrase must not be empty.")
			} else if keystorePassphrase != keystorePassphrase2 {
				fmt.Println("Your two inputs did not match. Please try again.")
			} else {
				match = true
			}

		}

		pubKey, wallet := api.CreateKeystore(keystorePassphrase)

		fmt.Println("Keystore successfully created. We are updating your user profile.\n" +
			"You will be able to sign your first asset in one minute")
		fmt.Println("Public key:\t", pubKey)
		fmt.Println("Keystore:\t", wallet)

	}

	//
	api.SyncKeys()

	fmt.Println("Login successful.")
}

// Commit => "sign"
func Sign(filename string, state meta.Status, visibility meta.Visibility, quit bool, acknowledge bool) {

	// check for token
	token, _ := api.LoadToken()
	checkOk, _ := api.CheckToken(token)
	if !checkOk {
		fmt.Println("You need to be logged in to sign.")
		fmt.Println("Proceed by authenticating yourself using <vcn login>")
		// errors.PrintErrorURLCustom("token", 428)
		os.Exit(1)
	}

	// keystore
	hasKeystore, _ := api.HasKeystore()
	if hasKeystore == false {
		fmt.Printf("You need a keystore to sign.\n")
		fmt.Println("Proceed by authenticating yourself using <vcn auth>")
		// errors.PrintErrorURLCustom("keystore", 428)
		os.Exit(1)
	}

	var err error
	var artifactHash string
	var fileSize int64 = 0

	if strings.HasPrefix(filename, "docker:") {
		artifactHash, err = docker.GetHash(filename)
		if err != nil {
			log.Fatal("failed to get hash for docker image", err)
		}
		fileSize, err = docker.GetSize(filename)
		if err != nil {
			log.Fatal("failed to get size for docker image", err)
		}
	} else {
		// file mode
		artifactHash = hash(filename)
		fi, err := os.Stat(filename)
		if err != nil {
			log.Fatal(err)
		}
		fileSize = fi.Size()
	}

	reader := bufio.NewReader(os.Stdin)

	if !acknowledge {
		fmt.Println("CodeNotary - code signing in 1 simple step:")
		fmt.Println()
		fmt.Println("Attention, by signing this asset with CodeNotary you implicitly claim its ownership.")
		fmt.Println("Doing this can potentially infringe other publisher's intellectual property under the laws of your country of residence.")
		fmt.Println("vChain and the Zero Trust Consortium cannot be held responsible for legal ramifications.")
		color.Set(color.FgGreen)
		fmt.Println()
		fmt.Println("If you are the owner of the asset (e.g. author, creator, publisher) you can continue")
		color.Unset()
		fmt.Println()
		fmt.Print("I understand and want to continue. (y/n)")
		question, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(question)) != "y" {
			os.Exit(1)
		}
	}

	passphrase, err := ProvideKeystorePassword()
	if err != nil {
		log.Fatal(err)
	}

	s := spinner.New(spinner.CharSets[1], 500*time.Millisecond)

	s.Prefix = "Signing asset... "
	s.Start()

	_ = api.TrackPublisher(meta.VcnSignEvent)
	_ = api.TrackSign(artifactHash, filepath.Base(filename), state)

	// TODO: return and display: block #, trx #
	_, _ = commitHash(artifactHash, passphrase, filepath.Base(filename), fileSize, state, visibility)

	s.Stop()
	fmt.Println("")
	fmt.Println("Asset:\t", filename)
	fmt.Println("Hash:\t", artifactHash)
	// fmt.Println("Date:\t\t", time.Now())
	// fmt.Println("Signer:\t", "<pubKey>")

	if !quit {
		if _, err := fmt.Scanln(); err != nil {
			log.Fatal(err)
		}
	}
}

func VerifyAll(files []string, quit bool) {
	_ = api.TrackPublisher(meta.VcnVerifyEvent)
	var success = true
	for _, file := range files {
		success = success && verify(file)
	}
	if !quit {
		if _, err := fmt.Scanln(); err != nil {
			log.Fatal(err)
		}
	}
	if success {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func verify(filename string) (success bool) {
	var artifactHash string
	var err error

	if strings.HasPrefix(filename, "docker:") {
		artifactHash, err = docker.GetHash(filename)
		if err != nil {
			log.Fatal("failed to get hash for docker image", err)
		}
	} else {
		artifactHash = strings.TrimSpace(hash(filename))
	}
	_ = api.TrackVerify(artifactHash, filepath.Base(filename))
	verification, err := api.BlockChainVerify(artifactHash)
	if err != nil {
		log.Fatal("unable to verify hash", err)
	}

	var artifact *api.ArtifactResponse
	if verification.Owner != common.BigToAddress(big.NewInt(0)) {
		artifact, _ = api.LoadArtifactForHash(artifactHash, verification.HashAsset())
	}
	if artifact != nil {
		printColumn("Asset", artifact.Filename, filepath.Base(filename))
		printColumn("Hash", artifactHash, "NA")
		printColumn("Date", verification.Timestamp.String(), "NA")
		printColumn("Signer", artifact.Publisher, verification.Owner.Hex())
		printColumn("Name", artifact.Name, "NA")
		if artifact.FileSize > 0 {
			printColumn("Size", humanize.Bytes(artifact.FileSize), "NA")
		} else {
			printColumn("Size", "NA", "NA")
		}
		printColumn("Company", artifact.PublisherCompany, "NA")
		printColumn("Website", artifact.PublisherWebsiteUrl, "NA")
		printColumn("Level", meta.LevelName(verification.Level), "NA")
	} else {
		printColumn("Asset", filepath.Base(filename), "NA")
		printColumn("Hash", artifactHash, "NA")
		if verification.Timestamp != time.Unix(0, 0) {
			printColumn("Date", verification.Timestamp.String(), "NA")
		} else {
			printColumn("Date", "NA", "NA")
		}
		if verification.Owner != common.BigToAddress(big.NewInt(0)) {
			printColumn("Signer", verification.Owner.Hex(), "NA")
		} else {
			printColumn("Signer", "NA", "NA")
		}
		printColumn("Name", "NA", "NA")
		printColumn("Company", "NA", "NA")
		printColumn("Website", "NA", "NA")
		printColumn("Size", "NA", "NA")
		printColumn("Level", "NA", "NA")
	}

	var c, s color.Attribute
	switch verification.Status {
	case meta.StatusTrusted:
		success = true
		c, s = meta.StyleSuccess()
	case meta.StatusUnknown:
		success = false
		c, s = meta.StyleWarning()
	default:
		success = false
		c, s = meta.StyleError()
	}
	printColumn("Status", meta.StatusName(verification.Status), "NA", c, s)

	return success
}