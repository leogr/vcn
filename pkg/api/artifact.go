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

	"github.com/sirupsen/logrus"
	"github.com/vchain-us/vcn/pkg/meta"
)

// Artifact represents the set of all relevant information gathered from a digital asset.
type Artifact struct {
	Kind        string
	Name        string
	Hash        string
	Size        uint64
	ContentType string
	Metadata
}

// Copy returns a deep copy of the artifact.
func (a Artifact) Copy() Artifact {
	c := a
	if a.Metadata != nil {
		c.Metadata = nil
		c.Metadata.SetValues(a.Metadata)
	}
	return c
}

func (a Artifact) toRequest() *artifactRequest {
	aR := &artifactRequest{
		// root fields
		Kind:        a.Kind,
		Name:        a.Name,
		Hash:        a.Hash,
		Size:        a.Size,
		ContentType: a.ContentType,

		// custom metadata
		Metadata: a.Metadata,
	}

	// promote url from custom metadata to root
	aR.URL = a.Metadata.swipeString("url")

	return aR
}

type artifactRequest struct {
	// root fields
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Hash        string `json:"hash"`
	Size        uint64 `json:"size,omitempty"`
	ContentType string `json:"contentType"`
	URL         string `json:"url"`

	// custom metadata
	Metadata Metadata `json:"metadata"`

	// artifactRequest specific
	Visibility string `json:"visibility"`
	Status     string `json:"status"`
	MetaHash   string `json:"metaHash"`
}

// PagedArtifactResponse holds a page of ArtifactResponse(s) returned by the platform.
type PagedArtifactResponse struct {
	Content       []ArtifactResponse `json:"content"`
	TotalElements uint64             `json:"totalElements"`
	Pageable      struct {
		PageSize   uint64 `json:"pageSize"`
		PageNumber uint64 `json:"pageNumber"`
	} `json:"pageable"`
}

// ArtifactResponse holds artifact values returned by the platform.
type ArtifactResponse struct {
	// root fields
	Kind        string `json:"kind" vcn:"Kind"`
	Name        string `json:"name" vcn:"Name"`
	Hash        string `json:"hash" vcn:"Hash"`
	Size        uint64 `json:"size" vcn:"Size"`
	ContentType string `json:"contentType" vcn:"ContentType"`
	URL         string `json:"url" vcn:"URL"`

	// custom metadata
	Metadata Metadata `json:"metadata" vcn:"Metadata"`

	// ArtifactResponse specific
	Level             int64  `json:"level"`
	Visibility        string `json:"visibility" vcn:"Visibility"`
	Status            string `json:"status"`
	CreatedAt         string `json:"createdAt"`
	VerificationCount uint64 `json:"verificationCount"`
	SignerCount       uint64 `json:"signerCount"`
	Signer            string `json:"signer" vcn:"Signer"`
	Company           string `json:"company" vcn:"Company"`
	Website           string `json:"website" vcn:"Website"`
}

func (a ArtifactResponse) String() string {
	return fmt.Sprintf("Name:\t%s\nHash:\t%s\nStatus:\t%s\n\n",
		a.Name, a.Hash, a.Status)
}

// Artifact returns an new *Artifact from a
func (a ArtifactResponse) Artifact() *Artifact {
	return &Artifact{
		// root fields
		Kind:        a.Kind,
		Name:        a.Name,
		Hash:        a.Hash,
		Size:        a.Size,
		ContentType: a.ContentType,

		// custom metadata
		Metadata: a.Metadata,
	}
}

func (u User) createArtifact(verification *BlockchainVerification, walletAddress string,
	artifact Artifact, visibility meta.Visibility, status meta.Status) error {

	hasAuth, err := u.IsAuthenticated()
	if err != nil {
		return err
	}
	if !hasAuth {
		return makeAuthRequiredError()
	}

	aR := artifact.toRequest()
	aR.Visibility = meta.VisibilityName(visibility)
	aR.Status = meta.StatusName(status)
	aR.MetaHash = verification.MetaHash()

	restError := new(Error)
	r, err := newSling(u.token()).
		Post(meta.ArtifactEndpointForWallet(walletAddress)).
		BodyJSON(aR).Receive(nil, restError)
	if err != nil {
		return err
	}
	if r.StatusCode != 200 {
		return fmt.Errorf("request failed: %s (%d)", restError.Message,
			restError.Status)
	}
	return nil
}

// LoadArtifact fetches and returns an *ArtifactResponse for the given hash and current u, if any.
func (u *User) LoadArtifact(hash string) (*ArtifactResponse, error) {
	notFound := func() (*ArtifactResponse, error) {
		return nil, fmt.Errorf("no asset matching hash %s signed by %s found", hash, u.Email())
	}
	response := new(PagedArtifactResponse)
	restError := new(Error)
	r, err := newSling(u.token()).
		Get(meta.ArtifactEndpoint()+"/"+hash+"?scope=CURRENT_USER&size=1&sort=createdAt,desc").
		Receive(&response, restError)
	if err != nil {
		return nil, err
	}

	switch r.StatusCode {
	case 200:
		if len(response.Content) < 1 {
			return notFound()
		}
	case 404:
		return notFound()
	default:
		return nil, fmt.Errorf("request failed: %s (%d)",
			restError.Message, restError.Status)
	}

	ar := &response.Content[0]
	if ar.Hash != hash {
		return notFound()
	}

	return ar, nil
}

// ListArtifacts fetches and returns a paged list of user's artifacts.
func (u User) ListArtifacts(page uint) (*PagedArtifactResponse, error) {
	response := new(PagedArtifactResponse)
	restError := new(Error)
	url := fmt.Sprintf(
		"%s/search?limit=CURRENT_USER&sort=createdAt,desc&size=25&page=%d&group=true",
		meta.ArtifactEndpoint(),
		page,
	)
	r, err := newSling(u.token()).
		Get(url).
		Receive(&response, restError)
	if err != nil {
		return nil, err
	}

	if r.StatusCode == 200 {
		return response, nil
	}

	return nil, fmt.Errorf(
		"request failed: %s (%d)",
		restError.Message,
		restError.Status,
	)
}

// LoadArtifact fetches and returns an artifact matching the given hash and optionally a given metahash.
// Returned values depends on user permissions on the artifact, if user is nil then only
// publicly disclosable values are returned.
func LoadArtifact(user *User, hash string, metahash string) (*ArtifactResponse, error) {
	response := new(ArtifactResponse)
	restError := new(Error)
	r, err := newSling(user.token()).
		Get(meta.ArtifactEndpoint()+"/"+hash+"/"+metahash).
		Receive(&response, restError)
	logger().WithFields(logrus.Fields{
		"response":  response,
		"err":       err,
		"restError": restError,
	}).Trace("LoadArtifact")
	if err != nil {
		return nil, err
	}
	switch r.StatusCode {
	case 200:
		return response, nil
	case 404:
		return nil, fmt.Errorf("no artifact matching %s/%s found", hash, metahash)
	}
	return nil, fmt.Errorf("loading artifact failed: %+v", restError)
}
