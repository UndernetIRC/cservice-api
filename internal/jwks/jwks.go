// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package jwks

import (
	"encoding/json"
	"encoding/pem"
	"os"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/undernetirc/cservice-api/internal/config"
)

func GenerateJWKS() []byte {
	atKey, _ := os.ReadFile(config.Conf.JWT.PublicKey)
	atPem, _ := pem.Decode(atKey)
	atJWK := jose.JSONWebKey{Key: atPem.Bytes, Algorithm: config.Conf.JWT.SigningMethod, Use: "sig", KeyID: "at"}
	rtKey, _ := os.ReadFile(config.Conf.JWT.RefreshPublicKey)
	rtPem, _ := pem.Decode(rtKey)
	rtJWK := jose.JSONWebKey{Key: rtPem.Bytes, Algorithm: config.Conf.JWT.SigningMethod, Use: "sig", KeyID: "rt"}
	pubJWKS := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{atJWK, rtJWK}}

	var pubJSJWKS []byte

	pubJSJWKS, err := json.Marshal(pubJWKS)
	if err != nil {
		panic(err)
	}

	return pubJSJWKS
}
