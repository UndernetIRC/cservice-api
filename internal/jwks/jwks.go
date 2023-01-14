// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package jwks

import (
	"encoding/json"
	"encoding/pem"
	jose "github.com/square/go-jose/v3"
	"github.com/undernetirc/cservice-api/internal/config"
	"os"
)

func GenerateJWKS() []byte {
	pubKey, _ := os.ReadFile(config.Conf.JWT.PublicKey)
	pubPem, _ := pem.Decode(pubKey)
	pubJWK := jose.JSONWebKey{Key: pubPem.Bytes, Algorithm: config.Conf.JWT.SigningMethod, Use: "sig"}
	pubJWKS := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}

	var pubJSJWKS []byte

	pubJSJWKS, err := json.Marshal(pubJWKS)
	if err != nil {
		panic(err)
	}

	return pubJSJWKS
}
