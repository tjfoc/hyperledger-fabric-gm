/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm_test

import (
	"testing"

	"github.com/hyperledger/fabric/core/comm"
	"github.com/stretchr/testify/assert"
	tls "github.com/tjfoc/gmtls"
	"google.golang.org/grpc/credentials"
)

func TestCreds(t *testing.T) {
	var creds credentials.TransportCredentials
	creds = comm.NewServerTransportCredentials(&tls.Config{})
	_, _, err := creds.ClientHandshake(nil, "", nil)
	assert.EqualError(t, err, comm.ClientHandshakeNotImplError.Error())
	err = creds.OverrideServerName("")
	assert.EqualError(t, err, comm.OverrrideHostnameNotSupportedError.Error())
	clone := creds.Clone()
	assert.Equal(t, creds, clone)
	assert.Equal(t, "1.2", creds.Info().SecurityVersion)
	assert.Equal(t, "tls", creds.Info().SecurityProtocol)
}
