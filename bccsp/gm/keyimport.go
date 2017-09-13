/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package gm

import (
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/gm/sm2"
	"github.com/hyperledger/fabric/bccsp/utils"
)

//实现内部的 KeyImporter 接口
type gmsm4ImportKeyOptsKeyImporter struct{}

func (*gmsm4ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	sm4Raw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if sm4Raw == nil {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	return &gmsm4PrivateKey{utils.Clone(sm4Raw), false}, nil
}

type gmsm2PrivateKeyImportOptsKeyImporter struct{}

func (*gmsm2PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {

	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[GMSM2PrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[GMSM2PrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	// lowLevelKey, err := utils.DERToPrivateKey(der)
	// if err != nil {
	// 	return nil, fmt.Errorf("Failed converting PKIX to GMSM2 public key [%s]", err)
	// }
	
	// gmsm2SK, ok := lowLevelKey.(*sm2.PrivateKey)
	// if !ok {
	// 	return nil, errors.New("Failed casting to GMSM2 private key. Invalid raw material.")
	// }

	//gmsm2SK, err :=  sm2.ParseSM2PrivateKey(der)
	gmsm2SK, err :=  sm2.ParsePKCS8UnecryptedPrivateKey(der)

	if err != nil {
		return nil, fmt.Errorf("Failed converting to GMSM2 private key [%s]", err)
	}

	return &gmsm2PrivateKey{gmsm2SK}, nil
}


type gmsm2PublicKeyImportOptsKeyImporter struct{}

func (*gmsm2PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[GMSM2PublicKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[GMSM2PublicKeyImportOpts] Invalid raw. It must not be nil.")
	}

	// lowLevelKey, err := utils.DERToPrivateKey(der)
	// if err != nil {
	// 	return nil, fmt.Errorf("Failed converting PKIX to GMSM2 public key [%s]", err)
	// }

	// gmsm2SK, ok := lowLevelKey.(*sm2.PrivateKey)
	// if !ok {
	// 	return nil, errors.New("Failed casting to GMSM2 private key. Invalid raw material.")
	// }

	gmsm2SK, err := sm2.ParseSm2PublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting to GMSM2 public key [%s]", err)
	}


	return &gmsm2PublicKey{gmsm2SK}, nil
}
