/*

 */
package gm

import (
	"errors"

	"github.com/hyperledger/fabric/bccsp"
)

//模拟实现
func NewDummyKeyStore() bccsp.KeyStore {
	return &dummyKeyStore{}
}

// 模拟的ks，实现 bccsp.KeyStore 接口
type dummyKeyStore struct {
}

// read only
func (ks *dummyKeyStore) ReadOnly() bool {
	return true
}

//test GetKey
func (ks *dummyKeyStore) GetKey(ski []byte) (k bccsp.Key, err error) {
	return nil, errors.New("Key not found. This is a dummy KeyStore")
}

//test StoreKey
func (ks *dummyKeyStore) StoreKey(k bccsp.Key) (err error) {
	return errors.New("Cannot store key. This is a dummy read-only KeyStore")
}
