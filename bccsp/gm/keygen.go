package gm

import (
	"crypto/elliptic"
	"errors"
	"github.com/hyperledger/fabric/bccsp"
)

//定义国密 keygen 结构体，实现 KeyGenerator 接口
type gmKeyGenerator struct {
	curve elliptic.Curve
}

func (gm *gmKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {

	return nil, errors.New("Not implemented")

}
