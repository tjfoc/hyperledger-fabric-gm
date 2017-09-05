/*
	Hash 选项
*/

package gm

import (
	"hash"

	"github.com/hyperledger/fabric/bccsp"
)

//定义hasher 结构体，实现内部的一个 Hasher 接口
type hasher struct {
	hash func() hash.Hash
}

func (c *hasher) Hash(msg []byte, opts bccsp.HashOpts) (hash []byte, err error) {
	h := c.hash()
	h.Write(msg)
	return h.Sum(nil), nil
}

func (c *hasher) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	return c.hash(), nil
}
