## 更新日志

0.9 :
- 基于 Hyperledger/fabric 1.0.2 实现
- 编译 cryptogen 工具生成国密版密钥和证书文件
- 编译 configtxgen 工具生成创世区块和相关通道配置
- 启用TLS需要注意</br>

    需要修改编译chaincode的容器：hyperledger/fabric-ccenv</br>
    将 hyperledger/fabric-ccenv 中的fabric源码替换成国密版的fabric</br>