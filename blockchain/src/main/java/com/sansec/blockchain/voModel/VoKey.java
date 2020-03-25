package com.sansec.blockchain.voModel;

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/2/26 0026 17:38
 */
public class VoKey {
    public String rawPrivateKey;
    public String rawPubilcKey;
    public String comPublicKey;
    public String address;
    public String getRawPrivateKey() {
        return rawPrivateKey;
    }

    public void setRawPrivateKey(String rawPrivateKey) {
        this.rawPrivateKey = rawPrivateKey;
    }

    public String getRawPubilcKey() {
        return rawPubilcKey;
    }

    public void setRawPubilcKey(String rawPubilcKey) {
        this.rawPubilcKey = rawPubilcKey;
    }

    public String getComPublicKey() {
        return comPublicKey;
    }

    public void setComPublicKey(String comPublicKey) {
        this.comPublicKey = comPublicKey;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }


}
