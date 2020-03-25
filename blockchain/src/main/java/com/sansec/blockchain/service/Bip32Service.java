package com.sansec.blockchain.service;

import com.sansec.blockchain.voModel.VoKey;
import com.sansec.common.crypto.Key;
import com.sansec.common.crypto.bip32.ExtendedKey;
import com.sansec.common.result.Result;
import com.sansec.common.tools.Base64Tools;
import org.springframework.stereotype.Service;

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/2/26 0026 16:32
 */
@Service
public class Bip32Service {
    public Result createNew (){
        ExtendedKey ekey = ExtendedKey.createNew();
        Key master = ekey.getMaster();
        VoKey voKey = new VoKey();
        voKey.setRawPrivateKey(Base64Tools.HexUtils.toHex(master.getRawPrivateKey()));
        voKey.setComPublicKey(Base64Tools.HexUtils.toHex(master.getRawPublicKey()));
        voKey.setRawPubilcKey(Base64Tools.HexUtils.toHex(master.getRawPublicKey(false)));
        voKey.setAddress(Base64Tools.HexUtils.toHex(master.getRawAddress()));
        return Result.success(voKey);
    }
}
