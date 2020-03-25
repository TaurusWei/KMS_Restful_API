package com.sansec.common.crypto.bip44;



import com.sansec.common.crypto.CoinTypes;
import com.sansec.common.crypto.ECKeyPair;
import com.sansec.common.crypto.bip32.ExtendedKey;
import com.sansec.common.crypto.bip32.Index;
import com.sansec.common.crypto.bitcoin.BitCoinECKeyPair;
import com.sansec.common.crypto.ethereum.EthECKeyPair;
import com.sansec.common.exception.ValidationException;
import com.sansec.common.tools.Base64Tools;

import java.util.Map;
import java.util.WeakHashMap;

/**
 * @author QuincySx
 * @date 2018/3/5 下午3:48
 */
public class CoinPairDerive {
    private static Map<String, ExtendedKey> sExtendedKeyMap = new WeakHashMap<>();

    private ExtendedKey mExtendedKey;

    public CoinPairDerive(ExtendedKey extendedKey) {
        mExtendedKey = extendedKey;
    }

    public ExtendedKey deriveByExtendedKey(AddressIndex addressIndex) throws ValidationException {
        String keyStr = Base64Tools.HexUtils.toHex(mExtendedKey.getChainCode()) + Base64Tools.HexUtils.toHex(mExtendedKey.getMaster().getRawPublicKey()) + addressIndex.toString();
        byte[] byteKey = Base64Tools.SHA256.sha256(keyStr.getBytes());
        ExtendedKey extendedKey = sExtendedKeyMap.get(Base64Tools.HexUtils.toHex(byteKey));
        if (extendedKey != null) {
            return extendedKey;
        }
        int address = addressIndex.getValue();
        int change = addressIndex.getParent().getValue();
        int account = addressIndex.getParent().getParent().getValue();
        CoinTypes coinType = addressIndex.getParent().getParent().getParent().getValue();
        int purpose = addressIndex.getParent().getParent().getParent().getParent().getValue();

        ExtendedKey child = mExtendedKey
                .getChild(Index.hard(purpose))
                .getChild(Index.hard(coinType.coinType()))
                .getChild(Index.hard(account))
                .getChild(change)
                .getChild(address);
        sExtendedKeyMap.put(Base64Tools.HexUtils.toHex(byteKey), child);
        return child;
    }

    public ECKeyPair derive(AddressIndex addressIndex) throws ValidationException {
        CoinTypes coinType = addressIndex.getParent().getParent().getParent().getValue();
        ExtendedKey child = deriveByExtendedKey(addressIndex);
        ECKeyPair ecKeyPair = convertKeyPair(child, coinType);
        return ecKeyPair;
    }

    public ECKeyPair convertKeyPair(ExtendedKey child, CoinTypes coinType) throws ValidationException {
        switch (coinType) {
            case BitcoinTest:
                return BitCoinECKeyPair.parse(child.getMaster(), true);// convertBitcoinKeyPair(new BigInteger(1, child.getMaster().getPrivate()), true);
            case Ethereum:
                return EthECKeyPair.parse(child.getMaster());//convertEthKeyPair(new BigInteger(1, child.getMaster().getPrivate()));
            case Bitcoin:
            default:
                return BitCoinECKeyPair.parse(child.getMaster(), false);//convertBitcoinKeyPair(new BigInteger(1, child.getMaster().getPrivate()), false);
        }
    }
}
