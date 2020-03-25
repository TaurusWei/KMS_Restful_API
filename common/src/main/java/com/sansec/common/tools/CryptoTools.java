package com.sansec.common.tools;


import com.sansec.common.exception.KeyUtilException;
import com.sansec.common.exception.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.*;

public class CryptoTools {
	public static final String PROVIDER = "SwxaJCE";

	private static final String modeP = "/ECB/PKCS5Padding";

	public static byte[] encrypt(String alg, PublicKey publicKey, byte[] data) throws CryptoException {
		byte[] result = null;
		try {
			Cipher cipher = Cipher.getInstance(alg, PROVIDER);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			result = cipher.doFinal(data);
		} catch (Exception e) {
			throw new CryptoException(e);
		}

		return result;

	}

	public static String encrypt2BaseString(String alg, PublicKey publicKey, byte[] data) throws CryptoException {
		return Base64Tools.encode(encrypt(alg, publicKey, data));
	}

	public static byte[] decrypt(PrivateKey privateKey, byte[] encData) throws CryptoException {

		byte[] result = null;
		try {
			String alg = privateKey.getAlgorithm();
			if (alg.equals("RSA")) {
				alg = "RSA/ECB/PKCS1Padding";
			}
			Cipher cipher = Cipher.getInstance(alg, PROVIDER);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			result = cipher.doFinal(encData);
		} catch (Exception e) {
			throw new CryptoException(e);
		}

		return result;
	}

	public static String decrypt2BaseString(PrivateKey privateKey, byte[] encData) throws CryptoException {
		return Base64Tools.encode(decrypt(privateKey, encData));
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// �Գ�
	public static byte[] encrypt(SecretKey secretKey, String alg, byte[] data) throws CryptoException {
		byte[] result = null;
		try {
			if (alg.indexOf("/") == -1) {
				alg += modeP;
			}
			Cipher cipher = Cipher.getInstance(alg, PROVIDER);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			result = cipher.doFinal(data);
		} catch (Exception e) {
			throw new CryptoException(e);
		}

		return result;

	}

	public static byte[] encrypt(int index, String alg, byte[] data) throws CryptoException {
		SecretKey secretKey;
		try {
			secretKey = KeyUtil.genSecretKey_Internal(index, alg);
		} catch (KeyUtilException e) {
			throw new CryptoException(e);
		}

		byte[] result = encrypt(secretKey, alg, data);

		return result;

	}

	public static byte[] encrypt(SecretKey secretKey, String mode, String padding, byte[] data) throws CryptoException {

		byte[] result = null;
		try {
			String alg = secretKey.getAlgorithm() + "/" + mode + "/" + padding;
			result = encrypt(secretKey, alg, data);
		} catch (Exception e) {
			throw new CryptoException(e);
		}

		return result;

	}

	public static String encrypt2BaseString(SecretKey secretKey, String mode, String padding, byte[] data)
			throws CryptoException {
		return Base64Tools.encode(encrypt(secretKey, mode, padding, data));
	}

	public static String encrypt2BaseString(SecretKey secretKey, String alg, byte[] data) throws CryptoException {
		return Base64Tools.encode(encrypt(secretKey, alg, data));
	}

	public static String encrypt2BaseString(int index, String alg, byte[] data) throws CryptoException {
		return Base64Tools.encode(encrypt(index, alg, data));
	}

	public static byte[] decrypt(SecretKey secretKey, String alg, byte[] data) throws CryptoException {
		byte[] result = null;
		try {
			if (alg.indexOf("/") == -1) {
				alg += modeP;
			}
			Cipher cipher = Cipher.getInstance(alg, PROVIDER);
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			result = cipher.doFinal(data);
		} catch (Exception e) {
			throw new CryptoException(e);
		}

		return result;
	}

	public static byte[] decrypt(int index, String alg, byte[] data) throws CryptoException {
		SecretKey secretKey;
		try {
			secretKey = KeyUtil.genSecretKey_Internal(index, alg);
		} catch (KeyUtilException e) {
			throw new CryptoException(e);
		}

		byte[] result = decrypt(secretKey, alg, data);

		return result;
	}

	public static byte[] decrypt(SecretKey secretKey, String mode, String padding, byte[] data) throws CryptoException {
		byte[] result = null;
		try {
			String alg = secretKey.getAlgorithm() + "/" + mode + "/" + padding;
			result = decrypt(secretKey, alg, data);
		} catch (Exception e) {
			throw new CryptoException(e);
		}

		return result;
	}

	public static String decrypt2BaseString(SecretKey secretKey, String mode, String padding, byte[] data)
			throws CryptoException {
		return Base64Tools.encode(decrypt(secretKey, mode, padding, data));
	}

	public static String decrypt2BaseString(SecretKey secretKey, String alg, byte[] data) throws CryptoException {
		return Base64Tools.encode(decrypt(secretKey, alg, data));
	}

	public static String decrypt2BaseString(int index, String alg, byte[] data) throws CryptoException {
		return Base64Tools.encode(decrypt(index, alg, data));
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////
	// signature

	public static boolean verify(String alg, PublicKey publicKey, byte[] data, byte[] signature)
			throws CryptoException {

		boolean result = false;
		try {
			Signature sign = Signature.getInstance(alg, PROVIDER);
			sign.initVerify(publicKey);
			sign.update(data);
			result = sign.verify(signature);
		} catch (Exception e) {
			throw new CryptoException(e);
		}

		return result;

	}

	public static boolean verifyBaseString(String alg, PublicKey publicKey, String data, String baseSignature)
			throws CryptoException {
		return verify(alg, publicKey, data.getBytes(), Base64Tools.decode(baseSignature));
	}

	public static byte[] sign(String alg, PrivateKey privateKey, byte[] data) throws CryptoException {

		byte[] result = null;
		try {
			Signature signature = Signature.getInstance(alg, PROVIDER);
			signature.initSign(privateKey);
			signature.update(data);
			result = signature.sign();
		} catch (Exception e) {
			throw new CryptoException(e);
		}

		return result;
	}

	public static String sign2BaseString(String alg, PrivateKey privateKey, byte[] data) throws CryptoException {
		return Base64Tools.encode(sign(alg, privateKey, data));
	}

	public static byte[] digest(String algorithm, byte[] input, byte[] sm2PubKeyWithId)
			throws NoSuchAlgorithmException, NoSuchProviderException {

		MessageDigest digest = MessageDigest.getInstance(algorithm, PROVIDER);

		if (algorithm.equals("SM3") && sm2PubKeyWithId != null) {
			digest.update(sm2PubKeyWithId);
		}
		digest.update(input);

		return digest.digest();
	}
}
