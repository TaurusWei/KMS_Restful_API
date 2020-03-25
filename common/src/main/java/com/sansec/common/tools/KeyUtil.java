package com.sansec.common.tools;

import com.sansec.asn1.DERBitString;
import com.sansec.asn1.DERNull;
import com.sansec.asn1.pkcs.*;
import com.sansec.asn1.x509.AlgorithmIdentifier;
import com.sansec.asn1.x509.RSAPublicKeyStructure;
import com.sansec.asn1.x509.SubjectPublicKeyInfo;
import com.sansec.common.exception.KeyUtilException;
import com.sansec.common.exception.NoneExistException;
import com.sansec.jce.provider.JCESM2PrivateKey;
import com.sansec.jce.provider.JCESM2PublicKey;
import com.sansec.jce.provider.SwxaProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class KeyUtil {

	public static final String PROVIDER = "SwxaJCE";

	public static PublicKey generatePublicKey(String basePubKey) throws KeyUtilException {

		PublicKey publicKey = null;
		try {
			publicKey = generateRSAPublicKey(basePubKey);
		} catch (Exception e) {
			e.printStackTrace();
			try {
				publicKey = generateSM2PublicKey(basePubKey);
			} catch (Exception e2) {
				throw new KeyUtilException(e2);
			}
		}
		return publicKey;
	}

	public static PublicKey generatePublicKey(byte[] derPubKey) throws KeyUtilException {
		PublicKey publicKey = null;
		try {
			publicKey = generateRSAPublicKey(derPubKey);
		} catch (Exception e) {
			e.printStackTrace();
			try {
				publicKey = generateSM2PublicKey(derPubKey);
			} catch (Exception e2) {
				e.printStackTrace();
				throw new KeyUtilException(e2);
			}
		}
		return publicKey;
	}

	public static PrivateKey generatePrivateKey(String basePriKey) throws KeyUtilException {
		PrivateKey privateKey = null;
		try {
			privateKey = generateRSAPrivateKey(basePriKey);
		} catch (Exception e) {
			e.printStackTrace();
			try {
				privateKey = generateSM2PrivateKey(basePriKey);
			} catch (Exception e2) {
				e2.printStackTrace();
				throw new KeyUtilException(e2);
			}
		}
		return privateKey;
	}

	public static PrivateKey generatePrivateKey(byte[] derPriKey) throws KeyUtilException {
		PrivateKey privateKey = null;
		try {
			privateKey = generateRSAPrivateKey(derPriKey);
		} catch (Exception e) {
			e.printStackTrace();
			try {
				privateKey = generateSM2PrivateKey(derPriKey);
			} catch (Exception e2) {
				e2.printStackTrace();
				throw new KeyUtilException(e2);
			}
		}
		return privateKey;
	}

	////////////////////////////////////////////////////
	// RSA
	public static RSAPublicKey generateRSAPublicKey(String basePubKey) throws KeyUtilException {
		return generateRSAPublicKey(Base64Tools.decode(basePubKey));
	}

	public static RSAPublicKey generateRSAPublicKey(byte[] derPubKey) throws KeyUtilException {
		RSAPublicKey key = null;
		try {
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derPubKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA", PROVIDER);
			key = (RSAPublicKey) keyFactory.generatePublic(keySpec);
		} catch (Exception e) {
			e.printStackTrace();
			throw new KeyUtilException(e);
		}

		return key;
	}

	public static RSAPrivateCrtKey generateRSAPrivateKey(String basePriKey) throws KeyUtilException {
		return generateRSAPrivateKey(Base64Tools.decode(basePriKey));
	}

	public static RSAPrivateCrtKey generateRSAPrivateKey(byte[] derPriKey) throws KeyUtilException {

		RSAPrivateCrtKey key = null;
		try {
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(derPriKey);
			KeyFactory factory = KeyFactory.getInstance("RSA", PROVIDER);
			key = (RSAPrivateCrtKey) factory.generatePrivate(spec);
		} catch (Exception e) {
			e.printStackTrace();
			throw new KeyUtilException(e);
		}

		return key;
	}

	////////////////////////////////////////////////////
	// SM2

	public static JCESM2PublicKey generateSM2PublicKey(String basePubKey) throws KeyUtilException {
		return generateSM2PublicKey(Base64Tools.decode(basePubKey));
	}

	public static JCESM2PublicKey generateSM2PublicKey(byte[] derPubKey) throws KeyUtilException {

		JCESM2PublicKey key = null;
		try {
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derPubKey);
			KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
			key = (JCESM2PublicKey) keyFactory.generatePublic(keySpec);
		} catch (Exception e) {
			e.printStackTrace();
			throw new KeyUtilException(e);
		}

		return key;
	}

	public static JCESM2PrivateKey generateSM2PrivateKey(String basePriKey) throws KeyUtilException {
		return generateSM2PrivateKey(Base64Tools.decode(basePriKey));
	}

	public static JCESM2PrivateKey generateSM2PrivateKey(byte[] derPriKey) throws KeyUtilException {

		JCESM2PrivateKey key = null;
		try {
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(derPriKey);
			KeyFactory factory = KeyFactory.getInstance("SM2", PROVIDER);
			key = (JCESM2PrivateKey) factory.generatePrivate(spec);
		} catch (Exception e) {
			e.printStackTrace();
			throw new KeyUtilException(e);
		}

		return key;
	}

	///////////////////////////////////////////
	// 对称

	public static SecretKey generateSecretKey(String alg, String baseKey) throws KeyUtilException {
		return generateSecretKey(alg, Base64Tools.decode(baseKey));
	}

	public static SecretKey generateSecretKey(String alg, byte[] derKey) throws KeyUtilException {
		return new SecretKeySpec(derKey, alg);

	}

	public static SecretKey generateSecretKey(String alg, int length) throws KeyUtilException {
		KeyGenerator generator;
		try {
			generator = KeyGenerator.getInstance(alg, PROVIDER);
		} catch (Exception e) {
			e.printStackTrace();
			throw new KeyUtilException(e);
		}
		generator.init(length);
		SecretKey skey = generator.generateKey();
		return skey;
	}
	////////////////////////////////////////////////////////////
	// to string

	public static String key2BaseString(Key key) {
		return Base64Tools.encode(key.getEncoded());
	}

	public static int getBitLength(PublicKey publicKey) throws KeyUtilException {
		if (publicKey instanceof RSAPublicKey) {
			RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
			return rsaPublicKey.getModulus().bitLength();
		} else if (publicKey instanceof JCESM2PublicKey) {
			return 256;
		} else {
			throw new KeyUtilException("UnKnow key algorithm : " + publicKey.getAlgorithm());
		}

	}

	public static KeyPair genKeyPair(int keyLength, String alg) throws KeyUtilException {
		if (!alg.equals("RSA") && !alg.equals("SM2")) {
			throw new KeyUtilException("Key algorithm must be SM2 or RSA");
		}
	/*	if (alg.equals("RSA") && keyLength != 1024 && keyLength != 2048) {
			throw new KeyUtilException("RSA key length must be 2048");
		}*/
		if (alg.equals("SM2") && keyLength != 256) {
			throw new KeyUtilException("SM2 key length must be 256");
		}

		KeyPair pair = null;
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(alg,PROVIDER);
			generator.initialize(keyLength);
			pair = generator.generateKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
			throw new KeyUtilException("gen key pair error:" + e.getMessage());
		}

		return pair;
	}

	public static KeyPair genKeyPair_Internal(int index, String alg) throws KeyUtilException, NoneExistException {
		if (index < 1 || index > 100) {
			throw new KeyUtilException("invalid key index[1-100]");
		}

		KeyPair pair = null;
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(alg, PROVIDER);
			int bitlength = index << 16;
			generator.initialize(bitlength);
			pair = generator.generateKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
			throw new KeyUtilException("gen key pair error:" + e.getMessage());
		}

		if (pair == null) {
			throw new NoneExistException(alg + " " + index + " keypair isn't existing");
		}

		return pair;
	}

	public static KeyPair genRSAKeyPair_Internal(int index) throws KeyUtilException, NoneExistException {
		KeyPair pair = genKeyPair_Internal(index, "RSA");

		return pair;

	}

	public static KeyPair genSM2KeyPair_Internal(int index) throws KeyUtilException, NoneExistException {

		KeyPair pair = genKeyPair_Internal(index, "SM2");

		return pair;

	}

	public static SecretKey genSecretKey_Internal(int index, String alg) throws KeyUtilException {

		if ((index < 1 || index > 1000)) {
			throw new KeyUtilException("invalid key index[1-1000]");
		}
		SecretKey key = null;
		try {
			KeyGenerator generator = KeyGenerator.getInstance(alg, PROVIDER);
			int bitlength = index << 16;
			generator.init(bitlength);
			key = generator.generateKey();
		} catch (Exception e) {
			e.printStackTrace();
			throw new KeyUtilException("gen secret key error:" + e.getMessage());
		}

		return key;

	}

	public static SecretKey genDefaultKey(String alg) {
		byte[] keyValue;
		try {
			keyValue = CryptoTools.digest("SHA1", "DEFAULTKEY".getBytes(), null);
			keyValue = Arrays.copyOfRange(keyValue, 0, 16);
		} catch (Exception e) {
			e.printStackTrace();
			keyValue = new byte[16];
		}

		return new SecretKeySpec(keyValue, alg);
	}
	
	/**
	 * generate rsa PublicKey from n and e
	 * @param n
	 * @param e
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public static PublicKey getRSAPublicKey(byte[] n, byte[] e) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
		
		BigInteger bN = new BigInteger(1, n);
		BigInteger bE = new BigInteger(1, e);
		
		RSAPublicKeyStructure structure = new RSAPublicKeyStructure(bN, bE);
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, new DERNull()), structure.getDERObject());
		byte[] encodedKey = info.getEncoded();
		
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA", SwxaProvider.PROVIDER_NAME);
		PublicKey key = keyFactory.generatePublic(keySpec);
		
		return key;
	}
	
	/**
	 * generate rsa PrivateKey from n,e,d,p,q,dp,dq and coef
	 * @param n
	 * @param e
	 * @param d
	 * @param p
	 * @param q
	 * @param dp
	 * @param dq
	 * @param coef
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public static PrivateKey getRSAPrivateKey(byte[] n, byte[] e, byte[] d, byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] coef) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
		
		BigInteger bN = new BigInteger(1, n);
		BigInteger bE = new BigInteger(1, e);
		BigInteger bD = new BigInteger(1, d);
		BigInteger bP = new BigInteger(1, p);
		BigInteger bQ = new BigInteger(1, q);
		BigInteger bP1 = new BigInteger(1, dp);
		BigInteger bQ1 = new BigInteger(1, dq);
		BigInteger bCoef = new BigInteger(1, coef);
		
		RSAPrivateKeyStructure structure = new RSAPrivateKeyStructure(bN,bE,bD,bP,bQ,bP1,bQ1,bCoef);
		PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, new DERNull()), structure.getDERObject());
		byte[] encodedKey = info.getEncoded();
		
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA", SwxaProvider.PROVIDER_NAME);
		PrivateKey key = keyFactory.generatePrivate(keySpec);
		
		return key;
	}
	
	/**
	 * generate sm2 PublicKey from x and y
	 * @param x
	 * @param y
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public static PublicKey getSM2PubicKey(byte[] x, byte[] y) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
		
		BigInteger bX = new BigInteger(1, x);
		BigInteger bY = new BigInteger(1, y);
		
		SM2PublicKeyStructure structure = new SM2PublicKeyStructure(new ECPoint(bX, bY));
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.ecPublicKey, GBObjectIdentifiers.sm2), structure.getDERObject());
		byte[] encodedKey = info.getEncoded();
		
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
		KeyFactory keyFactory = KeyFactory.getInstance("SM2", SwxaProvider.PROVIDER_NAME);
		PublicKey key = keyFactory.generatePublic(keySpec);
		
		return key;
	}
	
	public static PrivateKey getSM2PrivateKey(byte[] x, byte[] y, byte[] d) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
		
		DERBitString pubkey = null;
		if(x != null && x.length > 0 && y != null && y.length > 0){
			BigInteger bX = new BigInteger(1, x);
			BigInteger bY = new BigInteger(1, y);
			
			pubkey = new DERBitString(new SM2PublicKeyStructure(new ECPoint(bX, bY)).getPublicKey());
		}

		BigInteger bD = new BigInteger(1, d);
		
		SM2PrivateKeyStructure structure = new SM2PrivateKeyStructure(bD, pubkey, null);
		PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.ecPublicKey, GBObjectIdentifiers.sm2), structure.getDERObject());
		byte[] encodedKey = info.getEncoded();
		
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
		KeyFactory keyFactory = KeyFactory.getInstance("SM2", SwxaProvider.PROVIDER_NAME);
		PrivateKey key = keyFactory.generatePrivate(keySpec);
		
		return key;
	}

}
