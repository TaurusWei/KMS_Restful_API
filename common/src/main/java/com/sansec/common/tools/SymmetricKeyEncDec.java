package com.sansec.common.tools;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SymmetricKeyEncDec {

	private static final Logger logger = LoggerFactory.getLogger(SymmetricKeyEncDec.class);
	private static final String k = "TQZsRzHnswB3UM4A";
	private static final String transformation = "AES/ECB/PKCS5PADDING";
	private static final byte[] loginkey = "TQZsRzHnswB3UM4A".getBytes();
	
	public static String EncDec(String data, int flag){
		String alg = transformation.substring(0, transformation.indexOf("/"));
		SecretKey key = new SecretKeySpec(k.getBytes(), alg);
		if(flag == Cipher.ENCRYPT_MODE){
			return encryptStringReturnBase64(key, transformation, data);
		}else{
			return decryptBase64ReturnString(key, transformation, data);
		}
	}

    public static byte[] EncDec(byte[] data, int flag) throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String alg = transformation.substring(0, transformation.indexOf("/"));
        Key key;
        byte[] encrypt = null;
        KeyGenerator kg = KeyGenerator.getInstance(alg, "SwxaJCE");
        kg.init(1<<16);
        key = kg.generateKey();
        Cipher cipher = Cipher.getInstance(transformation,"SwxaJCE");
        cipher.init(flag, key);
        encrypt = cipher.doFinal(data);
        return encrypt;
    }
    
    //使用密码卡一号对称密钥加密转Base64
    public static String EncReturnBase64(byte[] data) {
        String alg = transformation.substring(0, transformation.indexOf("/"));
        Key key;
        byte[] encrypt = null;
        try{
	        KeyGenerator kg = KeyGenerator.getInstance(alg, "SwxaJCE");
	        kg.init(1<<16);
	        key = kg.generateKey();
	        Cipher cipher = Cipher.getInstance(transformation,"SwxaJCE");
	        cipher.init(Cipher.ENCRYPT_MODE, key);
	        encrypt = cipher.doFinal(data);
        }catch(Exception e) {
			e.printStackTrace();
        	logger.error(e.getMessage());
        }
            
        return Base64.encodeBase64String(encrypt);
    }

	public static byte[] EncDec(byte[] data, int flag, byte[] key, String algorithm){
//		String alg = algorithm.substring(0, algorithm.indexOf("/"));
		SecretKey secretkey = new SecretKeySpec(key, algorithm);
		byte[] encDecData = null;
		try {
			Cipher cipher = Cipher.getInstance(algorithm,"SwxaJCE");
//			System.out.println(cipher.getProvider().toString());
			cipher.init(flag, secretkey);
			encDecData = cipher.doFinal(data);
		} catch (Exception e){
			e.printStackTrace();
			logger.error(e.getMessage());
		}
		return encDecData;
	}
	public static byte[] HMac(byte[] data, byte[] key, String hmacAlg){
		String algorithm = hmacAlg.replace("-","");
		algorithm = algorithm.replace("_", "");
		try{
	         SecretKeySpec signingKey = new SecretKeySpec(key, "Hmac"+algorithm);
	         Mac mac = Mac.getInstance("Hmac"+algorithm,"SwxaJCE");
	         mac.init(signingKey);
	         return mac.doFinal(data);
	      } catch (Exception e){
			e.printStackTrace();
				logger.error(e.getMessage());
	      }
	      return null;
	}

	public static byte[] HMacVerify(byte[] data, byte[] key, String hmacAlg){
		String algorithm = hmacAlg.replace("-","");
		algorithm = algorithm.replace("_", "");
		try{
			SecretKeySpec signingKey = new SecretKeySpec(key, "Hmac"+algorithm);
			Mac mac = Mac.getInstance("Hmac"+algorithm,"SwxaJCE");
			mac.init(signingKey);
			return mac.doFinal(data);
		} catch (Exception e){
			e.printStackTrace();
			logger.error(e.getMessage());
		}
		return null;
	}

	private static String encryptStringReturnBase64(SecretKey key, String transformation, String data){
		String encrypt = null;
		try {
			Cipher cipher = Cipher.getInstance(transformation,"SwxaJCE");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] tTemp = cipher.doFinal(data.getBytes());
			encrypt = Base64.encodeBase64String(tTemp);
		} catch (Exception e){
			e.printStackTrace();
			logger.error(e.getMessage());
		}
		return encrypt;
	}
	
	
	
	private static String decryptBase64ReturnString(SecretKey key, String transformation, String data){
		String decrypt = null;
		try{
			Cipher cipher = Cipher.getInstance(transformation,"SwxaJCE");
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] tResult = cipher.doFinal(Base64.decodeBase64(data));
			decrypt = new String(tResult);
		}catch (Exception e) {
			e.printStackTrace();
			logger.error(e.getMessage());
		}
		return decrypt;
	}
	
	public static byte[] LoginuserEncDec(byte[] data, int flag) throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String alg = "AES/ECB/NOPADDING".substring(0, transformation.indexOf("/"));
        Key key;
        byte[] encrypt = null;
            KeyGenerator kg = KeyGenerator.getInstance(alg, "SwxaJCE");
            kg.init(1<<16);
            key = kg.generateKey();
            Cipher cipher = Cipher.getInstance("AES/ECB/NOPADDING","SwxaJCE");
            cipher.init(flag, key);
            encrypt = cipher.doFinal(data);
        return encrypt;
    }
	
	public static void main(String[] args) {
		String str = "12345678123456781234567812345678";
		System.out.println(Base64.encodeBase64String(str.getBytes()));
		byte[] enresultBytes = null;
		try {
			enresultBytes = LoginuserEncDec(str.getBytes(), Cipher.ENCRYPT_MODE);
		} catch (InvalidKeyException | NoSuchProviderException | NoSuchAlgorithmException | NoSuchPaddingException
				| BadPaddingException | IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(Base64.encodeBase64String(enresultBytes));
		
		try {
			System.out.println(Base64.encodeBase64String(LoginuserEncDec(enresultBytes, Cipher.DECRYPT_MODE)));
		} catch (InvalidKeyException | NoSuchProviderException | NoSuchAlgorithmException | NoSuchPaddingException
				| BadPaddingException | IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
