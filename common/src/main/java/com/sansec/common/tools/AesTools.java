package com.sansec.common.tools;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Base64Utils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class AesTools {
	private static final Logger logger = LoggerFactory.getLogger(AesTools.class);
	
	private static String byte2HexStr(byte[] b)
	{    
	    String stmp="";
	    StringBuilder sb = new StringBuilder("");
	    for (int n=0;n<b.length;n++)    
	    {    
	        stmp = Integer.toHexString(b[n] & 0xff);
	        sb.append((stmp.length()==1)? "0"+stmp : stmp);    
	        sb.append("");    
	    }    
	    return sb.toString().toLowerCase().trim();    
	} 
	
	public static String decrypt(String data, String token) throws Exception {
		byte[] key=token.substring(16, token.length()).getBytes("UTF-8");
		Key k=new SecretKeySpec(key,"AES");
		Cipher cipher= Cipher.getInstance("AES/ECB/PKCS7Padding");
		cipher.init(Cipher.DECRYPT_MODE,k);
		byte[] original = cipher.doFinal(Base64Utils.decodeFromString(data));
        String originalString = new String(original);
        return originalString;	
	}
}
