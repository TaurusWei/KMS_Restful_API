package com.sansec.common.tools;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha256Tool {

	private static final Logger logger = LoggerFactory.getLogger(Sha256Tool.class);
	
	
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
    
    //sha256计算 返回Base64
    public static String doDigestBase64(byte[] data) {
        byte[] sha = null;
        try{
	        MessageDigest messageDigest = MessageDigest.getInstance("SHA256", "SwxaJCE");
	        sha = messageDigest.digest(data);
        }catch(Exception e) {
        	logger.error(e.getMessage());
        }
            
        return Base64.encodeBase64String(byte2HexStr(sha).getBytes());
    }
    
    public static byte[] string2SHA256Bytes(String inStr) {

		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        byte[] bytes = null;
		try {
			bytes = md.digest(inStr.getBytes("utf-8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return bytes;
	}

}
