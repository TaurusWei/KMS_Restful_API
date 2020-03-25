package com.sansec.common.tools;

import com.sansec.device.sds.local.JARLibUtil;
import org.springframework.util.Base64Utils;
import sun.misc.BASE64Decoder;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.lang.reflect.Field;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Random;
import java.util.zip.ZipFile;


public class Util {
	public static final String provider = "SwxaJCE";
	/**
	 * 使用绝对路径解析RSA私钥
	 * @param fileName
	 * @return
	 * @throws IOException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
//	public static PrivateKey parseRSAPrivateKey(String fileName) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException{
//		File file = new File(fileName);
//		FileInputStream inputStream = new FileInputStream(file);
//		byte[] tmppriKey = new byte[new Long(file.length()).intValue()];
//		inputStream.read(tmppriKey);
//		inputStream.close();
//
//		byte[] modulus = new byte[128];
//		byte[] pE = new byte[3];
//		byte[] d = new byte[128];
//		byte[] p = new byte[64];
//		byte[] q = new byte[64];
//		byte[] p1 = new byte[64];
//		byte[] q1 = new byte[64];
//		byte[] coef = new byte[64];
//		int offset = 4;
//		offset += 8*16;
//		System.arraycopy(tmppriKey, offset, modulus, 0, 128);
//		offset += 128;
//
//		BigInteger bN = new BigInteger(1, modulus);
//
//		offset += 256 -3;
//		System.arraycopy(tmppriKey, offset, pE, 0, 3);
//		offset += 3;
//
//		BigInteger bE = new BigInteger(1, pE);
//
//		offset += 128;
//		System.arraycopy(tmppriKey, offset, d, 0, 128);
//		offset += 128;
//
//		BigInteger bD = new BigInteger(1, d);
//
//		offset += 64;
//		System.arraycopy(tmppriKey, offset, p, 0, 64);
//		offset += 64;
//
//		BigInteger bP = new BigInteger(1, p);
//
//		offset += 64;
//		System.arraycopy(tmppriKey, offset, q, 0, 64);
//		offset += 64;
//		BigInteger bQ = new BigInteger(1, q);
//
//		offset += 64;
//		System.arraycopy(tmppriKey, offset, p1, 0, 64);
//		offset += 64;
//		BigInteger bP1 = new BigInteger(1, p1);
//
//		offset += 64;
//		System.arraycopy(tmppriKey, offset, q1, 0, 64);
//		offset += 64;
//		BigInteger bQ1 = new BigInteger(1, q1);
//
//		offset += 64;
//		System.arraycopy(tmppriKey, offset, coef, 0, 64);
//		offset += 64;
//		BigInteger bCoef = new BigInteger(1, coef);
//
//		RSAPrivateKeyStructure structure = new RSAPrivateKeyStructure(bN,bE,bD,bP,bQ,bP1,bQ1,bCoef);
//		PrivateKeyInfo          info = new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, new DERNull()), structure.getDERObject());
//
//
//		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(info.getEncoded());
//		KeyFactory keyFactory = KeyFactory.getInstance("RSA", provider);
//		PrivateKey key = keyFactory.generatePrivate(keySpec);
//
//		return key;
//	}

//	public static PrivateKey parseSM2PrivateKey(String pubKeyFile,String priKeyFile) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException{
//		File file = new File(priKeyFile);
//		FileInputStream inputStream = new FileInputStream(file);
//		byte[] tmppriKey = new byte[new Long(file.length()).intValue()];
//		inputStream.read(tmppriKey);
//		inputStream.close();
//
//		byte[] tmpkey  = new byte[32];
//		System.arraycopy(tmppriKey, 4, tmpkey, 0, 32);
//		BigInteger s = new BigInteger(tmpkey);
//
//		//公钥
//		file = new File(pubKeyFile);
//		inputStream = new FileInputStream(file);
//		byte[] exPubKey = new byte[new Long(file.length()).intValue()];
//		inputStream.read(exPubKey);
//		inputStream.close();
//		byte[] pubKey = new byte[65];
//		pubKey[0] = 0x04;
//		System.arraycopy(exPubKey, 4, pubKey, 1, 64);
//
//		DERBitString pKey = new DERBitString(pubKey);
//
//		SM2PrivateKeyStructure sm2Structure = new SM2PrivateKeyStructure(s, pKey, null);
//
//		PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(/*PKCSObjectIdentifiers.ecPublicKey,*/GBObjectIdentifiers.sm2), sm2Structure.getDERObject());
//
////		PrintUtil.printWithHex(info.getEncoded());
//
//
//		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(info.getEncoded());
//		KeyFactory factory = KeyFactory.getInstance("SM2", provider);
//		PrivateKey key = factory.generatePrivate(keySpec);
//
//		return key;
//	}


	public static Certificate readCertFromFile(String fileName) throws FileNotFoundException, CertificateException, NoSuchProviderException {
		FileInputStream inputStream = new FileInputStream(fileName);
		CertificateFactory certFactory = CertificateFactory.getInstance("X509", provider);
		Certificate cerx509 = (Certificate)certFactory.generateCertificate(inputStream);

		return cerx509;
	}


	public static byte[] readFromFile(String fileName) throws IOException {
		byte[] data = null;
		File file = new File(fileName);
		data = new byte[new Long(file.length()).intValue()];
		FileInputStream in = new FileInputStream(file);

		in.read(data);

		in.close();

		return data;
	}
	public static void writeToFile(String fileName, byte[] data) throws IOException {
		FileOutputStream out = new FileOutputStream(fileName);
		out.write(data);
		out.close();
	}

	/**
	 * 导出设备内部指定算法的指定索引的非对称密钥
	 * @param index     要导出的密钥索引号
	 * @param alg       算法：RSA或者SM2
	 * @param isPublic   导出公钥：true。导出私钥：false
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static Key readKeyFromDevice(int index, String alg, boolean isPublic) throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(alg, provider);
		generator.initialize(index<<16);
		KeyPair pair = generator.generateKeyPair();
		if(pair != null){
			if(isPublic)
				return pair.getPublic();
			else
			    return pair.getPrivate();
		}
		return null;
	}

	@SuppressWarnings("rawtypes")
	public static int get(Class clasz, String fieldName) {
		// 获得对象的类型
		try {
			Field f = clasz.getDeclaredField(fieldName);

			return f.getInt(clasz);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return 0;
	}

	public static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

	public static String genEnvelope(String cert, byte[] key1) throws CertificateException, IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		byte[] decodeBufferCert = new BASE64Decoder().decodeBuffer(cert);
		byte[] sessionKey = new byte[16];
		Random random = new Random();
		random.nextBytes(sessionKey);
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(decodeBufferCert));
		PublicKey publicKey = certificate.getPublicKey();

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] b1 = cipher.doFinal( sessionKey );

		Cipher ciph = Cipher.getInstance("AES/ECB/PKCS5Padding");
		Key key = new SecretKeySpec(sessionKey, "AES");

		ciph.init(Cipher.ENCRYPT_MODE, key);
		byte[] b2 = ciph.doFinal(key1);

		byte[] bytes = new byte[b1.length + b2.length];
		System.arraycopy(b1, 0, bytes, 0, b1.length);
		System.arraycopy(b2, 0, bytes, b1.length, b2.length);
		System.out.println(Base64Utils.encodeToString(bytes));
		return Base64Utils.encodeToString(bytes);
	}

	/**
	 * 初始化 AES Cipher
	 *
	 * @param sKey  base64编码格式
	 * @param cipherMode
	 * @return
	 */
	public static Cipher initAESCipher(String sKey, int cipherMode) {
		// 创建Key gen
		KeyGenerator keyGenerator = null;
		Cipher cipher = null;
		try {
//			keyGenerator = KeyGenerator.getInstance("AES");
//			keyGenerator.init(128, new SecureRandom(Base64Utils.decodeFromString(sKey)));
//			SecretKey secretKey = keyGenerator.generateKey();
			Key secretKey = new SecretKeySpec(Base64Utils.decodeFromString(sKey),"AES");
			byte[] codeFormat = secretKey.getEncoded();
			SecretKeySpec key = new SecretKeySpec(codeFormat, "AES");
			cipher = Cipher.getInstance("AES/ECB/Pkcs5Padding");
			// 初始化
			cipher.init(cipherMode, key);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace(); // To change body of catch statement use File |
			// Settings | File Templates.RR
		} catch (NoSuchPaddingException e) {
			e.printStackTrace(); // To change body of catch statement use File |
			// Settings | File Templates.
		} catch (InvalidKeyException e) {
			e.printStackTrace(); // To change body of catch statement use File |
			// Settings | File Templates.
		}
		return cipher;
	}
	/**
	 *  AES方式解密文件
	 * @param sourceFile 要解密的文件路径
	 * @param decryptFile 解密后的文件路径
	 * @param sKey
	 * @return
	 */
//	public static Result decryptFile(File sourceFile, File decryptFile,
//                                     String sKey) {
//		InputStream inputStream = null;
//		OutputStream outputStream = null;
//		try {
//			Cipher cipher = initAESCipher(sKey, Cipher.DECRYPT_MODE);
//			inputStream = new FileInputStream(sourceFile);
//			outputStream = new FileOutputStream(decryptFile);
//			CipherOutputStream cipherOutputStream = new CipherOutputStream(
//					outputStream, cipher);
//			byte[] buffer = new byte[1024];
//			int r;
//			while ((r = inputStream.read(buffer)) >= 0) {
//				cipherOutputStream.write(buffer, 0, r);
//			}
//			cipherOutputStream.close();
//		} catch (Exception e) {
//			return Result.error(CodeMsg.ENCRYPT_ERROR.fillArgs(e.getMessage()));
//		} finally {
//			try {
//				inputStream.close();
//			} catch (IOException e) {
//				return Result.error(CodeMsg.ENCRYPT_ERROR.fillArgs(e.getMessage()));
//			}
//			try {
//				outputStream.close();
//			} catch (IOException e) {
//				return Result.error(CodeMsg.ENCRYPT_ERROR.fillArgs(e.getMessage()));
//			}
//		}
//		return Result.success("");
//	}
//
//	/**
//	 * 对文件进行AES加密
//	 *
//	 * @param sourceFile
//	 * @param Result
//	 * @param sKey
//	 * @return
//	 */
//	public static Result encryptFile(File sourceFile, File encrypfile, String sKey) {
//
//		InputStream inputStream = null;
//		OutputStream outputStream = null;
//		try {
//			inputStream = new FileInputStream(sourceFile);
//
//			outputStream = new FileOutputStream(encrypfile);
//			Cipher cipher = initAESCipher(sKey, Cipher.ENCRYPT_MODE);
//			// 以加密流写入文件
//			CipherInputStream cipherInputStream = new CipherInputStream(
//					inputStream, cipher);
//			byte[] cache = new byte[1024];
//			int nRead = 0;
//			while ((nRead = cipherInputStream.read(cache)) != -1) {
//				outputStream.write(cache, 0, nRead);
//				outputStream.flush();
//			}
//			cipherInputStream.close();
//		} catch (Exception e) {
//			return Result.error(CodeMsg.DECRYPT_ERROR.fillArgs(e.getMessage()));
//		} finally {
//			try {
//				inputStream.close();
//			} catch (Exception e) {
//				return Result.error(CodeMsg.DECRYPT_ERROR.fillArgs(e.getMessage()));
//			}
//			try {
//				outputStream.close();
//			} catch (Exception e) {
//				return Result.error(CodeMsg.DECRYPT_ERROR.fillArgs(e.getMessage()));
//			}
//		}
//		return Result.success("");
//	}

	public static boolean isSameFile(String fileName1, String fileName2){
		FileInputStream fis1 = null;
		FileInputStream fis2 = null;
		try {
			fis1 = new FileInputStream(fileName1);
			fis2 = new FileInputStream(fileName2);

			int len1 = fis1.available();//返回总的字节数
			int len2 = fis2.available();

			if (len1 == len2) {//长度相同，则比较具体内容
				//建立两个字节缓冲区
				byte[] data1 = new byte[len1];
				byte[] data2 = new byte[len2];

				//分别将两个文件的内容读入缓冲区
				fis1.read(data1);
				fis2.read(data2);

				//依次比较文件中的每一个字节
				for (int i=0; i<len1; i++) {
					//只要有一个字节不同，两个文件就不一样
					if (data1[i] != data2[i]) {
						System.out.println("文件内容不一样");
						return false;
					}
				}
				System.out.println("两个文件完全相同");
				return true;
			} else {
				//长度不一样，文件肯定不同
				return false;
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {//关闭文件流，防止内存泄漏
			if (fis1 != null) {
				try {
					fis1.close();
				} catch (IOException e) {
					//忽略
					e.printStackTrace();
				}
			}
			if (fis2 != null) {
				try {
					fis2.close();
				} catch (IOException e) {
					//忽略
					e.printStackTrace();
				}
			}
		}
		return false;
	}

	public static void loadLib(ZipFile zf, String filename, String outFileName) {
		try {
			File f = new File(outFileName);

			if( !f.exists() ) { // 文件存在不需要执行
				InputStream in = zf.getInputStream(zf.getEntry(filename));
				FileOutputStream out = new FileOutputStream(f);
				byte[] buf = new byte[1024];
				int len = -1;
				while ((len = in.read(buf)) > 0)
					out.write(buf, 0, len);
				in.close();
				out.close();
				JARLibUtil.addExec(f.getAbsolutePath());
			}
			System.out.println(f.getAbsolutePath());
			System.load(f.getAbsolutePath());
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException(ex.getMessage());
		}
	}
	public static boolean isWindowsOS() {
		boolean isWindowsOS = false;
		String osName = System.getProperty("os.name");
		if (osName.toLowerCase().startsWith("windows")) {
			isWindowsOS = true;
		}
		return isWindowsOS;
	}

	public static boolean isLinuxOS() {
		boolean isWindowsOS = false;
		String osName = System.getProperty("os.name");
		if (osName.toLowerCase().startsWith("linux")) {
			isWindowsOS = true;
		}
		return isWindowsOS;
	}

}
