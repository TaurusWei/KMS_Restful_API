package com.sansec.common.tools;

import com.google.common.base.VerifyException;
import com.sansec.asn1.ASN1Object;
import com.sansec.asn1.DERBitString;
import com.sansec.asn1.DERObjectIdentifier;
import com.sansec.asn1.DEROctetString;
import com.sansec.asn1.misc.MiscObjectIdentifiers;
import com.sansec.asn1.misc.NetscapeCertType;
import com.sansec.asn1.x509.X509Extension;
import com.sansec.asn1.x509.*;
import com.sansec.common.exception.CoreException;
import com.sansec.common.exception.ValidRequestException;
import com.sansec.common.exception.CryptoException;
import com.sansec.jce.PKCS10CertificationRequest;
import com.sansec.jce.provider.JCESM2PrivateKey;
import com.sansec.jce.provider.SwxaProvider;
import com.sansec.openssl.PEMReader;
import com.sansec.openssl.PEMWriter;
import com.sansec.util.encoders.Hex;
import com.sansec.x509.X509V3CertificateGenerator;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

public class CertificateTools {

	private static Logger logger = LoggerFactory.getLogger(CertificateTools.class);

	private static final String PROVIDER = "SwxaJCE";

	public static final String BEGIN_CERTIFICATE_REQUEST = "-----BEGIN CERTIFICATE REQUEST-----";
	public static final String END_CERTIFICATE_REQUEST = "-----END CERTIFICATE REQUEST-----";
	public static final String BEGIN_KEYTOOL_CERTIFICATE_REQUEST = "-----BEGIN NEW CERTIFICATE REQUEST-----";
	public static final String END_KEYTOOL_CERTIFICATE_REQUEST = "-----END NEW CERTIFICATE REQUEST-----";
	public static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
	public static final String END_CERTIFICATE = "-----END CERTIFICATE-----";
	public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
	public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
	public static final String BEGIN_X509_CRL_KEY = "-----BEGIN X509 CRL-----";
	public static final String END_X509_CRL_KEY = "-----END X509 CRL-----";
	public static final String BEGIN_PFXCERTIFICATE = "-----BEGIN PFXCERTIFICATE-----";
	public static final String END_PFXCERTIFICATE = "-----END PFXCERTIFICATE-----";

	public static void verifyCertificate(X509Certificate parentCert, X509Certificate childrenCert) throws VerifyException {

		if (!parentCert.getSubjectDN().equals(childrenCert.getIssuerDN())) {
			throw new VerifyException("Check parentcert.subject != childcert.issuer");
		}
		// 验证根证书是否过期
		try {
			parentCert.checkValidity();
		} catch (Exception e) {
			e.printStackTrace();
			throw new VerifyException("Check parent cert validity error", e);
		}

		try {
			childrenCert.checkValidity();
		} catch (Exception e) {
			e.printStackTrace();
			throw new VerifyException("Check children cert validity error", e);
		}

		try {
			childrenCert.verify(parentCert.getPublicKey());
		} catch (Exception e) {
			e.printStackTrace();
			throw new VerifyException("Verify children certficate signature error", e);
		}
	}

	public static void verifyCertificate(X509Certificate selfCert) throws VerifyException {

		if (!selfCert.getSubjectDN().equals(selfCert.getIssuerDN())) {
			throw new VerifyException("Check selfsign cert issuer != subject");
		}

		try {
			selfCert.checkValidity();
		} catch (Exception e) {
			e.printStackTrace();
			throw new VerifyException("Check selfsign cert validity error", e);
		}

		try {
			selfCert.verify(selfCert.getPublicKey());
		} catch (Exception e) {
			e.printStackTrace();
			throw new VerifyException("Verify selfsign certficate signature error", e);
		}
	}

	public static List<X509Certificate> getCertificates(String certs) throws CertificateParsingException {

		// 获取证书工厂类
		CertificateFactory factory = getCertificateFactory();
		if (factory == null) {
			logger.error("Initliaze CertificateFactory error");
			throw new CertificateParsingException("Initliaze CertificateFactory error");
		}

		// 处理非标准PKCS7，即对PKCS7做了base64编码并加入头部（-----BEGIN PKCS7-----）和尾部（-----END
		// PKCS7-----）
		byte[] certsData = null;

		if (certs.indexOf("-----BEGIN PKCS7-----") != -1 || certs.indexOf("-----END PKCS7-----") != -1) {
			certs = certs.replace("-----BEGIN PKCS7-----", "");
			certs = certs.replace("-----END PKCS7-----", "");
			certsData = Base64Tools.decode(certs);
		} else {
			certsData = certs.getBytes();
		}

		String[] certPathEncoding = { "PEM", "PkiPath" };

		CertPath certPath = null;

		for (String encoding : certPathEncoding) {
			ByteArrayInputStream inStream = new ByteArrayInputStream(certsData);

			try {
				certPath = factory.generateCertPath(inStream, encoding);
				break;
			} catch (CertificateException e) {
				e.printStackTrace();
				logger.error("Exception caught when attempting to read CertPath by " + encoding + " encoding", e);
			} finally {
				try {
					inStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		if (certPath == null) {
			throw new CertificateParsingException("Exception caught when attempting to read CertPath by PKCS7/PEM/PkiPath encoding");
		}
		List<?> certList = certPath.getCertificates();
		if (certList.isEmpty()) {
			throw new CertificateParsingException("No certificate in String");
		}
		return (List<X509Certificate>) certList;
	}

	/**
	 * Returns a CertificateFactory that can be used to create certificates from
	 * byte arrays and such.
	 * 
	 * @param provider
	 *            Security provider that should be used to create certificates,
	 *            default BC is null is passed.
	 * @return CertificateFactory
	 */
	public static CertificateFactory getCertificateFactory(final String provider) {
		final String prov;
		if (provider == null) {
			prov = PROVIDER;
		} else {
			prov = provider;
		}

		try {
			return CertificateFactory.getInstance("X.509", prov);
		} catch (NoSuchProviderException nspe) {
			logger.error("NoSuchProvider: ", nspe);
		} catch (CertificateException ce) {
			logger.error("CertificateException: ", ce);
		}
		return null;
	}

	public static CertificateFactory getCertificateFactory() {
		return getCertificateFactory(PROVIDER);
	}

	public static X509Certificate getCertificate(String sCert) throws CertificateParsingException {

		return getCertificates(sCert).get(0);
	}

	public static void verifyCertChain(List<X509Certificate> list) throws VerifyException {
		int index = 0;
		while (index < list.size()) {
			if (index == list.size() - 1) {

				X509Certificate certificate = list.get(index);

				verifyCertificate(certificate);
				break;
			} else {
				X509Certificate certificate = list.get(index);
				X509Certificate upCertificate = list.get(index + 1);
				verifyCertificate(upCertificate, certificate);
			}
			index++;
		}
	}

	public static String encodePEMCertPath(List<X509Certificate> list) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		PEMWriter writer = new PEMWriter(new OutputStreamWriter(out));
		for (int index = 0; index < list.size(); index++) {
			writer.writeObject(list.get(index));
		}
		writer.flush();

		try {
			return out.toString();
		} finally {
			try {
				writer.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	public static PKCS10CertificationRequest getCertificationRequest(String baseRequest) throws ValidRequestException {

		try {
			Reader reader = new StringReader(baseRequest);
			PEMReader pemReader = new PEMReader(reader, null, PROVIDER);
			PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemReader.readObject();
			if (csr != null) {
				return csr;
			}
		} catch (Exception e1) {
			e1.printStackTrace();
		}
		try {

			String prefix = "-----BEGIN NEW CERTIFICATE REQUEST-----";
			String endf = "-----END NEW CERTIFICATE REQUEST-----";
			String sepLine = "\r";
			String sepLine2 = "\n";

			if (baseRequest.indexOf(prefix) > -1) {
				baseRequest = baseRequest.replace(sepLine, "");
				baseRequest = baseRequest.replace(sepLine2, "");
				baseRequest = baseRequest.replace(prefix, "");
				baseRequest = baseRequest.replace(endf, "");
			}
			PKCS10CertificationRequest p10Request = new PKCS10CertificationRequest(Base64Tools.decode(baseRequest));

			return p10Request;
		} catch (Exception e) {
			e.printStackTrace();
		}
		throw new ValidRequestException("Invalid certificate request");
	}

	public static String getSubjectDN(String sCertRequest) throws ValidRequestException {
		PKCS10CertificationRequest request = getCertificationRequest(sCertRequest);
		return request.getCertificationRequestInfo().getSubject().toString();
	}

	public static String getSerialNum(final X509Certificate cert) {
		if (cert == null) {
			return null;
		}
		return toHexSerialNum(cert.getSerialNumber());
	}

	public static String toHexSerialNum(BigInteger serialNum) {
		String serial = serialNum.toString(16);
		return toHexSerialNum(serial);
	}

	public static BigInteger getSerialNum(String serialNum) {
		return new BigInteger(serialNum, 16);
	}

	public static String toHexSerialNum(String serialNum) {
		while (serialNum.length() < 16) {
			serialNum = "0" + serialNum;
		}
		return serialNum;
	}

	/**
	 * Gets subject DN in the format we are sure about (BouncyCastle),supporting
	 * UTF8.
	 * 
	 * @param cert
	 *            Certificate
	 * 
	 * @return String containing the subjects DN.
	 */
	public static String getSubjectDN(final X509Certificate cert) {
		return getDN(cert, 1);
	}

	/**
	 * Gets issuer DN in the format we are sure about (BouncyCastle),supporting
	 * UTF8.
	 * 
	 * @param cert
	 *            Certificate
	 * 
	 * @return String containing the issuers DN.
	 */
	public static String getIssuerDN(final X509Certificate cert) {
		return getDN(cert, 2);
	}

	/**
	 * Gets subject or issuer DN in the format we are sure about
	 * (BouncyCastle),supporting UTF8.
	 * 
	 * @param cert
	 *            X509Certificate
	 * @param which
	 *            1 = subjectDN, anything else = issuerDN
	 * 
	 * @return String containing the DN.
	 */
	private static String getDN(final X509Certificate cert, final int which) {
		if (cert == null) {
			return null;
		}

		String dn = null;
		if (which == 1) {
			dn = cert.getSubjectDN().toString();
		} else {
			dn = cert.getIssuerDN().toString();
		}
		return dn;
	}

	/**
	 * Checks if a certificate is a CA certificate according to BasicConstraints
	 * (X.509). If there is no basic constraints extension on a X.509
	 * certificate, checks if it is selfsigned ,if true return true ,else return
	 * false.
	 * 
	 * @param cert
	 *            the certificate that skall be checked.
	 * 
	 * @return boolean true if the certificate belongs to a CA.
	 */
	public static boolean isCA(X509Certificate cert) {
		boolean ret = false;
		if (cert.getBasicConstraints() > -1) {
			ret = true;
		}
		if (isSelfSigned(cert)) {
			ret = true;
		}
		return ret;
	}

	/**
	 * Checks if a certificate is self signed by verifying if subject and issuer
	 * are the same.
	 * 
	 * @param cert
	 *            the certificate that shall be checked.
	 * 
	 * @return boolean true if the certificate has the same issuer and subject,
	 *         false otherwise.
	 */
	public static boolean isSelfSigned(X509Certificate cert) {
		boolean ret = getSubjectDN(cert).equals(getIssuerDN(cert));
		return ret;
	} // isSelfSigned

	/**
	 * Gets a specified part of a DN. Specifically the first occurrence it the
	 * DN contains several instances of a part (i.e. cn=x, cn=y returns x).
	 * 
	 * @param dn
	 *            String containing DN, The DN string has the format "C=SE,
	 *            O=xx, OU=yy, CN=zz".
	 * @param dnpart
	 *            String specifying which part of the DN to get, should be "CN"
	 *            or "OU" etc.
	 * 
	 * @return String containing dnpart or null if dnpart is not present
	 */
	public static String getPartFromDN(String dn, String dnpart) {
		String part = null;
		final List<String> dnParts = getPartsFromDNInternal(dn, dnpart, true);
		if (!dnParts.isEmpty()) {
			part = dnParts.get(0);
		}
		return part;
	}

	/**
	 * Gets a specified parts of a DN. Returns all occurrences as an ArrayList,
	 * also works if DN contains several instances of a part (i.e. cn=x, cn=y
	 * returns {x, y, null}).
	 * 
	 * @param dn
	 *            String containing DN, The DN string has the format "C=SE,
	 *            O=xx, OU=yy, CN=zz".
	 * @param dnpart
	 *            String specifying which part of the DN to get, should be "CN"
	 *            or "OU" etc.
	 * 
	 * @return ArrayList containing dnparts or empty list if dnpart is not
	 *         present
	 */
	public static List<String> getPartsFromDN(String dn, String dnpart) {
		return getPartsFromDNInternal(dn, dnpart, false);
	}

	public static List<String> getPartsFromDNInternal(final String dn, final String dnPart, final boolean onlyReturnFirstMatch) {
		final List<String> parts = new ArrayList<String>();
		if (dn != null && dnPart != null) {
			final String dnPartLowerCase = dnPart.toLowerCase();
			final int dnPartLenght = dnPart.length();
			boolean quoted = false;
			boolean escapeNext = false;
			int currentStartPosition = -1;
			for (int i = 0; i < dn.length(); i++) {
				final char current = dn.charAt(i);
				// Toggle quoting for every non-escaped "-char
				if (!escapeNext && current == '"') {
					quoted = !quoted;
				}
				// If there is an unescaped and unquoted =-char we need to
				// investigate if it is a match for the sought after part
				if (!quoted && !escapeNext && current == '=' && dnPartLenght <= i) {
					// Check that the character before our expected partName
					// isn't a letter (e.g. dnsName=.. should not match E=..)
					if (i - dnPartLenght - 1 < 0 || !Character.isLetter(dn.charAt(i - dnPartLenght - 1))) {
						boolean match = true;
						for (int j = 0; j < dnPartLenght; j++) {
							if (Character.toLowerCase(dn.charAt(i - dnPartLenght + j)) != dnPartLowerCase.charAt(j)) {
								match = false;
								break;
							}
						}
						if (match) {
							currentStartPosition = i + 1;
						}
					}
				}
				// When we have found a start marker, we need to be on the
				// lookout for the ending marker
				if (currentStartPosition != -1 && ((!quoted && !escapeNext && (current == ',' || current == '+')) || i == dn.length() - 1)) {
					int endPosition = (i == dn.length() - 1) ? dn.length() - 1 : i - 1;
					// Remove white spaces from the end of the value
					while (endPosition > currentStartPosition && dn.charAt(endPosition) == ' ') {
						endPosition--;
					}
					// Remove white spaces from the beginning of the value
					while (endPosition > currentStartPosition && dn.charAt(currentStartPosition) == ' ') {
						currentStartPosition++;
					}
					// Only return the inner value if the part is quoted
					if (dn.charAt(currentStartPosition) == '"' && dn.charAt(endPosition) == '"') {
						currentStartPosition++;
						endPosition--;
					}
					parts.add(dn.substring(currentStartPosition, endPosition + 1));
					if (onlyReturnFirstMatch) {
						break;
					}
					currentStartPosition = -1;
				}
				if (escapeNext) {
					// This character was escaped, so don't escape the next one
					escapeNext = false;
				} else {
					if (!quoted && current == '\\') {
						// This escape character is not escaped itself, so the
						// next one should be
						escapeNext = true;
					}
				}
			}
		}
		return parts;
	}

	/**
	 * Check if the String contains any unescaped '+'. RFC 2253, section 2.2
	 * states that '+' is used for multi-valued RelativeDistinguishedName. BC
	 * (version 1.45) did not support multi-valued RelativeDistinguishedName,
	 * and automatically escaped them instead. Even though it is now (BC
	 * 1.49b15) supported, we want to keep ecaping '+' chars and warn that this
	 * might not be supported in the future.
	 */
	public static String handleUnescapedPlus(final String dn) {
		if (dn == null) {
			return dn;
		}
		final StringBuilder buf = new StringBuilder(dn);
		int index = 0;
		final int end = buf.length();
		while (index < end) {
			if (buf.charAt(index) == '+') {
				// Found an unescaped '+' character.
				logger.warn("DN \"" + dn + "\" contains an unescaped '+'-character that will be automatically escaped. RFC 2253 reservs this "
						+ "for multi-valued RelativeDistinguishedNames. Encourage clients to use '\\+' instead, since future behaviour might change.");
				buf.insert(index, '\\');
				index++;
			} else if (buf.charAt(index) == '\\') {
				// Found an escape character.
				index++;
			}
			index++;
		}
		return buf.toString();
	}

	public static String getSubjectName(X509Certificate cert) {
		if (cert == null) {
			return null;
		}
		return getPartFromDN(getSubjectDN(cert), "CN");
	}

	public static String getKeyAlgorithm(X509Certificate cert) {
		if (cert == null) {
			return null;
		}
		return cert.getPublicKey().getAlgorithm();
	}

	/**
	 * Generate SHA1 keyId of certificate's public key in string representation.
	 * 
	 * @param cert
	 *            Certificate.
	 * 
	 * @return String containing hex format of SHA1 keyId (lower case), or null
	 *         if input is null.
	 */
	public static String getKeyIdAsString(X509Certificate cert) {
		if (cert == null) {
			return null;
		}

		byte[] res = generateSHA1Fingerprint(cert.getPublicKey().getEncoded());

		return new String(Hex.encode(res));

	}

	/**
	 * Generate SHA1 fingerprint of certificate in string representation.
	 * 
	 * @param cert
	 *            Certificate.
	 * 
	 * @return String containing hex format of SHA1 fingerprint (lower case), or
	 *         null if input is null.
	 */
	public static String getFingerprintAsString(String sCert) {
		if (sCert == null) {
			return null;
		}
		try {
			X509Certificate cert = getCertificate(sCert);

			byte[] res = generateSHA1Fingerprint(cert.getEncoded());

			return new String(Hex.encode(res));
		} catch (CertificateEncodingException cee) {
			logger.error("Error encoding certificate.", cee);
		} catch (CertificateParsingException e) {
			e.printStackTrace();
			logger.error("Error parse certificate.", e);
		}

		return null;
	}

	/**
	 * Generate SHA1 fingerprint of certificate in string representation.
	 * 
	 * @param cert
	 *            Certificate.
	 * 
	 * @return String containing hex format of SHA1 fingerprint (lower case), or
	 *         null if input is null.
	 */
	public static String getFingerprintAsString(X509Certificate cert) {
		if (cert == null) {
			return null;
		}
		try {
			byte[] res = generateSHA1Fingerprint(cert.getEncoded());

			return new String(Hex.encode(res));
		} catch (CertificateEncodingException cee) {
			logger.error("Error encoding certificate.", cee);
		}

		return null;
	}

	/**
	 * Generate a SHA1 fingerprint from a byte array containing a certificate
	 * 
	 * @param ba
	 *            Byte array containing DER encoded Certificate or CRL.
	 * 
	 * @return Byte array containing SHA1 hash of DER encoded certificate.
	 */
	public static byte[] generateSHA1Fingerprint(byte[] ba) {
		// log.trace(">generateSHA1Fingerprint");
		try {
			MessageDigest md = MessageDigest.getInstance("SHA1");
			return md.digest(ba);
		} catch (NoSuchAlgorithmException nsae) {
			logger.error("SHA1 algorithm not supported", nsae);
		}
		// log.trace("<generateSHA1Fingerprint");
		return null;
	} // generateSHA1Fingerprint

	/**
	 * 获取证书用途，仅查找SSL 服务端和客户端身份认证，0标识证书请求，1标识服务端认证，2标识客户端认证，3标识服务端和客户端认证
	 * 
	 * @param certificate
	 * @return
	 */
	public static int getCertificatePurpose(X509Certificate certificate) {

		int rt = 0;

		byte[] value = certificate.getExtensionValue(MiscObjectIdentifiers.netscapeCertType.getId());
		if (value == null) {
			return 3;// 如果证书中没有指定网景证书用途，那么认为Server和Client都可用
		}
		try {
			DEROctetString octString = (DEROctetString) ASN1Object.fromByteArray(value);
			DERBitString bitString = (DERBitString) ASN1Object.fromByteArray(octString.getOctets());
			int usage = bitString.intValue();
			if ((usage & NetscapeCertType.sslServer) != 0) {
				rt += 1;
			}
			if ((usage & NetscapeCertType.sslClient) != 0) {
				rt += 2;
			}
		} catch (IOException e) {
			e.printStackTrace();
			return 3;
		}
		return rt;
	}

	public static String getCertificatePurpose(int i) {
		if (i == 0) {
			return "Certificate Request";
		} else if (i == 1) {
			return "Server";
		} else if (i == 2) {
			return "Client";
		} else if (i == 3) {
			return "Server/Client";
		}
		return "Server/Client";
	}

	/**
	 * 获取证书状态0：Request Pending证书请求;1：Active 证书有效2：Expired
	 * 证书过期;3:NotYetValid还未生效4：UnKnown （第三方CA证书不是根证书）;
	 * 
	 * @param certificate
	 * @param certType
	 *            证书类型，1：SSL 证书，；2：本地CA证书，；3：第三方CA证书
	 * @return
	 */
	public static int getCertificateStatus(X509Certificate certificate, int certType) {
		if (certType == 3 && !isSelfSigned(certificate)) {
			return 4;
		}
		try {
			certificate.checkValidity();
		} catch (CertificateExpiredException e) {
			e.printStackTrace();
			return 2;
		} catch (CertificateNotYetValidException e) {
			e.printStackTrace();
			return 3;
		}

		return 1;
	}

	public static String getCertificateStatusDesp(int i) {
		if (i == 0) {
			return "Request Pending";
		} else if (i == 1) {
			return "Active";
		} else if (i == 2) {
			return "Expired";
		} else if (i == 3) {
			return "Not Yet Valid";
		} else if (i == 4) {
			return "UnKnown";
		}
		return "";
	}

	public static KeyStore parseKeyStore(String keyStoreType, String keyStoreData, String keyStorePassword) throws CryptoException {
		Security.addProvider(new SwxaProvider());
		/*Security.addProvider(new SwxaProvider());
        final String defaultAlias = "server";
        final String defaultPassword = "66666666";
        String jksStr ="/u3+7QAAAAIAAAABAAAAAQAGc2VydmVyAAABZvEJAkUAAADIMIHFMA4GCisGAQQBKgIRAQEFAASBshdxYLvtYZ/vXbTZP34rY2LckxzcgW2YWuCGIbNeMJYgPnTSUgbGKeREuue9Vg1rEDEzm+MEMPWzNsJGrF1qAQfSpGfemvGoLujiTRjFk+M4hAuCyztV91VHh6mS2TBfykufBzB0Np2n5wV9HCg2fcO19ZERhFRyxosnvRmChEv5kbymkwrK7xPsmFwv5QO2d5JYvSF3D/9qx7Lc5qiWjH9IyC+ZnWeaA6LyIL6dMBIjcGQAAAACAAVYLjUwOQAAAXUwggFxMIIBFqADAgECAgg6ag5m86iZwDAMBggqgRzPVQGDdQUAMBoxCzAJBgNVBAYTAkNOMQswCQYDVQQDDAJodzAeFw0xODExMDcwMTU1MTZaFw0xOTAyMTUwMTU1MTZaMBwxCzAJBgNVBAYTAkNOMQ0wCwYDVQQDDARzd3hhMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEYEUJ/NdHLbwW7N9qvdGrbrU02tsnzfetEnbxCdRucyWmq9vMU+oY06vG/xe/DUungQT2RcZpKJVjy0o786rcW6NCMEAwHQYDVR0OBBYEFENtkG7K8YFMfw2sy/NMTDxpZ8oYMB8GA1UdIwQYMBaAFF5ohcCwwXJS3PEkmNDfq7tUDRjMMAwGCCqBHM9VAYN1BQADRwAwRAIgfcUpZvqOuj/XNjoqF4y3iprjObafIkyji1RtLUmeSsUCIFcQ6aEqyap9Y/2QZ0bcMkeRtuuZ6iVQA0VtgH4bpdCnAAVYLjUwOQAAAYYwggGCMIIBJaADAgECAggl8SXwVR3qHDAMBggqgRzPVQGDdQUAMBoxCzAJBgNVBAYTAkNOMQswCQYDVQQDDAJodzAeFw0xODExMDYwOTMzMTVaFw0yMTA4MDMwOTMzMTVaMBoxCzAJBgNVBAYTAkNOMQswCQYDVQQDDAJodzBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABF2phxOMlDTfHGJOnCsrTZsJlcfStuoziqZXMXClqsfG5BTzR8lD1hWs7T2XUztMJV/8MvO5CmZZ4dmj9Cs7B9yjUzBRMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFF5ohcCwwXJS3PEkmNDfq7tUDRjMMB8GA1UdIwQYMBaAFF5ohcCwwXJS3PEkmNDfq7tUDRjMMAwGCCqBHM9VAYN1BQADSQAwRgIhAONRv4t+/j9wg7Yb+e5OEEu3zQIyLSBBbcw1EtmJwzUnAiEAtIltzMSxUhkb7tgr3bBNBeLiWd9SaBySNZOFDx+Yh0dvF656q4YhvbhTxyqUrrCdO7goqQ==";
        
        
        //String keyStoreData = sslCertificate.getcKeyStore();
        byte[] jksBytes = Base64.decode(jksStr);
        PrintUtil.printWithHex(jksBytes);
        //BufferedInputStream   iBufferedInputStream = new BufferedInputStream();
        InputStream input = new ByteArrayInputStream(jksBytes);
        
        KeyStore jks=null;
		try {
			jks = KeyStore.getInstance("JKS", "SwxaJCE");
			//FileInputStream fis = new FileInputStream("./wwww.jks");  //caCommCert.jks
			jks.load(input, defaultPassword.toCharArray());
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} 
        
        PrivateKey key=null;
        try {
          key = (PrivateKey)jks.getKey(defaultAlias, defaultPassword.toCharArray());
        } catch (Exception e) {
          e.printStackTrace();
          //logger.error("Get privateKey in keyStore error",e);
          //DownloadUtil.downloadError(request, response, "Get privateKey in keyStore error");
        }
        System.out.println("key="+key);
			
			return jks; */
		
		
		byte[] bData = Base64Tools.decode(keyStoreData);
		ByteArrayInputStream inputStream = new ByteArrayInputStream(bData);
		char[] pass = keyStorePassword.toCharArray();
		try {
			KeyStore keyStore = KeyStore.getInstance(keyStoreType, PROVIDER);
			keyStore.load(inputStream, pass);

			return keyStore;
		} catch (Exception e) {
			e.printStackTrace();
			throw new CryptoException("Create KeyStore error", e);
		} finally {
			IOUtils.closeQuietly(inputStream);
		}
	}

	public static String createKeyStore(Certificate[] certificate, PrivateKey privateKey, String alias, String password, String keyStoreType) throws CryptoException {
		char[] pass = password.toCharArray();

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		try {
			
			KeyStore keyStore = KeyStore.getInstance(keyStoreType, PROVIDER);
			keyStore.load(null, pass);
			keyStore.setKeyEntry(alias, privateKey, pass, certificate);
			keyStore.setCertificateEntry("rootca", certificate[1]);
			keyStore.store(outputStream, pass);
		} catch (Exception e) {
			e.printStackTrace();
			throw new CryptoException("Create KeyStore error", e);
		} finally {
			IOUtils.closeQuietly(outputStream);
		}

		return Base64Tools.encode(outputStream.toByteArray());
	}

	public static String createTrustKeyStore(ArrayList<X509Certificate> cas, String alias, String password, String keyStoreType) throws CryptoException {
		char[] pass = password.toCharArray();
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		try {
			KeyStore keyStore = KeyStore.getInstance(keyStoreType, PROVIDER);
			keyStore.load(null, pass);

			for (int i = 0; i < cas.size(); i++) {
				keyStore.setCertificateEntry(alias + i, cas.get(i));
			}

			keyStore.store(outputStream, pass);
		} catch (Exception e) {
			e.printStackTrace();
			throw new CryptoException("Create trust KeyStore error", e);
		} finally {
			IOUtils.closeQuietly(outputStream);
		}

		return Base64Tools.encode(outputStream.toByteArray());
	}

	public static PKCS10CertificationRequest createCertificationRequest(KeyPair keyPair, String subjectDN) throws CryptoException {

		PrivateKey privateKey = keyPair.getPrivate();

		PublicKey publicKey = keyPair.getPublic();

		String signAlgorithm = "SM3WithSM2";
		if (publicKey instanceof RSAPublicKey) {
			signAlgorithm = "SHA256WithRSA";
		}

		X509Name x509Name = new X509Name(subjectDN);

		PKCS10CertificationRequest req;
		try {
			req = new PKCS10CertificationRequest(signAlgorithm, x509Name, publicKey, null, privateKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			logger.error("invalidkey", e);
			throw new CryptoException("generate PKCS10CertificationRequest error:" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			logger.error("no such algorithm", e);
			throw new CryptoException("generate PKCS10CertificationRequest error:" + e.getMessage());
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			logger.error("no such provider", e);
			throw new CryptoException("generate PKCS10CertificationRequest error:" + e.getMessage());
		} catch (SignatureException e) {
			e.printStackTrace();
			logger.error("signature", e);
			throw new CryptoException("generate PKCS10CertificationRequest error:" + e.getMessage());
		}
		return req;
	}

//	public static String constructX509String(CertificateRequestModel requestInfo) throws ValidRequestException {
//
//		String CN = requestInfo.getCommonName();
//		String O = requestInfo.getOrganizationName();
//		String OU = requestInfo.getUnitName();
//		String L = requestInfo.getLocalityName();
//		String ST = requestInfo.getProvinceName();
//		String C = requestInfo.getCountryName();
//		String emailAddress = requestInfo.getEmailAddress();
//
//		if (StringUtils.isEmpty(CN)) {
//			throw new ValidRequestException("Common name cannot be blank");
//		}
//		/*
//		 * if (StringUtils.isEmpty(C) || C.trim().length() != 2) { throw new
//		 * ValidRequestException("Country name must be two characters"); }
//		 */
//		StringBuffer buffer = new StringBuffer();
//		buffer.append("C=" + C);
//
//		if (!StringUtils.isEmpty(ST)) {
//			buffer.append(",ST=" + ST);
//		}
//
//		if (!StringUtils.isEmpty(L)) {
//			buffer.append(",L=" + L);
//		}
//		if (!StringUtils.isEmpty(O)) {
//			buffer.append(",O=" + O);
//		}
//		if (!StringUtils.isEmpty(OU)) {
//			buffer.append(",OU=" + OU);
//		}
//
//		buffer.append(",CN=" + CN);
//
//		if (!StringUtils.isEmpty(emailAddress)) {
//			buffer.append(",emailAddress=" + emailAddress);
//		}
//
//		return buffer.toString();
//
//	}

	public static boolean verifyCertificateWithPrivateKey(X509Certificate certificate, PrivateKey privateKey) {
		String signAlg = "SHA1WithRSA";
		if (privateKey instanceof JCESM2PrivateKey) {
			signAlg = "SM3WithSM2";
		}

		byte[] data = "test data".getBytes();

		byte[] signature;
		try {
			signature = CryptoTools.sign(signAlg, privateKey, data);
		} catch (CryptoException e) {
			e.printStackTrace();
			return false;
		}
		boolean result = false;
		try {
			result = CryptoTools.verify(signAlg, certificate.getPublicKey(), data, signature);
		} catch (CryptoException e) {
			e.printStackTrace();

			return false;
		}

		return result;
	}

	/**
	 * 生成唯一序列号
	 * 
	 * @return
	 * @throws CoreException
	 */
	public static BigInteger generateSerialNumber() throws CoreException {
		BigInteger sr = null;

		byte[] serno = new byte[8];
		SecureRandom random;
		try {
			random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			String msg = "Generate serial number error";
			logger.error(msg, e);
			throw new CoreException(msg);
		}
		long seed = 1L;
		synchronized (CertificateTools.class) {
			try {
				Thread.sleep(1);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			seed = new Date().getTime();
		}
		random.setSeed(seed);
		random.nextBytes(serno);
		sr = new BigInteger(serno).abs();

		return sr;
	}

	public static X509Certificate generateRootCertificate(String dn, PrivateKey privateKey, PublicKey publicKey, int validDays, String signAlgorithm) throws CoreException {
		BigInteger serialNum = generateSerialNumber();
		X509Name issuerName = new X509Name(dn);
		Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000L);// 证书有效期开始日期往前推1天
		Date notAfter = new Date(System.currentTimeMillis() + (long) validDays * 24 * 60 * 60 * 1000);

		X509ExtensionsGenerator extGenerator = new X509ExtensionsGenerator();

		BasicConstraints bcExtension = new BasicConstraints(true);
		extGenerator.addExtension(X509Extensions.BasicConstraints, true, bcExtension);

		SubjectPublicKeyInfo spki;
		try {
			spki = SubjectPublicKeyInfo.getInstance(ASN1Object.fromByteArray(publicKey.getEncoded()));
		} catch (IOException e) {
			e.printStackTrace();
			String msg = "Generate certificate extension error";
			logger.error(msg, e);
			throw new CoreException(msg);
		}
		SubjectKeyIdentifier ski = new SubjectKeyIdentifier(spki);
		AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(spki);

		extGenerator.addExtension(X509Extensions.SubjectKeyIdentifier, false, ski);
		extGenerator.addExtension(X509Extensions.AuthorityKeyIdentifier, false, aki);

		X509Extensions extensions = extGenerator.generate();

		return generateX509Certificate(issuerName, privateKey, publicKey, serialNum, notBefore, notAfter, issuerName, signAlgorithm, publicKey, extensions);
	}

	public static X509Certificate generateUserCertificate(BigInteger issuerSN, X509Name issuerDN, PrivateKey issuerPrivateKey, PublicKey issuerPublicKey, Date notBefore,
                                                          Date notAfter, String signAlgorithm, X509Name subjectDN, PublicKey subjectPublicKey, int purpose) throws CoreException {
		BigInteger userNum = generateSerialNumber();

		X509ExtensionsGenerator extGenerator = new X509ExtensionsGenerator();

		// 添加基本约束扩展
		// BasicConstraints bcExtension = new BasicConstraints(false);
		// extGenerator.addExtension(X509Extensions.BasicConstraints, true,
		// bcExtension);

		// 添加主题密钥扩展
		try {
			SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Object.fromByteArray(subjectPublicKey.getEncoded()));
			SubjectKeyIdentifier ski = new SubjectKeyIdentifier(subjectPublicKeyInfo);
			extGenerator.addExtension(X509Extensions.SubjectKeyIdentifier, false, ski.getDEREncoded());
		} catch (IOException e) {
			e.printStackTrace();
			throw new CoreException("Generate user subjectKeyIdentifier error", e);
		}
		// 添加权威密钥扩展
		try {
			SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Object.fromByteArray(issuerPublicKey.getEncoded()));
			GeneralName generalName = new GeneralName(issuerDN);
			// AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(spki, new
			// GeneralNames(generalName), issuerSN);

			AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(spki);
			extGenerator.addExtension(X509Extensions.AuthorityKeyIdentifier, false, aki.getDEREncoded());
		} catch (IOException e) {
			e.printStackTrace();
			throw new CoreException("Generate user authorityKeyIdentifier error", e);
		}
		// 添加SSL证书类型扩展
		// if (purpose == 1 || purpose == 3) {
		// extGenerator.addExtension(MiscObjectIdentifiers.netscapeCertType,
		// false,
		// new NetscapeCertType(NetscapeCertType.sslServer));
		// }
		// if (purpose == 2 || purpose == 3) {
		// extGenerator.addExtension(MiscObjectIdentifiers.netscapeCertType,
		// false,
		// new NetscapeCertType(NetscapeCertType.sslClient));
		// }

		X509Extensions extensions = extGenerator.generate();

		return generateX509Certificate(issuerDN, issuerPrivateKey, issuerPublicKey, userNum, notBefore, notAfter, subjectDN, signAlgorithm, subjectPublicKey, extensions);
	}

	/**
	 * 生成X509证书
	 * 
	 * @param issuerName
	 *            签发者名称
	 * @param issuerPrivateKey
	 *            签发者私钥
	 * @param issuerPublicKey
	 *            签发者公钥
	 * @param serialNum
	 *            证书序列号
	 * @param notBefore
	 *            开始有效期
	 * @param notAfter
	 *            结束有效期
	 * @param subjectName
	 *            使用者名称
	 * @param signAlgorithm
	 *            签名算法
	 * @param subjectPublicKey
	 *            使用者公钥
	 * @param extensions
	 *            证书扩展
	 * @return
	 * @throws CoreException
	 */
	public static X509Certificate generateX509Certificate(X509Name issuerName, PrivateKey issuerPrivateKey, PublicKey issuerPublicKey, BigInteger serialNum, Date notBefore,
                                                          Date notAfter, X509Name subjectName, String signAlgorithm, PublicKey subjectPublicKey, X509Extensions extensions) throws CoreException {

		try {
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

			certGen.setSerialNumber(serialNum);

			certGen.setIssuerDN(issuerName);

			certGen.setNotBefore(notBefore);

			certGen.setNotAfter(notAfter);

			certGen.setSubjectDN(subjectName);

			certGen.setPublicKey(subjectPublicKey);

			certGen.setSignatureAlgorithm(signAlgorithm);

			if (extensions != null) {
				Enumeration<?> e = extensions.oids();
				while (e.hasMoreElements()) {
					DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
					X509Extension ext = extensions.getExtension(oid);
					byte[] value = ext.getValue().getOctets();
					certGen.addExtension(oid, ext.isCritical(), value);
				}
			}
			return certGen.generate(issuerPrivateKey, PROVIDER);
		} catch (Exception e) {
			e.printStackTrace();
			String msg = "generate V3 X509 certificate error";
			logger.error(msg, e);
			throw new CoreException(msg);
		}
	}

	/**
	 * 生成PKCS12证书
	 * 
	 * @param certChain
	 *            证书链
	 * @param privateKey
	 *            签发者私钥
	 * @param alias
	 *            PKCS12条目别名
	 * @param password
	 *            PKCS12条目口令
	 * @return
	 * @throws CoreException
	 */
	public static KeyStore generatePKCS12(Certificate[] certChain, PrivateKey privateKey, String alias, String password) throws CoreException {

		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance("PKCS12", PROVIDER);
		} catch (KeyStoreException e) {
			e.printStackTrace();
			String msg = "Generate PKCS12 error";
			logger.error(msg, e);
			throw new CoreException(msg);
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			String msg = "Generate PKCS12 error";
			logger.error(msg, e);
			throw new CoreException(msg);
		}

		try {
			char[] pass = password.toCharArray();
			keyStore.load(null, pass);
			keyStore.setKeyEntry(alias, privateKey, pass, certChain);

		} catch (Exception e) {
			e.printStackTrace();
			String msg = "Generate PKCS12 error";
			logger.error(msg, e);
			throw new CoreException(msg);
		}

		return keyStore;
	}

	public static String convert2PemCert(String base64Cert) {
		byte[] certData = Base64Tools.decode(base64Cert);
		return BEGIN_CERTIFICATE + "\r\n" + Base64Tools.encodeLine(certData) + END_CERTIFICATE;
	}

	public static String convert2PemRequest(String base64Request) {
		byte[] requestData = Base64Tools.decode(base64Request);
		return BEGIN_CERTIFICATE_REQUEST + "\r\n" + Base64Tools.encodeLine(requestData) + END_CERTIFICATE_REQUEST;
	}

}
