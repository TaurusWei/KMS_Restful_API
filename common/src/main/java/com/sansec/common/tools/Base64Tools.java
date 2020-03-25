package com.sansec.common.tools;

import com.sansec.common.crypto.bitcoin.BTCTransaction;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.DLSequence;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.digests.KeccakDigest;
import org.spongycastle.crypto.digests.RIPEMD160Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.crypto.signers.HMacDSAKCalculator;
import org.spongycastle.util.Strings;
import org.springframework.util.Base64Utils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Stack;

public class Base64Tools {
	private static Base64 base64 = new Base64();

	public static String encode(byte[] data) {
		return Base64Utils.encodeToString(data);
	}

	public static byte[] decode(String data) {
		return Base64Utils.decodeFromString(data);
	}

	public static String decodeToString(String data) {
		return new String(decode(data));
	}

	public static String encodeLine(byte[] data) {
		return Base64Utils.encodeToString(data);
	}

	public static byte[] decodeLine(String data) {
		return Base64Utils.decode(data.getBytes());
	}

	public static String decodeToStringLine(String data) {
		return new String(decodeLine(data));
	}

    public static final class HmacSha512 {
        private static final String HMAC_SHA512 = "HmacSHA512";

        public static byte[] hmacSha512(final byte[] byteKey, final byte[] seed) {
            return initialize(byteKey)
                    .doFinal(seed);
        }

        private static Mac initialize(final byte[] byteKey) {
            final Mac hmacSha512 = getInstance(HMAC_SHA512);
            final SecretKeySpec keySpec = new SecretKeySpec(byteKey, HMAC_SHA512);
            try {
                hmacSha512.init(keySpec);
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
            return hmacSha512;
        }

        private static Mac getInstance(final String HMAC_SHA256) {
            try {
                return Mac.getInstance(HMAC_SHA256);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    /**
     * Converts between an array of bytes and a Base58Check string. Not instantiable.
     */
    public static final class Base58Check {

        /*---- Static functions ----*/

        // Adds the checksum and converts to Base58Check. Note that the caller needs to prepend the version byte(s).
        public static String bytesToBase58(byte[] data) {
            return rawBytesToBase58(addCheckHash(data));
        }


        // Directly converts to Base58Check without adding a checksum.
        static String rawBytesToBase58(byte[] data) {
            // Convert to base-58 string
            StringBuilder sb = new StringBuilder();
            BigInteger num = new BigInteger(1, data);
            while (num.signum() != 0) {
                BigInteger[] quotrem = num.divideAndRemainder(ALPHABET_SIZE);
                sb.append(ALPHABET.charAt(quotrem[1].intValue()));
                num = quotrem[0];
            }

            // Add '1' characters for leading 0-value bytes
            for (int i = 0; i < data.length && data[i] == 0; i++)
                sb.append(ALPHABET.charAt(0));
            return sb.reverse().toString();
        }


        // Returns a new byte array by concatenating the given array with its checksum.
        static byte[] addCheckHash(byte[] data) {
            try {
                byte[] hash = Arrays.copyOf(SHA256.doubleSha256(data), 4);
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                buf.write(data);
                buf.write(hash);
                return buf.toByteArray();
            } catch (IOException e) {
                throw new AssertionError(e);
            }
        }


        // Converts the given Base58Check string to a byte array, verifies the checksum, and removes the checksum to return the payload.
        // The caller is responsible for handling the version byte(s).
        public static byte[] base58ToBytes(String s) {
            byte[] concat = base58ToRawBytes(s);
            byte[] data = Arrays.copyOf(concat, concat.length - 4);
            byte[] hash = Arrays.copyOfRange(concat, concat.length - 4, concat.length);
            byte[] rehash = Arrays.copyOf(SHA256.doubleSha256(data), 4);
            if (!Arrays.equals(rehash, hash))
                throw new IllegalArgumentException("Checksum mismatch");
            return data;
        }


        // Converts the given Base58Check string to a byte array, without checking or removing the trailing 4-byte checksum.
        static byte[] base58ToRawBytes(String s) {
            // Parse base-58 string
            BigInteger num = BigInteger.ZERO;
            for (int i = 0; i < s.length(); i++) {
                num = num.multiply(ALPHABET_SIZE);
                int digit = ALPHABET.indexOf(s.charAt(i));
                if (digit == -1)
                    throw new IllegalArgumentException("Invalid character for Base58Check");
                num = num.add(BigInteger.valueOf(digit));
            }

            // Strip possible leading zero due to mandatory sign bit
            byte[] b = num.toByteArray();
            if (b[0] == 0)
                b = Arrays.copyOfRange(b, 1, b.length);

            try {
                // Convert leading '1' characters to leading 0-value bytes
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                for (int i = 0; i < s.length() && s.charAt(i) == ALPHABET.charAt(0); i++)
                    buf.write(0);
                buf.write(b);
                return buf.toByteArray();
            } catch (IOException e) {
                throw new AssertionError(e);
            }
        }



        /*---- Class constants ----*/

        public static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";  // Everything except 0OIl
        private static final BigInteger ALPHABET_SIZE = BigInteger.valueOf(ALPHABET.length());



        /*---- Miscellaneous ----*/

        private Base58Check() {
        }  // Not instantiable

    }

    /**
     * @author QuincySx
     * @date 2018/3/1 下午5:17
     */
    public static final class HexUtils {
        public static String toHex(byte[] bytes) {
            if (bytes == null) {
                return "";
            }
            final char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
            char[] hexChars = new char[bytes.length * 2];
            int v;
            for (int j = 0; j < bytes.length; j++) {
                v = bytes[j] & 0xFF;
                hexChars[j * 2] = hexArray[v >>> 4];
                hexChars[j * 2 + 1] = hexArray[v & 0x0F];
            }
            return new String(hexChars);
        }

        public static byte[] fromHex(String s) {
            if (s != null) {
                try {
                    StringBuilder sb = new StringBuilder(s.length());
                    for (int i = 0; i < s.length(); i++) {
                        char ch = s.charAt(i);
                        if (!Character.isWhitespace(ch)) {
                            sb.append(ch);
                        }
                    }
                    s = sb.toString();
                    int len = s.length();
                    byte[] data = new byte[len / 2];
                    for (int i = 0; i < len; i += 2) {
                        int hi = (Character.digit(s.charAt(i), 16) << 4);
                        int low = Character.digit(s.charAt(i + 1), 16);
                        if (hi >= 256 || low < 0 || low >= 16) {
                            return null;
                        }
                        data[i / 2] = (byte) (hi | low);
                    }
                    return data;
                } catch (Exception ignored) {
                }
            }
            return null;
        }
    }

    /**
     * @author QuincySx
     * @date 2018/3/1 下午5:04
     */
    public static final class Base58 {
        private static final char[] BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
        private static final int BASE58_CHUNK_DIGITS = 10;//how many base 58 digits fits in long
        private static final BigInteger BASE58_CHUNK_MOD = BigInteger.valueOf(0x5fa8624c7fba400L); //58^BASE58_CHUNK_DIGITS
        private static final byte[] BASE58_VALUES = new byte[]{-1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -2, -2, -2, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, -1, -1, -1, -1, -1, -1,
                -1, 9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
                22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
                -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
                47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

        public static byte[] decode(String input) {
            if (input == null) {
                return null;
            }
            input = input.trim();
            if (input.length() == 0) {
                return new byte[0];
            }
            BigInteger resultNum = BigInteger.ZERO;
            int nLeadingZeros = 0;
            while (nLeadingZeros < input.length() && input.charAt(nLeadingZeros) == BASE58[0]) {
                nLeadingZeros++;
            }
            long acc = 0;
            int nDigits = 0;
            int p = nLeadingZeros;
            while (p < input.length()) {
                int v = BASE58_VALUES[input.charAt(p) & 0xff];
                if (v >= 0) {
                    acc *= 58;
                    acc += v;
                    nDigits++;
                    if (nDigits == BASE58_CHUNK_DIGITS) {
                        resultNum = resultNum.multiply(BASE58_CHUNK_MOD).add(BigInteger.valueOf(acc));
                        acc = 0;
                        nDigits = 0;
                    }
                    p++;
                } else {
                    break;
                }
            }
            if (nDigits > 0) {
                long mul = 58;
                while (--nDigits > 0) {
                    mul *= 58;
                }
                resultNum = resultNum.multiply(BigInteger.valueOf(mul)).add(BigInteger.valueOf(acc));
            }
            final int BASE58_SPACE = -2;
            while (p < input.length() && BASE58_VALUES[input.charAt(p) & 0xff] == BASE58_SPACE) {
                p++;
            }
            if (p < input.length()) {
                return null;
            }
            byte[] plainNumber = resultNum.toByteArray();
            int plainNumbersOffs = plainNumber[0] == 0 ? 1 : 0;
            byte[] result = new byte[nLeadingZeros + plainNumber.length - plainNumbersOffs];
            System.arraycopy(plainNumber, plainNumbersOffs, result, nLeadingZeros, plainNumber.length - plainNumbersOffs);
            return result;
        }

        public static String encode(byte[] input) {
            if (input == null) {
                return null;
            }
            StringBuilder str = new StringBuilder((input.length * 350) / 256 + 1);
            BigInteger bn = new BigInteger(1, input);
            long rem;
            while (true) {
                BigInteger[] divideAndRemainder = bn.divideAndRemainder(BASE58_CHUNK_MOD);
                bn = divideAndRemainder[0];
                rem = divideAndRemainder[1].longValue();
                if (bn.compareTo(BigInteger.ZERO) == 0) {
                    break;
                }
                for (int i = 0; i < BASE58_CHUNK_DIGITS; i++) {
                    str.append(BASE58[(int) (rem % 58)]);
                    rem /= 58;
                }
            }
            while (rem != 0) {
                str.append(BASE58[(int) (rem % 58)]);
                rem /= 58;
            }
            str.reverse();
            int nLeadingZeros = 0;
            while (nLeadingZeros < input.length && input[nLeadingZeros] == 0) {
                str.insert(0, BASE58[0]);
                nLeadingZeros++;
            }
            return str.toString();
        }
    }

    /**
     * @author QuincySx
     * @date 2018/3/2 上午11:12
     */
    public static class KECCAK256 {
        private static final int keccak256_DIGEST_LENGTH = 32;

        public static byte[] keccak256(byte[] bytes) {
            return keccak256(bytes, 0, bytes.length);
        }

        public static byte[] keccak256(byte[] bytes, int offset, int size) {
            KeccakDigest keccakDigest = new KeccakDigest(256);
            keccakDigest.update(bytes, offset, size);
            byte[] keccak256 = new byte[keccak256_DIGEST_LENGTH];
            // TODO: 2018/3/2 有 BUG
            keccakDigest.doFinal(keccak256, offset);
            return keccak256;
        }
    }

    /**
     * @author QuincySx
     * @date 2018/3/2 下午3:13
     */
    public static class BTCUtils {
        public static byte[] reverse(byte[] bytes) {
            byte[] result = new byte[bytes.length];
            for (int i = 0; i < bytes.length; i++) {
                result[i] = bytes[bytes.length - i - 1];
            }
            return result;
        }

        public static void verify(BTCTransaction.Script[] scripts, BTCTransaction spendTx) throws BTCTransaction.Script.ScriptInvalidException {
            for (int i = 0; i < scripts.length; i++) {
                Stack<byte[]> stack = new Stack<>();
                spendTx.inputs[i].script.run(stack);//load signature+public key
                scripts[i].run(i, spendTx, stack); //verify that this transaction able to spend that output
                if (BTCTransaction.Script.verifyFails(stack)) {
                    throw new BTCTransaction.Script.ScriptInvalidException("Signature is invalid");
                }
            }
        }

        public static boolean verify(byte[] publicKey, byte[] signature, byte[] msg) {
            X9ECParameters params = SECNamedCurves.getByName("secp256k1");
            ECDomainParameters EC_PARAMS = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
            synchronized (EC_PARAMS) {
                boolean valid;
                ECDSASigner signerVer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
                try {
                    ECPublicKeyParameters pubKey = new ECPublicKeyParameters(EC_PARAMS.getCurve().decodePoint(publicKey), EC_PARAMS);
                    signerVer.init(false, pubKey);
                    ASN1InputStream derSigStream = new ASN1InputStream(signature);
                    DLSequence seq = (DLSequence) derSigStream.readObject();
                    BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
                    BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
                    derSigStream.close();
                    valid = signerVer.verifySignature(msg, r, s);
                } catch (IOException e) {
                    throw new RuntimeException();
                }
                return valid;
            }
        }
    }

    /**
     * @author QuincySx
     * @date 2018/3/1 下午5:59
     */
    public static class Base64 {
        public static String decode(String input) {
            return Strings.fromByteArray(org.spongycastle.util.encoders.Base64.decode(input));
        }

        public static String encode(BigInteger input) {
            return String.format("%064x", input);
        }

        public static String encode(byte[] input) {
            return Strings.fromByteArray(org.spongycastle.util.encoders.Base64.encode(input));
        }
    }

    /**
     * @author QuincySx
     * @date 2018/3/1 下午5:00
     */
    public static final class RIPEMD160 {
        private static final int RIPEMD160_DIGEST_LENGTH = 20;

        public static byte[] ripemd160(byte[] bytes) {
            RIPEMD160Digest ripemd160Digest = new RIPEMD160Digest();
            ripemd160Digest.update(bytes, 0, bytes.length);
            byte[] hash160 = new byte[RIPEMD160_DIGEST_LENGTH];
            ripemd160Digest.doFinal(hash160, 0);
            return hash160;
        }

        public static byte[] hash160(final byte[] bytes) {
            return ripemd160(SHA256.sha256(bytes));
        }

    }

    /**
     * @author QuincySx
     * @date 2018/3/1 下午4:58
     */
    public static final class SHA256 {
        public static byte[] sha256(byte[] bytes) {
            return sha256(bytes, 0, bytes.length);
        }

        public static byte[] sha256(byte[] bytes, int offset, int size) {
            SHA256Digest sha256Digest = new SHA256Digest();
            sha256Digest.update(bytes, offset, size);
            byte[] sha256 = new byte[32];
            sha256Digest.doFinal(sha256, 0);
            return sha256;
        }

        public static byte[] doubleSha256(byte[] bytes) {
            return doubleSha256(bytes, 0, bytes.length);
        }

        public static byte[] doubleSha256(byte[] bytes, int offset, int size) {
            try {
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                sha256.update(bytes, offset, size);
                return sha256.digest(sha256.digest());
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            return null;
        }

    }
}
