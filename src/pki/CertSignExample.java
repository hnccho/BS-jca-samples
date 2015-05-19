package pki;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.nio.charset.Charset;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import util.Bytes;
import util.Files;

public class CertSignExample {
	
	public static void main(String[] args) throws Exception {
		
		Security.addProvider(new BouncyCastleProvider());
		Charset charset = Charset.forName("UTF-8");
		
		// 암호화된 개인키(PBKDF1인 경우)
		File priKeyFile = new File("/SignPri.key");
		byte[] password = "hello".getBytes(charset);
		
		// 공인인증서
		File certFile = new File("/SignCert.der");
		RSAPrivateCrtKey privateKey = generatePrivateKey(priKeyFile, password);
		X509Certificate cert = generateCertificate(certFile);
		
		// 암호화
		String plainText = "오늘도 별이 바람에 스치운다.";
		
		byte[] signature = sign(privateKey, plainText.getBytes(charset));
		System.out.println(Bytes.bytesToHexString(signature));
		
		// 복호화
		boolean verified = verify(cert, signature, plainText.getBytes(charset));
		System.out.println("verified = " + verified);
	}
	
	private static X509Certificate generateCertificate(File certFile)
	throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = null;
		InputStream input = new BufferedInputStream(new FileInputStream(certFile));
		try {
			cert = (X509Certificate)certificateFactory.generateCertificate(input);
		} finally {
			try { input.close(); } catch(IOException ie) {}
		}
		return cert;
	}
	
	public static byte[] sign(PrivateKey privateKey, byte[] plainData) 
	throws GeneralSecurityException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(plainData);
		byte[] signatureData = signature.sign();
		return signatureData;
	}
	
	public static boolean verify(X509Certificate publicKey, byte[] signatureData, byte[] plainData) 
	throws GeneralSecurityException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(publicKey);
		signature.update(plainData);
		return signature.verify(signatureData);
	}
	
	private static RSAPrivateCrtKey generatePrivateKey(File priKeyFile, byte[] password)
	throws Exception {
		byte[] encryptedPrivateKey = Files.readBytes(priKeyFile);
		ASN1InputStream input = new ASN1InputStream(encryptedPrivateKey);
		try {
			ASN1Sequence sequence = (ASN1Sequence)input.readObject();
			System.out.println(sequence);
			
			// EncryptedPrivateKeyInfo
			ASN1Sequence encryptionAlgorithmIdentifier = (ASN1Sequence)sequence.getObjectAt(0);
			DEROctetString encryptedData = (DEROctetString)sequence.getObjectAt(1);
			
			// EncryptionAlgorithmIdentifier
			
			// Object Identifier
			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)encryptionAlgorithmIdentifier.getObjectAt(0);
			// Parameters
			ASN1Sequence algParameters = (ASN1Sequence)encryptionAlgorithmIdentifier.getObjectAt(1);

			DEROctetString saltString = (DEROctetString)algParameters.getObjectAt(0);
			ASN1Integer countInteger = (ASN1Integer)algParameters.getObjectAt(1);

			byte[] salt = saltString.getOctets();
			int iterationCount = countInteger.getValue().intValue();
			System.out.println("salt = " + Bytes.bytesToHexString(salt));
			System.out.println("count = " + iterationCount);
	
			int keyLength = 20;
			// 추출키 생성
			byte[] dk = generateDerivedKey(password, salt, iterationCount, keyLength);
			System.out.println("추출키 = " + Bytes.bytesToHexString(dk));
			
			// 비밀키 생성
			byte[] keyData = new byte[16];
			System.arraycopy(dk, 0, keyData, 0, 16);
			Key key = new SecretKeySpec(keyData, "SEED");
			System.out.println("비밀키 = " + Bytes.bytesToHexString(keyData));
			
			// 초기벡터(IV) 생성
			byte[] iv;
			ASN1ObjectIdentifier seedCBC = new ASN1ObjectIdentifier("1.2.410.200004.1.4");
			ASN1ObjectIdentifier seedCBCWithSHA1 = new ASN1ObjectIdentifier("1.2.410.200004.1.15");
			if( oid.equals(seedCBC)) {
				// 추출키(DK)와 상관없이 16바이트의 초기벡터를 고정
				iv = new byte[] {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35};
			} else if( oid.equals(seedCBCWithSHA1) ) {
				// 추출키(DK)에서 암호화 키(k)를 제외한 나머지 4바이트를 SHA-1 츠로 해쉬하여 20바이트의 값을 생성하고 
				// 이중 처음 16바이트를 취함 
				MessageDigest md = MessageDigest.getInstance("SHA1");
				md.update(dk, 16, 4);
				byte[] div = md.digest();
				iv = new byte[16];
				System.arraycopy(div, 0, iv, 0, 16);
			} else {
				throw new IllegalArgumentException("Can't generate a Initial Vector : Unknown OID " + oid.getId());
			}
			System.out.println("IV = " + Bytes.bytesToHexString(iv));
			
			// 개인키 복호화
			Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
			byte[] keySpecBytes = cipher.doFinal(encryptedData.getOctets());
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keySpecBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey)keyFactory.generatePrivate(keySpec);
			return privateKey;
		} finally {
			try { input.close(); } catch(IOException ie) {}
		}
	}
	
	public static byte[] generateDerivedKey(byte[] password, byte[] salt, int iterationCount, int keyLength) 
	throws DigestException, NoSuchAlgorithmException {
		
		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		if( keyLength > messageDigest.getDigestLength() ) {
			throw new IllegalArgumentException("Can't generate a derived key " + keyLength + " bytes long.");
		}
		
		byte[] derivedKey = new byte[keyLength];
		messageDigest.update(password);
		messageDigest.update(salt);
		messageDigest.digest(derivedKey, 0, derivedKey.length);
		for(int i=1; i < iterationCount; i++ ) {
			messageDigest.update(derivedKey);
			messageDigest.digest(derivedKey, 0, derivedKey.length);
		}
		return derivedKey;
	}

	
}
