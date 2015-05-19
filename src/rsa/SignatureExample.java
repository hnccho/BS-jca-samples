package rsa;
import java.io.File;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import util.Bytes;
import util.Files;

public class SignatureExample {
	
	public static void main(String[] args) throws Exception {
		
		// 공개키 생성
		File publicKeyFile = new File("/public.key");
		File privateKeyFile = new File("/private.key");
		
		PublicKey publicKey = null; 
		PrivateKey privateKey = null; 
		if( publicKeyFile.exists() && privateKeyFile.exists()) {
			byte[] publicKeyBytes = Files.readBytes(publicKeyFile);
			byte[] privateKeyBytes = Files.readBytes(privateKeyFile);

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes)); 
			privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes)); 
			System.out.println(Bytes.bytesToHexString(publicKey.getEncoded()));
			System.out.println(Bytes.bytesToHexString(privateKey.getEncoded()));
		} else {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1024);
			
			KeyPair pair = generator.generateKeyPair();
			publicKey = pair.getPublic();
			privateKey = pair.getPrivate();
			
			Files.writeBytes(publicKeyFile, publicKey.getEncoded());
			Files.writeBytes(privateKeyFile, privateKey.getEncoded());
		}
		
		// 암호화
		String plainText = "오늘도 별이 바람에 스치운다.";
		Charset charset = Charset.forName("UTF-8");
		
		byte[] signature = sign(privateKey, plainText.getBytes(charset));
		System.out.println(Bytes.bytesToHexString(signature));
		
		// 복호화
		boolean verified = verify(publicKey, signature, plainText.getBytes(charset));
		System.out.println("verified = " + verified);
	}
	
	public static byte[] sign(PrivateKey privateKey, byte[] plainData) 
	throws GeneralSecurityException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(plainData);
		byte[] signatureData = signature.sign();
		return signatureData;
	}
	
	public static boolean verify(PublicKey publicKey, byte[] signatureData, byte[] plainData) 
	throws GeneralSecurityException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(publicKey);
		signature.update(plainData);
		return signature.verify(signatureData);
	}
	
}
