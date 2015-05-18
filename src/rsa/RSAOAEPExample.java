package rsa;
import java.io.File;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import util.Bytes;
import util.Files;

public class RSAOAEPExample {
	
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
		
		byte[] encryptData = encrypt(publicKey, plainText.getBytes(charset));
		System.out.println(Bytes.bytesToHexString(encryptData));
		
		// 복호화
		byte[] decrptData = decrypt(privateKey, encryptData);
		System.out.println(new String(decrptData, charset));
	}
	
	public static byte[] encrypt(PublicKey publicKey, byte[] plainData) 
	throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptData = cipher.doFinal(plainData);
		return encryptData;
	}
	
	public static byte[] decrypt(PrivateKey privateKey, byte[] encryptData) 
	throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decryptData = cipher.doFinal(encryptData);
		return decryptData;
	}
	
}
