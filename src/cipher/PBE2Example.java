package cipher;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import util.Bytes;

public class PBE2Example {
	
	public static void main(String[] args) throws Exception {
		char[] password = "chohunchul".toCharArray();
		
		String plainText = "오늘도 별이 바람에 스치운다.";
		Charset charset = Charset.forName("UTF-8");
		
		// salt 생성
		byte[] salt = new byte[8];
		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);
		int iterationCount = 1000;
		
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, 128);
		
		SecretKey secretKey = new SecretKeySpec(keyFactory.generateSecret(keySpec).getEncoded(), "AES");
		
		// 암호화
		byte[] encryptData = encrypt(secretKey, plainText.getBytes(charset));
		System.out.println(Bytes.bytesToHexString(encryptData));
		
		// 복호화
		byte[] decrptData = decrypt(secretKey, encryptData);
		System.out.println(new String(decrptData, charset));
	}
	
	public static byte[] encrypt(SecretKey secretKey, byte[] plainData) 
	throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] encryptData = cipher.doFinal(plainData);
		return encryptData;
	}
	
	public static byte[] decrypt(SecretKey secretKey, byte[] encryptData) 
	throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] decryptData = cipher.doFinal(encryptData);
		return decryptData;
	}
	
}
