package cipher;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import util.Bytes;

public class PBEExample {
	
	public static void main(String[] args) throws Exception {
		char[] password = "".toCharArray();
		
		String plainText = "오늘도 별이 바람에 스치운다.";
		Charset charset = Charset.forName("UTF-8");
		
		// salt 생성
		byte[] salt = new byte[8];
		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);
		int iterationCount = 1000;
		
		PBEKeySpec keySpec = new PBEKeySpec(password);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		
		SecretKey secretKey = keyFactory.generateSecret(keySpec);
		PBEParameterSpec params = new PBEParameterSpec(salt, iterationCount);
		
		// 암호화
		byte[] encryptData = encrypt(secretKey, params, plainText.getBytes(charset));
		System.out.println(Bytes.bytesToHexString(encryptData));
		
		// 복호화
		byte[] decrptData = decrypt(secretKey, params, encryptData);
		System.out.println(new String(decrptData, charset));
	}
	
	public static byte[] encrypt(SecretKey secretKey, PBEParameterSpec params, byte[] plainData) 
	throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, params);
		byte[] encryptData = cipher.doFinal(plainData);
		return encryptData;
	}
	
	public static byte[] decrypt(SecretKey secretKey, PBEParameterSpec params, byte[] encryptData) 
	throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, params);
		byte[] decryptData = cipher.doFinal(encryptData);
		return decryptData;
	}
	
}
