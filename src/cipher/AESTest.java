package cipher;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import util.Bytes;

public class AESTest {
	
	public static void main(String[] args) throws Exception {
		
		// 비밀키 생성
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey secretKey = keyGenerator.generateKey();
		Charset charset = Charset.forName("UTF-8");
		
		// 암호화
		String plainText = "오늘도 별이 바람에 스치운다.";
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
