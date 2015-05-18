package cipher;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import util.Bytes;

public class AESCBCWithIVTest {
	
	public static void main(String[] args) throws Exception {
		
		// 비밀키 생성
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey secretKey = keyGenerator.generateKey();

		// IV 생성
		SecureRandom random = new SecureRandom();
		byte[] ivData = new byte[16];
		random.nextBytes(ivData);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(ivData);
		Charset charset = Charset.forName("UTF-8");
		
		// 암호화
		String plainText = "오늘도 별이 바람에 스치운다.";
		byte[] encryptData = encrypt(secretKey, ivParameterSpec, plainText.getBytes(charset));
		System.out.println(Bytes.bytesToHexString(encryptData));
		
		// 복호화
		byte[] decrptData = decrypt(secretKey, ivParameterSpec, encryptData);
		System.out.println(new String(decrptData, charset));
	}
	
	public static byte[] encrypt(SecretKey secretKey, IvParameterSpec ivParameterSpec, byte[] plainData) 
	throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
		byte[] encryptData = cipher.doFinal(plainData);
		return encryptData;
	}
	
	public static byte[] decrypt(SecretKey secretKey, IvParameterSpec ivParameterSpec, byte[] encryptData) 
	throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
		byte[] decryptData = cipher.doFinal(encryptData);
		return decryptData;
	}
	
}
