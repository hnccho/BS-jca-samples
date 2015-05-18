package hash;
import java.nio.charset.Charset;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import util.Bytes;

public class HMACExample {
	
	public static void main(String[] args) throws Exception {

		// 인증키 생성
		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
		SecretKey secretKey = keyGenerator.generateKey();
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(secretKey);
		
		Charset charset = Charset.forName("UTF-8");
		String plainText = "오늘도 별이 바람에 스치운다.";
		
		// MAC 생성
		byte[] macData = mac.doFinal(plainText.getBytes(charset));
		System.out.println(Bytes.bytesToHexString(macData));
	}
	
}
