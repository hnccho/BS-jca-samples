package hash;
import java.nio.charset.Charset;
import java.security.MessageDigest;

import util.Bytes;

public class MessageDigestExample {
	
	public static void main(String[] args) throws Exception {
		Charset charset = Charset.forName("UTF-8");
		String plainText = "오늘도 별이 바람에 스치운다.";
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		
		md.update(plainText.getBytes(charset));
		byte[] hash = md.digest();
		System.out.println(Bytes.bytesToHexString(hash));
	}
	
}
