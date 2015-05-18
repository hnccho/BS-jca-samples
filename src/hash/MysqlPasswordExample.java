package hash;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import util.Bytes;

public class MysqlPasswordExample {
	
	public static void main(String[] args) {
		String password = "helloworld";
		String digest = password(password);
		System.out.println("MySQL Password = " + digest);
	}
	
	public static byte[] getHash(byte[] input) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA1");
			return md.digest(input);
		} catch(NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA1 Algorithm Not Found", e);
		}
	}
	
	public static String password(byte[] input) {
		byte[] digest = null;
		
		// Stage1
		digest = getHash(input);
		
		// Stage2
		digest = getHash(digest);
		
		StringBuilder sb = new StringBuilder(1+digest.length);
		sb.append("*");
		sb.append(Bytes.bytesToHexString(digest).toUpperCase());
		return sb.toString();
	}
	
	public static String password(String input) {
		if(input == null) return null;
		
		return password(input.getBytes());
	}
	
}
