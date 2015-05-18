package random;
import java.security.SecureRandom;

import util.Bytes;

public class SecureRandomExample {
	
	public static void main(String[] args) throws Exception {
		SecureRandom random = new SecureRandom();
		
		byte bytes[] = new byte[16];
		random.nextBytes(bytes);
		
		System.out.println(Bytes.bytesToHexString(bytes));
	}
	
}
