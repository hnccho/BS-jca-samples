package util;

public class Bytes {

	private final static char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();

	public static String bytesToHexString(byte[] bytes) {
		if(bytes==null) return null;
		
		char[] hexChars = new char[bytes.length * 2];
		for(int i=0; i < bytes.length; i++) {
			int value = bytes[i] & 0xff;
			hexChars[i*2] = HEX_CHARS[value>>>4];
			hexChars[i*2+1] = HEX_CHARS[value & 0x0f];
		}
		return new String(hexChars);
	}
	
}
