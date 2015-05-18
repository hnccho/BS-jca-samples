package hash;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;

import util.Bytes;

public class ChecksumExample {
	
	public static void main(String[] args) throws Exception {
		
		File file = new File("apache-tomcat-8.0.12.zip");
		String md5 = "d5335be1f8c658bf83fa1f64b9e400e5";
		
		MessageDigest md = MessageDigest.getInstance("MD5");
		
		InputStream input = new BufferedInputStream(new FileInputStream(file));
		try {
			byte[] buffer = new byte[1024];
			int read = -1;
			while( (read=input.read(buffer)) != -1) {
				md.update(buffer, 0, read);
			}
		} finally {
			try { input.close(); }
			catch(IOException ie) {}
		}
		
		byte[] hash = md.digest();
		System.out.println("MD5 : " + md5);
		System.out.println("HASH : " + Bytes.bytesToHexString(hash));
		System.out.println(md5.equalsIgnoreCase(Bytes.bytesToHexString(hash)));
	}
	
}
