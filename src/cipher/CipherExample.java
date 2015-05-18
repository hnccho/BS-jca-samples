package cipher;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CipherExample {
	
	public static void main(String[] args) throws Exception {
		
		// 비밀키 생성
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey secretKey = keyGenerator.generateKey();
		String tansformation = "AES/ECB/PKCS5Padding";
		
		File plainFile = new File("/plain.txt");
		File encryptFile = new File("/encrypt.txt");
		File decryptFile = new File("/decrypt.txt");
		
		// 파일 암호화
		encrypt(secretKey, tansformation, plainFile, encryptFile);
		
		// 파일 복호화
		decrypt(secretKey, tansformation, encryptFile, decryptFile);
	}
	
	public static void encrypt(SecretKey secretKey, String tansformation, File plainFile, File encryptFile) 
	throws Exception {
		Cipher cipher = Cipher.getInstance(tansformation);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		
		InputStream input = null;
		OutputStream output = null;
		
		try {
			input = new BufferedInputStream(new FileInputStream(plainFile));
			output = new BufferedOutputStream(new FileOutputStream(encryptFile));
			
			int read = 0;
			byte[] inbuf = new byte[1024];
			byte[] outbuf = null;
			
			while( (read = input.read(inbuf)) != -1 ) {
				outbuf = cipher.update(inbuf, 0, read);
				if(outbuf != null) {
					output.write(outbuf);
				}	
			}
			outbuf = cipher.doFinal();
			output.write(outbuf);
		} finally {
			if( output != null ) try { output.close(); } catch(IOException ie) {}
			if( input != null ) try { input.close(); } catch(IOException ie) {}
		}
	}
	
	public static void decrypt(SecretKey secretKey, String tansformation, File encryptFile, File decryptFile) 
	throws Exception {
		Cipher cipher = Cipher.getInstance(tansformation);
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		
		InputStream input = null;
		OutputStream output = null;
		
		try {
			input = new BufferedInputStream(new FileInputStream(encryptFile));
			output = new BufferedOutputStream(new FileOutputStream(decryptFile));
			
			int read = 0;
			byte[] inbuf = new byte[1024];
			byte[] outbuf = null;
			
			while( (read = input.read(inbuf)) != -1 ) {
				outbuf = cipher.update(inbuf, 0, read);
				if(outbuf != null) {
					output.write(outbuf);
				}	
			}
			outbuf = cipher.doFinal();
			output.write(outbuf);
		} finally {
			if( output != null ) try { output.close(); } catch(IOException ie) {}
			if( input != null ) try { input.close(); } catch(IOException ie) {}
		}
	}
	
}
