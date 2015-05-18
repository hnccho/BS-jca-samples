package util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class Files {

	public static void writeBytes(File file, byte[] bytes) throws IOException {
		OutputStream output = new BufferedOutputStream(new FileOutputStream(file));
		
		try {
			output.write(bytes);
		} finally {
			try { output.close(); } catch(IOException ie) {}
		}
	}
	
	public static byte[] readBytes(File file) throws IOException {
		byte[] bytes = null;
		
		InputStream input = null;
		ByteArrayOutputStream output = null;
		try {
			input = new BufferedInputStream(new FileInputStream(file));
			output = new ByteArrayOutputStream();
			
			byte[] buffer = new byte[1024];
			int read = -1;
			while( (read = input.read(buffer)) != -1) {
				output.write(buffer, 0, read);
			}
			bytes = output.toByteArray();
		} finally {
			try { output.close(); } catch(IOException ie) {}
			try { input.close(); } catch(IOException ie) {}
		}
		return bytes;
	}
	
}
