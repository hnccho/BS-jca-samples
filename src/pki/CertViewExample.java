package pki;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertViewExample {
	
	public static void main(String[] args) throws Exception {
		
		// 공인인증서
		File certFile = new File("/SignCert.der");
		
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		
		X509Certificate cert = null;
		InputStream input = new BufferedInputStream(new FileInputStream(certFile));
		try {
			cert = (X509Certificate)certificateFactory.generateCertificate(input);
		} finally {
			try { input.close(); } catch(IOException ie) {}
		}
		System.out.println(cert);
	}
}
