package pki;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CertValidateExample {
	
	public static void main(String[] args) throws Exception {
		
		Security.addProvider(new BouncyCastleProvider());
		
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		
		// 공인인증서
		File certFile = new File("/SignCert.der");
		X509Certificate cert = generateCertificate(certificateFactory, certFile);
		
		File yessignFile = new File("/yessign.der");
		X509Certificate yessign = generateCertificate(certificateFactory, yessignFile);

		File trustFile = new File("/root-rsa-sha2.der");
		X509Certificate trust = generateCertificate(certificateFactory, trustFile);

		List<X509Certificate> certificates = new ArrayList<X509Certificate>();
		certificates.add(cert);
		certificates.add(yessign);
		CertPath certPath = certificateFactory.generateCertPath(certificates);
		
		TrustAnchor anchor = new TrustAnchor(trust, null);
		PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
		params.setRevocationEnabled(false); // 폐기정보 비활성화

		CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
		PKIXCertPathValidatorResult result;
		try {
			result = (PKIXCertPathValidatorResult)cpv.validate(certPath, params);
			System.out.println("유효한 인증서입니다");
			System.out.println(result);
		} catch (CertPathValidatorException e) {
			System.out.println("유효하지 않은 인증서입니다");
			e.printStackTrace();
		} 
	}
	
	private static X509Certificate generateCertificate(CertificateFactory certificateFactory, File certFile)
	throws FileNotFoundException, CertificateException {
		X509Certificate cert = null;
		InputStream input = new BufferedInputStream(new FileInputStream(certFile));
		try {
			cert = (X509Certificate)certificateFactory.generateCertificate(input);
		} finally {
			try { input.close(); } catch(IOException ie) {}
		}
		return cert;
	}
	
}
