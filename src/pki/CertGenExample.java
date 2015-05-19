package pki;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder; 
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertGenExample {
	
	public static void main(String[] args) throws Exception {
		
		Security.addProvider(new BouncyCastleProvider());
		
		// 공개키 생성
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		
		KeyPair pair = generator.generateKeyPair();
		PublicKey publicKey = pair.getPublic();
		PrivateKey privateKey = pair.getPrivate();
		
		// Serial Number
		BigInteger serialNumber = BigInteger.valueOf(1);
		
		// Subject and Issue DN
		X500Name subjectDN = new X500Name("C=US,O=Bluedawn,OU=PKI,CN=RootCA"); // 대상
		X500Name issuerDN = new X500Name("C=US,O=Bluedawn,OU=PKI,CN=RootCA"); // 발급자
		
		// Validity(유효기간)
		Date notBefore = new Date(System.currentTimeMillis());
		Date notAfter = new Date(notBefore.getTime() + (((1000L*60*60*24*30))*12)*3);
	
		// SubjectPublicKeyInfo(공개키정보)
		SubjectPublicKeyInfo subjPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(publicKey.getEncoded()));
		
		X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuerDN, serialNumber, notBefore, notAfter, subjectDN, subjPubKeyInfo);
		DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
		X509ExtensionUtils x509ExtentionUtils = new X509ExtensionUtils(digCalc);
		
		// Subject Key Identifier
		certBuilder.addExtension(Extension.subjectKeyIdentifier, false, x509ExtentionUtils.createSubjectKeyIdentifier(subjPubKeyInfo));
		
		// Autority Key Identifier
		certBuilder.addExtension(Extension.authorityKeyIdentifier, false, x509ExtentionUtils.createAuthorityKeyIdentifier(subjPubKeyInfo));

		// Key Usage
		certBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
	
		// Extended Key Usage
		KeyPurposeId[] eku = new KeyPurposeId[2];
		eku[0] = KeyPurposeId.id_kp_emailProtection;
		eku[1] = KeyPurposeId.id_kp_serverAuth;
		certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
		
		// Basic Constraints
		certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
		
		// Certificate Policies
		PolicyInformation[] certPolicies = new PolicyInformation[2];
		certPolicies[0] = new PolicyInformation(new ASN1ObjectIdentifier("2.16.840.1.101.2.1.11.5"));
		certPolicies[1] = new PolicyInformation(new ASN1ObjectIdentifier("2.16.840.1.101.2.1.11.9"));
		certBuilder.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(certPolicies));
		
		// Subject Alternative Name
		GeneralName[] genNames = new GeneralName[2];
		genNames[0] = new GeneralName(GeneralName.rfc822Name, new DERIA5String("hnccho@hanafos.com"));
		genNames[1] = new GeneralName(GeneralName.directoryName, new X500Name("C=US,O=Bluedawn,OU=PKI,CN=RootCA"));
		certBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(genNames));

		// Authority Information Access
		AccessDescription caIssuers = new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String("http://www.aramsoft.co.kr")));
		AccessDescription ocsp = new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String("http://ocsp.aramsoft.co.kr")));
		ASN1EncodableVector aia_ASN = new ASN1EncodableVector();
		aia_ASN.add(caIssuers);
		aia_ASN.add(ocsp);
		certBuilder.addExtension(Extension.authorityInfoAccess, false, new DERSequence(aia_ASN));

		// CRL Distribution Points
		DistributionPointName distPointOne = new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, "http://www.aramsoft.co.kr/master.crl")));
		DistributionPointName distPointTwo = new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, "ldap://www.aramsoft.co.kr/cn%3dRootCA%2cou%3dBluedawn%2cc%3dUS?certificationlist;binary")));
		DistributionPoint[] distPoints = new DistributionPoint[2];
		distPoints[0] = new DistributionPoint(distPointOne, null, null);
		distPoints[1] = new DistributionPoint(distPointTwo, null, null);
		
		// Content Signer
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1WithRSA").setProvider("BC").build(privateKey);
		X509CertificateHolder certificateHolder = certBuilder.build(contentSigner);
		
		// Certificate
		X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
		System.out.println(certificate);
		
	}
	
}
