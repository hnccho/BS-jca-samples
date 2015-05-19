package pki;
import java.io.File;
import java.security.Key;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import util.Files;

public class EncryptedPrivateKeyExample {
	
	public static void main(String[] args) throws Exception {
		
		// 암호화된 개인키(PBES1인 경우)
		File priKeyFile = new File("/SignPri.key");
		char[] password = "hello".toCharArray();
		
		byte[] encryptedPrivateKey = Files.readBytes(priKeyFile);
		EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(encryptedPrivateKey);
		System.out.println(encryptedPrivateKeyInfo.getAlgName());
		
		SecretKeyFactory skFactory = SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
		Key key = skFactory.generateSecret(new PBEKeySpec(password));
		
		Cipher cipher = Cipher.getInstance(encryptedPrivateKeyInfo.getAlgName());
		cipher.init(Cipher.DECRYPT_MODE, key, encryptedPrivateKeyInfo.getAlgParameters());

		PKCS8EncodedKeySpec keySpec = encryptedPrivateKeyInfo.getKeySpec(cipher);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey)keyFactory.generatePrivate(keySpec);

		System.out.println(privateKey);

	}
}
