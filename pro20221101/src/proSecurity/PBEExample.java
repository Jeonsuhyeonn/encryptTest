package proSecurity;

import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

public class PBEExample {

	public static void main(String[] args) throws Exception {
		
		char [] password = "asdf1234".toCharArray();
		String plainText = "이 밤을 다시 한번";
		Charset charset = Charset.forName("utf-8");
		byte [] salt = new byte[8];
		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);
		int iterationCount = 1000;
		
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, 128);
		SecretKey secretKey = new SecretKeySpec(keyFactory.generateSecret(keySpec).getEncoded(), "AES");
		
		byte [] encryptData = encrypt(secretKey, plainText.getBytes(charset));
		byte [] decryptData = decrypt(secretKey, encryptData);
	
		System.out.println(ByteUtils.toHexString(encryptData));
		System.out.println(new String(decryptData,charset));
	}
	
	public static byte [] encrypt(SecretKey secretKey, byte [] plainData) throws Exception {
		
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte [] encryptData = cipher.doFinal(plainData);
		return encryptData;
	}
	
	public static byte [] decrypt(SecretKey secretKey, byte [] encryptData) throws Exception {
		
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte [] decryptData = cipher.doFinal(encryptData);
		return decryptData;
	}
}
