/*
 * Copyright 2016 Jigar Joshi
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.jigar.otr.crypto;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Created by jigar.joshi on 11/20/16.
 */
public class RSA {
	private static final String ALGORITHM = "RSA";
	private static final String SIGNATUER_ALGORITHM = "MD5WithRSA";
	private static final String ENCRYPTION_ALGORITHM = "RSA/ECB/PKCS1Padding";
	private static final String FINGERPRINT_HASH_ALGORITHM = "MD5";
	private static final String UTF8 = "UTF8";

	static {
		init();
	}

	private RSA() {
	}

	private static void init() {
		Security.addProvider(new BouncyCastleProvider());
	}


	public static KeyPair generateKey(int keySizeInBytes) throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
		keyGen.initialize(keySizeInBytes);
		return keyGen.generateKeyPair();
	}

	private static byte[] encrypt(byte[] text, PublicKey key) throws Exception {
		byte[] cipherText;
		Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		cipherText = cipher.doFinal(text);
		return cipherText;
	}

	public static String encrypt(String text, PublicKey key) throws Exception {
		String encryptedText;
		byte[] cipherText = encrypt(text.getBytes(UTF8), key);
		encryptedText = encodeBASE64(cipherText);
		return encryptedText;
	}

	public static String sign(String text, PrivateKey key) throws Exception {
		Signature sig = Signature.getInstance(SIGNATUER_ALGORITHM);
		sig.initSign(key);
		sig.update(text.getBytes(UTF8));
		byte[] signatureBytes = sig.sign();
		return Base64.getEncoder().encodeToString(signatureBytes);
	}


	public static boolean verifySignature(String signedText, String actualText, PublicKey key) throws Exception {
		Signature sig = Signature.getInstance(SIGNATUER_ALGORITHM);
		byte[] signatureBytes = Base64.getDecoder().decode(signedText);
		sig.initVerify(key);
		sig.update(actualText.getBytes(UTF8));
		return sig.verify(signatureBytes);
	}

	private static byte[] decrypt(byte[] text, PrivateKey key) throws Exception {
		byte[] decrypted;
		Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, key);
		decrypted = cipher.doFinal(text);
		return decrypted;
	}

	public static String decrypt(String text, PrivateKey key) throws Exception {
		String result;
		byte[] decryptedText = decrypt(decodeBASE64(text), key);
		result = new String(decryptedText, UTF8);
		return result;
	}

	public static String getKeyAsString(Key key) {
		byte[] keyBytes = key.getEncoded();
		return encodeBASE64(keyBytes);
	}

	public static PrivateKey getPrivateKeyFromString(String key) throws Exception {
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decodeBASE64(key));
		return keyFactory.generatePrivate(privateKeySpec);
	}

	public static PublicKey getPublicKeyFromString(String key) throws Exception {
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodeBASE64(key));
		return keyFactory.generatePublic(publicKeySpec);
	}

	private static String encodeBASE64(byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}

	private static byte[] decodeBASE64(String text) {
		return Base64.getDecoder().decode(text);
	}


	public static String prettyFingerPrint(PublicKey publicKey) throws NoSuchAlgorithmException {
		byte[] bytesOfMessage = publicKey.getEncoded();
		MessageDigest md = MessageDigest.getInstance(FINGERPRINT_HASH_ALGORITHM);
		byte[] arr = md.digest(bytesOfMessage);
		final StringBuilder builder = new StringBuilder();
		for (int i = 0; i < arr.length; i++) {
			builder.append(String.format("%02x", arr[i]));
			if (i < arr.length - 1) {
				builder.append(" : ");
			}
		}
		return builder.toString();
	}
}