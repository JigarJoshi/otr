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

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by jigar.joshi on 11/20/16.
 */
public class AES {
	private final SecretKey secretKey;
	private final Cipher cipher;
	private final byte[] iv;

	public AES(String secret, String secretSalt, byte[] iv) throws Exception {
		try {
			final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			final KeySpec spec = new PBEKeySpec(secret.toCharArray(), secretSalt.getBytes("UTF-8"), 65536, 256);
			final SecretKey tmp = factory.generateSecret(spec);
			this.iv = iv;
			secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
		} catch (NoSuchAlgorithmException e) {
			throw new Exception("Cannot get an instance of secret key factory", e);
		} catch (UnsupportedEncodingException e) {
			throw new Exception("encoding is not supported", e);
		} catch (InvalidKeySpecException e) {
			throw new Exception("invalid secret key", e);
		}

		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new Exception("Error getting a cipher instance for encryption", e);
		}
	}

	public final String encrypt(String plaintext) throws Exception {

		try {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new Exception("invalid secret key", e);
		}
		try {
			final byte[] cipherTextBytes = cipher.doFinal(plaintext.getBytes());
			return Base64.getEncoder().encodeToString(cipherTextBytes);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new Exception("Error encrypting base 64 format for the key", e);
		}
	}

	public final String decrypt(String cipherText) throws Exception {
		try {
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new Exception("invalid secret key", e);
		}
		try {
			final byte[] decodedCipherText = Base64.getDecoder().decode(cipherText);
			final byte[] plainTextBytes = cipher.doFinal(decodedCipherText);
			return new String(plainTextBytes);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new Exception("Error decrypting base 64 format for the key", e);
		}
	}
}
