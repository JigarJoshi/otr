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

package com.jigar.otr.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Created by jigar.joshi on 11/10/16.
 */
public class Utils {

	public static final String SUCCESSFUL_CODE = "successful";
	public static final String FAIL_CODE = "failed";

	public static byte[] generateRandomSalt() {
		final Random r = new SecureRandom();
		byte[] salt = new byte[24];
		r.nextBytes(salt);
		return salt;
	}

	public static byte[] base64Decode(String data) {
		return Base64.getDecoder().decode(data);
	}

	public static String base64Encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}

	public static byte[] hash(char[] password, byte[] salt) {
		PBEKeySpec spec = new PBEKeySpec(password, salt, 1000, 128);
		Arrays.fill(password, Character.MIN_VALUE);
		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1"); //PBKDF2WithHmacSHA1
			return skf.generateSecret(spec).getEncoded();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new AssertionError("Error while hashing a password: " + e.getMessage(), e);
		} finally {
			spec.clearPassword();
		}
	}


	public static void closeQuietly(Connection connection) {
		try {
			connection.close();
		} catch (Exception ignore) {}
	}

	public static void closeQuietly(ResultSet resultSet) {
		try {
			resultSet.close();
		} catch (Exception ignore) {}
	}


	public static void closeQuietly(PreparedStatement preparedStatement) {
		try {
			preparedStatement.close();
		} catch (Exception ignore) {}
	}
}
