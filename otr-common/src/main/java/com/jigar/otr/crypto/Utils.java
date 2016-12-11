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

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by jigar.joshi on 11/22/16.
 */
public class Utils {

	public static String generateRandomSalt() {
		return new BigInteger(130, new SecureRandom()).toString(32);
	}

	private static final char[] hexArray = "0123456789abcdef".toCharArray();

	public static byte[] generateRandomIV() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return iv;
	}

	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
}
