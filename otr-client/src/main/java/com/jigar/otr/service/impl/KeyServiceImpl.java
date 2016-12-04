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

package com.jigar.otr.service.impl;

import com.lithium.flow.config.Config;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import com.jigar.otr.crypto.ECDH;
import com.jigar.otr.crypto.RSA;
import com.jigar.otr.exception.OTRException;
import com.jigar.otr.service.KeyService;

/**
 * Created by jigar.joshi on 11/22/16.
 */
public class KeyServiceImpl implements KeyService {
	private final Config config;

	public KeyServiceImpl(Config config) {
		this.config = config;
	}

	@Override
	public List<KeyPair> generateMessageKeys(int numberOfKeys) throws OTRException {
		boolean trustPlatform = config.getBoolean("keys.trustPlatform", false);
		List<KeyPair> result = new ArrayList<>(numberOfKeys);
		Random random = new Random();
		try {
			while (result.size() <= numberOfKeys) {
				KeyPair keyPair = ECDH.generateKeyPair();
				if (trustPlatform || random.nextBoolean()) {
					result.add(keyPair);
				}
			}
			return result;
		} catch (InvalidAlgorithmParameterException |
				NoSuchAlgorithmException | NoSuchProviderException ex) {
			throw new OTRException("Failed to generate pre-keys ", ex);
		}
	}

	@Override
	public KeyPair generateClientIdentityKeyPair() throws OTRException {
		try {
			return RSA.generateKey(config.getInt("keys.identity.keySize", 4096));
		} catch (NoSuchAlgorithmException ex) {
			throw new OTRException("Failed to generate client identity keypair", ex);
		}
	}

	@Override
	public void addTrusted(PublicKey publicKey, String userName) {
		//TODO: update trusted store
	}
}
