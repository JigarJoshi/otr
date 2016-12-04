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

package com.jigar.otr.service;

import java.util.List;

import com.jigar.otr.exception.CryptoException;

/**
 * Created by jigar.joshi on 11/7/16.
 */
public interface CryptoService {
	String getPrePublicKey(int userId) throws CryptoException;

	int getPrePublicKeyCount(int userId) throws CryptoException;

	String getPublicKey(int userId) throws CryptoException;

	void addPreKeys(int userId, List<String> prePublicKeys) throws CryptoException;

	void deletePreKeyById(int id);

	int countPreKeyByUserId(int userId);
}
