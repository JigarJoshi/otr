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

import com.lithium.flow.config.Config;

import com.jigar.otr.exception.OTRException;
import com.jigar.otr.service.impl.OTRRestClient;

import java.util.Map;

/**
 * Created by jigar.joshi on 11/21/16.
 */
public interface OTRClient {


	void register(String login, String password) throws OTRException;

	void login(String login, String password) throws OTRException;

	void logout() throws OTRException;

	void refreshMessageKeys() throws OTRException;

	void readMessages();

	void sendMessage(String message, int toUserId) throws OTRException;

	String getPublicIdKey(int userId) throws OTRException;

	String getPrePublicKey(int userId) throws OTRException;

	String listUsers() throws OTRException;

	static OTRClient get(Config config) {
		String clientType = config.getString("otr.client", "rest");
		switch (clientType) {
			case "rest":
				return OTRRestClient.getInstance(config);

		}
		return null;
	}

}
