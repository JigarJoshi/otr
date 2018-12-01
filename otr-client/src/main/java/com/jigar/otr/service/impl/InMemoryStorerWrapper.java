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

import com.google.gson.JsonObject;
import com.jigar.otr.service.Storer;
import com.jigar.otr.service.StorerWrapper;

import java.util.Map;

/**
 * Created by jigar.joshi on 11/28/16.
 */
public class InMemoryStorerWrapper implements StorerWrapper {
	private final Storer storer;
	private static StorerWrapper INSTANCE;

	public static StorerWrapper getInstance() {
		if (INSTANCE == null) {
			INSTANCE = new InMemoryStorerWrapper();
		}
		return INSTANCE;
	}

	private InMemoryStorerWrapper() {
		this.storer = InMemoryStorer.getInstance();
	}

	@Override
	public int getUserId() {
		return storer.get(Storer.NameSpace.USER, "user").get("userId").getAsInt();
	}

	@Override
	public String getUsername() {
		return storer.get(Storer.NameSpace.USER, "user").get("userName").getAsString();
	}

	@Override
	public String getPrivateIdKey() {
		return storer.get(Storer.NameSpace.ID_KEYS, Storer.ID_KEY).get("private").getAsString();
	}

	@Override
	public String getPublicIdKey() {
		return storer.get(Storer.NameSpace.ID_KEYS, Storer.ID_KEY).get("public").getAsString();
	}


	@Override
	public String getPrivatePreKey(String publicPreKey) {
		return storer.get(Storer.NameSpace.PRE_KEYS, publicPreKey).get("private").getAsString();
	}

	public boolean loadUser(Map<Storer.NameSpace, Map<String, JsonObject>> newUser){
		if (storer instanceof InMemoryStorer){
			return  ((InMemoryStorer) storer).set(newUser);
		}
		return false;
	}
}
