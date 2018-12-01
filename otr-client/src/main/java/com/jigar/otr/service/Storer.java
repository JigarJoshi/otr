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

import com.google.gson.JsonObject;
import com.jigar.otr.service.impl.InMemoryStorer;

/**
 * Created by jigar.joshi on 11/22/16.
 */
public interface Storer {
	enum NameSpace {
		PRE_KEYS,
		ID_KEYS,
		USER
	}

	String ID_KEY = "id";
	String USER_KEY = "user";

	void put(NameSpace namespace, String key, JsonObject data);

	JsonObject get(NameSpace namespace, String key);

	void remove(NameSpace namespace, String key);

	void remove(NameSpace namespace);

	static Storer get(Config config) {
		String storerType = config.getString("storer.type", "memory");
		switch (storerType) {
			case "memory":
				return InMemoryStorer.getInstance();
		}
		return null;
	}
}
