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

import java.util.HashMap;
import java.util.Map;

import com.google.gson.JsonObject;
import com.jigar.otr.service.Storer;

/**
 * Created by jigar.joshi on 11/27/16.
 */
public class InMemoryStorer implements Storer {
	private static Storer INSTANCE;

	private InMemoryStorer() {

	}

	public static Storer getInstance() {
		if (INSTANCE == null) {
			INSTANCE = new InMemoryStorer();
		}
		return INSTANCE;
	}

	private final Map<NameSpace, Map<String, JsonObject>> map = new HashMap<>();

	@Override
	public void put(NameSpace namespace, String key, JsonObject data) {
		Map<String, JsonObject> valueMap = map.get(namespace);
		if (valueMap == null) {
			valueMap = new HashMap<>();
			map.put(namespace, valueMap);
		}
		valueMap.put(key, data);
	}

	@Override
	public JsonObject get(NameSpace namespace, String key) {
		Map<String, JsonObject> valueMap = map.get(namespace);
		if (valueMap == null) {
			valueMap = new HashMap<>();
		}
		JsonObject result = valueMap.get(key);
		if (result == null) {
			result = new JsonObject();
		}
		return result;
	}

	@Override
	public void remove(NameSpace namespace, String key) {
		Map<String, JsonObject> valueMap = map.get(namespace);
		if (valueMap != null) {
			valueMap.remove(key);
		}
	}

	@Override
	public void remove(NameSpace namespace) {
		map.remove(namespace);
	}
}