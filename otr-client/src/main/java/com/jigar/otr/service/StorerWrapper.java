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

import com.jigar.otr.service.impl.InMemoryStorerWrapper;

/**
 * Created by jigar.joshi on 11/28/16.
 */
public interface StorerWrapper {

	int getUserId();

	String getPrivateIdKey();

	String getPublicIdKey();

	String getPrivatePreKey(String publicPreKey);


	static StorerWrapper get(Config config) {
		String storerWrapperType = config.getString("store.type", "memory");
		switch (storerWrapperType) {
			case "memory":
				return InMemoryStorerWrapper.getInstance();
		}
		return null;
	}
}
