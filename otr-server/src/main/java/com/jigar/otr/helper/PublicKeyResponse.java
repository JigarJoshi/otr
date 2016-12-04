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

package com.jigar.otr.helper;

/**
 * Created by jigar.joshi on 11/17/16.
 */
public class PublicKeyResponse {
	private final String publicKey;

	public PublicKeyResponse(String publicKey) {
		this.publicKey = publicKey;
	}

	public String getPublicKey() {
		return publicKey;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		PublicKeyResponse that = (PublicKeyResponse) o;

		return publicKey != null ? publicKey.equals(that.publicKey) : that.publicKey == null;

	}

	@Override
	public int hashCode() {
		return publicKey != null ? publicKey.hashCode() : 0;
	}
}