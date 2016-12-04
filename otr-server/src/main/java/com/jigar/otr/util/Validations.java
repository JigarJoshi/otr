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

import com.jigar.otr.exception.ValidationException;

/**
 * Created by jigar.joshi on 11/10/16.
 */
public class Validations {


	public static void validatePassword(String password) throws ValidationException {
		if (password.length() < 8) {
			throw new ValidationException("password length needs to be atleast 8 character");
		}
	}

	public static void validateLogin(String login) throws ValidationException {
		if (login == null || login.isEmpty()) {
			throw new ValidationException("invalid login");
		}
	}
}
