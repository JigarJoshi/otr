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
import java.util.Map;

import com.jigar.otr.exception.UserException;

/**
 * Created by jigar.joshi on 11/10/16.
 */
public interface UserService {

	int registerUser(String login, String password, String clientPublicKey,
			List<String> preKeys) throws UserException;

	int login(String login, String password, String clientPublicKey) throws UserException;

	String listUsers() throws UserException;
}
