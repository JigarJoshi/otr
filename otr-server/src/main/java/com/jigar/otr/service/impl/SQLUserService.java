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
import com.lithium.flow.util.Logs;

import java.security.PublicKey;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.validation.constraints.NotNull;

import org.slf4j.Logger;

import com.jigar.otr.crypto.RSA;
import com.jigar.otr.exception.UserException;
import com.jigar.otr.service.Database;
import com.jigar.otr.service.UserService;
import com.jigar.otr.util.Utils;
import com.jigar.otr.util.Validations;

/**
 * Created by jigar.joshi on 11/10/16.
 */
public class SQLUserService implements UserService {

	private final Database databasePool;
	private final RSA rsa;

	private static final Logger log = Logs.getLogger();

	public SQLUserService(Database databasePool, Config config) {
		this.databasePool = databasePool;
		this.rsa = new RSA(config);
	}

	@Override
	public String listUsers() throws UserException{

		Connection connection = null;
		PreparedStatement userPreparedStatement;
		String users;
		try
		{
			users = "";
			connection = databasePool.getConnection();
			userPreparedStatement = connection.prepareStatement("SELECT id, login FROM USERS");
			ResultSet resultSet = userPreparedStatement.executeQuery();
			while(resultSet.next()){
				users += resultSet.getInt(1) + "," + resultSet.getString(2) + "\n";
			}
		}
		catch (Exception ex) {
		log.error("Failed to list users", ex);
		throw new UserException("Failed to list users" + ex.getMessage());
		}
		finally {
			Utils.closeQuietly(connection);
		}
		return users;
	}


	@Override
	public int registerUser(@NotNull String login, @NotNull String password, @NotNull String clientPublicKey,
			@NotNull List<String> preKeys) throws UserException {
		System.out.println("Hi from register user");
		Validations.validatePassword(password);
		Validations.validateLogin(login);

		Connection connection = null;
		PreparedStatement userPreparedStatement;
		int userId = -1;
		try {
			byte[] salt = Utils.generateRandomSalt();
			byte[] hashedPassword = Utils.hash(password.toCharArray(), salt);
			connection = databasePool.getConnection();
			userPreparedStatement = connection.prepareStatement("INSERT INTO USERS (login, password, salt, " +
					"PUBLIC_ID_KEY) values (?, ?, ?, ?)", Statement.RETURN_GENERATED_KEYS);
			userPreparedStatement.setString(1, login);
			userPreparedStatement.setString(2, Utils.base64Encode(hashedPassword));
			userPreparedStatement.setString(3, Utils.base64Encode(salt));
			userPreparedStatement.setString(4, clientPublicKey);
			int result = userPreparedStatement.executeUpdate();
			log.info("{} rows updated ", result);
			try (ResultSet generatedKeys = userPreparedStatement.getGeneratedKeys()) {
				if (generatedKeys.next()) {
					userId = generatedKeys.getInt(1);
				} else {
					throw new SQLException("Creating user failed, no ID obtained.");
				}
			}

			for (String preKey : preKeys) {
				try (PreparedStatement preKeysPreparedStatement = connection.prepareStatement("" +
						"INSERT INTO PRE_KEYS (USER_ID, PUBLIC_KEY) VALUES (?, ?)")) {
					preKeysPreparedStatement.setLong(1, userId);
					preKeysPreparedStatement.setString(2, preKey);
					log.info("inserted pre-key {}", preKeysPreparedStatement.executeUpdate());
				}
			}
		} catch (Exception ex) {
			log.error("Failed to register user", ex);
			throw new UserException("Failed to register user" + ex.getMessage());
		} finally {
			Utils.closeQuietly(connection);
		}
		return userId;
	}


	@Override
	public int login(String login, String password, String signedLogin) throws UserException {
		Validations.validatePassword(password);
		Validations.validateLogin(login);

		Connection connection = null;
		PreparedStatement loginPreparedStatement = null;
		PreparedStatement validationPreparedStatement;
		int userId = -1;
		try {
			connection = databasePool.getConnection();
			loginPreparedStatement = connection.prepareStatement("SELECT SALT, ID, PUBLIC_ID_KEY FROM USERS WHERE LOGIN = ?");
			loginPreparedStatement.setString(1, login);
			ResultSet resultSet = loginPreparedStatement.executeQuery();
			String salt = null;
			String publicIdKeyStr = null;
			while (resultSet.next()) {
				salt = resultSet.getString(1);
				userId = resultSet.getInt(2);
				publicIdKeyStr = resultSet.getString(3);
			}
			if (salt == null | publicIdKeyStr == null) {
				log.error("Salt ={} , publicIdKeyStr = {} - Null not allowed", salt, publicIdKeyStr);
				throw new UserException("Login failed");
			}
			// verify authenticity with signature
			PublicKey clientPublicIdKey = RSA.getPublicKeyFromString(publicIdKeyStr);
			if (!rsa.verifySignature(signedLogin, login, clientPublicIdKey)) {
				log.error("User failed to login, signature mismatch");
				throw new UserException("Login Failed: Signature mismatch");
			}

			byte[] providedPasswordHash = Utils.hash(password.toCharArray(), Utils.base64Decode(salt));
			String providedPassword = Utils.base64Encode(providedPasswordHash);
			validationPreparedStatement = connection.prepareStatement("SELECT LOGIN FROM USERS WHERE LOGIN = ? AND SALT = ? AND PASSWORD = ?");
			validationPreparedStatement.setString(1, login);
			validationPreparedStatement.setString(2, salt);
			validationPreparedStatement.setString(3, providedPassword);
			ResultSet rs = validationPreparedStatement.executeQuery();
			boolean loggedIn = false;
			while (rs.next()) {
				loggedIn = true;
				break;
			}
			if (!loggedIn) {
				log.error("Failed to login user");
				throw new UserException("Failed to login");
			}
			log.debug("login successful {}", login);
		} catch (Exception ex) {
			log.error("Failed to login user", ex);
			throw new UserException("Failed to login : " + ex.getMessage());
		} finally {
			Utils.closeQuietly(connection);
			Utils.closeQuietly(loginPreparedStatement);
		}
		return userId;
	}
}
