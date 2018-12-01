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

import com.lithium.flow.util.Logs;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import org.slf4j.Logger;

import com.jigar.otr.service.CryptoService;
import com.jigar.otr.util.Utils;
import com.jigar.otr.exception.CryptoException;
import com.jigar.otr.service.Database;

/**
 * Created by jigar.joshi on 11/7/16.
 */
public class CryptoServiceImpl implements CryptoService {
	private final Database databasePool;

	private static final Logger log = Logs.getLogger();

	public CryptoServiceImpl(Database databasePool) {
		this.databasePool = databasePool;
	}

	@Override
	public String getPrePublicKey(int userId) throws CryptoException {
		PreparedStatement getPreparedStatement;
		ResultSet getResultSet = null;
		Connection connection = null;
		String result = null;
		try {
			connection = databasePool.getConnection();
			getPreparedStatement = connection.prepareStatement("SELECT id, public_key FROM PRE_KEYS where USER_ID = ? LIMIT 1");
			getPreparedStatement.setInt(1, userId);
			getResultSet = getPreparedStatement.executeQuery();
			int id = -1;
			while (getResultSet.next()) {
				result = getResultSet.getString("PUBLIC_KEY");
				id = getResultSet.getInt("ID");
				break;
			}

			if (result == null) {
				throw new CryptoException("Failed to find pre_public_key");
			}

			// determine if it is safe to delete that pub_key
			int count = countPreKeyByUserId(userId);
			if (count > 1 && id != -1L) {
				this.deletePreKeyById(id);
			}
		} catch (SQLException exception) {
			log.error("Failed to read SinglePreKey for user = " + userId, exception);
		} finally {
			Utils.closeQuietly(connection);
			Utils.closeQuietly(getResultSet);
		}
		return result;
	}

	@Override
	public int countPreKeyByUserId(int userId) {
		Connection connection = null;
		ResultSet resultSet = null;
		PreparedStatement preparedStatement = null;
		int result = -1;
		try {
			connection = databasePool.getConnection();
			preparedStatement = connection.prepareStatement("SELECT COUNT(PUBLIC_KEY) from PRE_KEYS WHERE USER_ID=?");
			preparedStatement.setLong(1, userId);
			resultSet = preparedStatement.executeQuery();
			resultSet.next();
			result = resultSet.getInt(1);
		} catch (SQLException sqlException) {
			log.error("Failed to execute count query ", sqlException);
		} finally {
			Utils.closeQuietly(connection);
			Utils.closeQuietly(preparedStatement);
			Utils.closeQuietly(resultSet);
		}
		return result;
	}

	@Override
	public void deletePreKeyById(int id) {
		Connection connection = null;
		ResultSet resultSet = null;
		PreparedStatement preparedStatement = null;
		int result;
		try {
			connection = databasePool.getConnection();
			preparedStatement = connection.prepareStatement("DELETE FROM PRE_KEYS WHERE ID = ?");
			preparedStatement.setInt(1, id);
			result = preparedStatement.executeUpdate();
			// resultSet.next();
			// result = resultSet.getInt(1);
			log.debug("deleted pre_key, id={}", result);
		} catch (SQLException sqlException) {
			log.error("Failed to execute count query ", sqlException);
		} finally {
			Utils.closeQuietly(connection);
			Utils.closeQuietly(preparedStatement);
			// Utils.closeQuietly(resultSet);
		}
	}

	@Override
	public int getPrePublicKeyCount(int userId) throws CryptoException {
		PreparedStatement getPreparedStatement;
		ResultSet getResultSet = null;
		Connection connection = null;
		int result = 0;
		try {
			connection = databasePool.getConnection();
			getPreparedStatement = connection.prepareStatement("SELECT count(*) FROM PRE_KEYS where USER_ID = ?");
			getPreparedStatement.setInt(1, userId);
			getResultSet = getPreparedStatement.executeQuery();
			while (getResultSet.next()) {
				result = getResultSet.getInt("total");
				break;
			}
		} catch (SQLException ex) {
			log.error("Failed to read SinglePreKey for user = " + userId, ex);
			throw new CryptoException("Failed to read count, reason = " + ex.getMessage(), ex);
		} finally {
			Utils.closeQuietly(connection);
			Utils.closeQuietly(getResultSet);
		}
		return result;
	}

	@Override
	public String getPublicKey(int userId) throws CryptoException {

		PreparedStatement getPreparedStatement;
		ResultSet getResultSet = null;
		Connection connection = null;
		String result = null;
		try {
			connection = databasePool.getConnection();
			getPreparedStatement = connection.prepareStatement("SELECT public_id_key FROM USERS where ID = ?");
			getPreparedStatement.setInt(1, userId);
			getResultSet = getPreparedStatement.executeQuery();
			while (getResultSet.next()) {
				result = getResultSet.getString("public_id_key");
				break;
			}
			if (result == null) {
				throw new CryptoException("Failed to find public_id_key");
			}
		} catch (SQLException exception) {
			log.error("Failed to read SinglePreKey for user = " + userId, exception);
		} finally {
			Utils.closeQuietly(connection);
			Utils.closeQuietly(getResultSet);
		}
		return result;
	}

	@Override
	public void addPreKeys(int userId, List<String> prePublicKeys) throws CryptoException {
		Connection connection;
		try {
			connection = databasePool.getConnection();
			for (String preKey : prePublicKeys) {
				try (PreparedStatement preKeysPreparedStatement = connection.prepareStatement("" +
						"INSERT INTO PRE_KEYS (USER_ID, PUBLIC_KEY) VALUES (?, ?)")) {
					preKeysPreparedStatement.setLong(1, userId);
					preKeysPreparedStatement.setString(2, preKey);
					log.info("inserted pre-key {}", preKeysPreparedStatement.executeUpdate());
				}
			}
		} catch (SQLException sqlException) {
			log.error("Failed to insert pre-keys", sqlException);
			throw new CryptoException("Failed to insert prePublicKeys, reason" + sqlException.getMessage());
		}
	}
}
