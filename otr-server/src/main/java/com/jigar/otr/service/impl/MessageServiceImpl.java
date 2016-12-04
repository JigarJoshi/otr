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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.jigar.otr.exception.MessageException;
import com.jigar.otr.helper.MessageHelper;
import com.jigar.otr.service.MessageService;
import com.jigar.otr.util.Utils;
import com.jigar.otr.service.Database;

/**
 * Created by jigar.joshi on 11/7/16.
 */
public class MessageServiceImpl implements MessageService {

	private final Database database;

	public MessageServiceImpl(Database database) {
		this.database = database;
	}

	@Override
	public void sendMessage(long fromUserId, long toUserId, String message, String salt, String signedSalt,
			String messageMetadata, String sendersPublicPreKey, String recipientPublicPreKey) throws MessageException {
		Connection connection = null;
		PreparedStatement insert = null;
		try {
			connection = database.getConnection();
			insert = connection.prepareStatement("INSERT INTO MESSAGES (from_user_id, to_user_id, message, salt," +
					" signed_salt, message_metadata, senders_public_pre_key, recipient_public_pre_key, sent_time) VALUES  " +
					"(?, ?, ?, ?, ?, ?, ?, ?, ?)");
			insert.setLong(1, fromUserId);
			insert.setLong(2, toUserId);

			insert.setBytes(3, message.getBytes());
			insert.setBytes(4, salt.getBytes());
			insert.setBytes(5, signedSalt.getBytes());


			insert.setBytes(6, messageMetadata.getBytes());

			insert.setString(7, sendersPublicPreKey);
			insert.setString(8, recipientPublicPreKey);

			insert.setDate(9, new java.sql.Date(System.currentTimeMillis()));

			insert.executeUpdate();
		} catch (SQLException sqlException) {
			throw new MessageException("Failed to send Message", sqlException);
		} finally {
			Utils.closeQuietly(insert);
			Utils.closeQuietly(connection);
		}
	}

	@Override
	public List<MessageHelper> receiveMessage(long userId) throws MessageException {

		Connection connection = null;
		PreparedStatement select = null;
		ResultSet resultSet = null;
		List<MessageHelper> result = new ArrayList<>();
		try {
			connection = database.getConnection();
			// TODO: scroll through
			select = connection.prepareStatement("SELECT * FROM MESSAGES WHERE TO_USER_ID = ?");
			select.setLong(1, userId);
			resultSet = select.executeQuery();
			while (resultSet.next()) {
				String message = resultSet.getString("message");
				String salt = resultSet.getString("salt");
				String signedSalt = resultSet.getString("signed_salt");

				String messageMetaData = resultSet.getString("message_metadata");
				long fromUserId = resultSet.getLong("from_user_id");
				long toUserId = resultSet.getLong("to_user_id");
				String partialKey = resultSet.getString("senders_public_pre_key");
				String originalPublicKey = resultSet.getString("recipient_public_pre_key");

				Date sentTime = resultSet.getTime("sent_time");
				MessageHelper messageHelper = new MessageHelper();
				messageHelper.setFromUserId(fromUserId);
				messageHelper.setMessage(message);
				messageHelper.setSalt(salt);
				messageHelper.setSignedSalt(signedSalt);
				messageHelper.setMessageMetadata(messageMetaData);
				messageHelper.setSentTime(sentTime);
				messageHelper.setToUserId(toUserId);
				messageHelper.setPartialMessageKey(partialKey);
				messageHelper.setOriginalPublicKey(originalPublicKey);
				result.add(messageHelper);
			}
		} catch (SQLException sqlException) {
			throw new MessageException("Failed to send Message", sqlException);
		} finally {
			Utils.closeQuietly(resultSet);
			Utils.closeQuietly(select);
			Utils.closeQuietly(connection);
		}
		return result;
	}
}
