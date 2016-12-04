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

package com.jigar.otr.endpoint;

import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;
import static javax.ws.rs.core.Response.Status.OK;

import java.util.List;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jigar.otr.exception.MessageException;
import com.jigar.otr.helper.MessageHelper;
import com.jigar.otr.service.MessageService;

/**
 * Created by jigar.joshi on 11/7/16.
 */

@Path("/message")
public class MessageEndpoint {

	@Inject
	private MessageService messageService;

	private final Logger log = LoggerFactory.getLogger(MessageEndpoint.class);

	@POST
	@Path("/send")
	public Response sendMessage(@FormParam("fromUserId") @Nullable Long fromUserId,
			@FormParam("toUserId") @Nullable Long toUserId,
			@FormParam("message") @Nullable String message,
			@FormParam("salt") @Nullable String salt,
			@FormParam("signedSalt") @Nullable String signedSalt,
			@FormParam("messageMetadata") @Nullable String messageMetadata,
			@FormParam("sendersPublicPreKey") @Nullable String sendersPublicPreKey,
			@FormParam("recipientPublicPreKey") @Nullable String recipientPublicPreKEy) {
		try {
			messageService.sendMessage(fromUserId, toUserId, message, salt, signedSalt, messageMetadata, sendersPublicPreKey, recipientPublicPreKEy);
			return Response.status(OK).entity("Message sent successfully").type(MediaType.APPLICATION_JSON_TYPE).build();
		} catch (MessageException messageException) {
			log.error("Failed to send message : " + messageException.getMessage(), messageException);
			return Response.status(INTERNAL_SERVER_ERROR).entity(messageException.getMessage())
					.type(MediaType.APPLICATION_JSON_TYPE).build();
		}
	}

	@POST
	@Path("/receive")
	public Response receiveMessage(@FormParam("userId") @Nullable Long userId) {
		try {
			List<MessageHelper> messages = messageService.receiveMessage(userId);
			return Response.status(OK).entity("Message sent successfully").entity(messages).
					type(MediaType.APPLICATION_JSON_TYPE).build();
		} catch (MessageException messageException) {
			log.error("Failed to read message : " + messageException.getMessage(), messageException);

			return Response.status(INTERNAL_SERVER_ERROR).entity(messageException.getMessage())
					.type(MediaType.APPLICATION_JSON_TYPE).build();
		}
	}
}