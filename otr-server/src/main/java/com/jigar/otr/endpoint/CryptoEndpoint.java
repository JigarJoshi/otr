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

import static javax.ws.rs.core.Response.Status.CREATED;
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

import com.jigar.otr.exception.CryptoException;
import com.jigar.otr.helper.Ack;
import com.jigar.otr.helper.ErrorMessage;
import com.jigar.otr.helper.MessagePreKeysCountResponse;
import com.jigar.otr.helper.PreKeyResponse;
import com.jigar.otr.helper.PublicKeyResponse;
import com.jigar.otr.service.CryptoService;
import com.jigar.otr.util.Utils;

/**
 *
 * Created by jigar.joshi on 11/9/16.
 */
@Path("/crypto")
public class CryptoEndpoint {

	@Inject private CryptoService cryptoService;

	@POST
	@Path("/pre-public-key")
	public Response getPrePublicKey(@FormParam("userId") @Nullable Integer userId) {
		try {
			return Response.status(OK).type(MediaType.APPLICATION_JSON_TYPE).entity(new PreKeyResponse(cryptoService.getPrePublicKey(userId))).build();
		} catch (CryptoException cryptoException) {
			return Response.status(INTERNAL_SERVER_ERROR).entity(new ErrorMessage(cryptoException.getMessage())).build();
		}
	}

	@POST
	@Path("/pre-public-key/count")
	public Response getPrePublicKeyCount(@FormParam("userId") @Nullable Integer userId) {
		try {
			return Response.status(OK).type(MediaType.APPLICATION_JSON_TYPE).entity(new MessagePreKeysCountResponse(cryptoService.getPrePublicKeyCount(userId))).build();
		} catch (CryptoException cryptoException) {
			return Response.status(INTERNAL_SERVER_ERROR).entity(new ErrorMessage(cryptoException.getMessage())).build();
		}
	}

	@POST
	@Path("/pre-public-key/refresh")
	public Response refreshPrePublicKey(@FormParam("userId") @Nullable Integer userId, @FormParam("prePublicKeys") List<String> prePublicKeys) {
		try {
			cryptoService.addPreKeys(userId, prePublicKeys);
			return Response.status(CREATED).type(MediaType.APPLICATION_JSON_TYPE)
					.entity(new Ack("added successfully", Utils.SUCCESSFUL_CODE)).build();
		} catch (CryptoException cryptoException) {
			return Response.status(INTERNAL_SERVER_ERROR).entity(new ErrorMessage(cryptoException.getMessage())).build();
		}
	}

	@POST
	@Path("/public-key")
	public Response getPublicKey(@FormParam("userId") @Nullable Integer userId) {
		try {
			return Response.status(OK).type(MediaType.APPLICATION_JSON_TYPE).entity(new PublicKeyResponse(cryptoService.getPublicKey(userId))).build();
		} catch (CryptoException cryptoException) {
			return Response.status(INTERNAL_SERVER_ERROR).entity(new ErrorMessage(cryptoException.getMessage())).build();
		}
	}
}
