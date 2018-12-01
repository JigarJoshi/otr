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

import com.jigar.otr.helper.UserList;
import com.lithium.flow.util.Logs;

import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.GenericEntity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;

import com.jigar.otr.helper.Ack;
import com.jigar.otr.helper.UserRegistrationHelper;
import com.jigar.otr.service.UserService;
import com.jigar.otr.util.Utils;

/**
 * Created by jigar.joshi on 11/10/16.
 */
@Path("/user")
public class UserEndpoint {

	private final static Logger log = Logs.getLogger();
	@Inject private UserService userService;

	@POST
	@Path("/register")
	//@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response register(@FormParam("login") @Nullable String login, @FormParam("password") @Nullable String password,
			@FormParam("identityPublicKey") @Nullable String identityPublicKey,
			@FormParam("prePublicKeys") @Nullable List<String> prePublicKeys) {
		log.info("login = {}, identityPublicKey = {}, sizeOfPreKeys = {}", login, identityPublicKey, prePublicKeys.size());
		try {
			int userId = userService.registerUser(login, password, identityPublicKey, prePublicKeys);
			return Response.status(201)
					.entity(new UserRegistrationHelper(userId)).build();
		} catch (Exception ex) {
			System.out.println("Exception: " + ex.getMessage());
			return Response.status(503).entity(new Ack("failed to register user: " + ex.getMessage(),
					Utils.FAIL_CODE)).build();
		}
	}

	@POST
	@Path("/login")
	public Response login(@FormParam("login") @Nullable String login, @FormParam("password") @Nullable String password,
			@FormParam("signedLogin") @Nullable String signedLogin) {
		try {
			int userId = userService.login(login, password, signedLogin);
			return Response.status(200).type(MediaType.APPLICATION_JSON_TYPE)
					.entity(new UserRegistrationHelper(userId)).build();
		} catch (Exception ex) {
			log.error("Failed to login", ex);
			return Response.status(403).build();
		}
	}

	@GET
	@Path("/list")
	public Response list() {
		try {
			// list userService
			String userList = userService.listUsers();
			return Response.status(200)
					.entity(new UserList(userList)).build();
		} catch (Exception ex) {
			System.out.println("Exception: " + ex.getMessage());
			return Response.status(503).entity(new Ack("failed to register user: " + ex.getMessage(),
			                                           Utils.FAIL_CODE)).build();
		}
	}

}
