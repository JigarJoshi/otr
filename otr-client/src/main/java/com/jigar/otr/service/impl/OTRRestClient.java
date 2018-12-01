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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import com.lithium.flow.config.Config;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Type;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpURLConnection;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.goebl.david.Response;
import com.goebl.david.Webb;
import com.google.gson.JsonObject;
import com.jigar.otr.crypto.AES;
import com.jigar.otr.crypto.ECDH;
import com.jigar.otr.crypto.RSA;
import com.jigar.otr.crypto.Utils;
import com.jigar.otr.exception.OTRException;
import com.jigar.otr.service.KeyService;
import com.jigar.otr.service.OTRClient;
import com.jigar.otr.service.Storer;
import com.jigar.otr.service.StorerWrapper;

import javax.naming.Name;

/**
 * Created by jigar.joshi on 11/21/16.
 */
public class OTRRestClient implements OTRClient {

	private final Config config;
	private final Webb webb;
	private final KeyService keyService;
	private final Storer storer;
	private final StorerWrapper storerWrapper;
	private final ECDH ecdh;
	private final RSA rsa;
	private static OTRClient INSTANCE;
	private final static Logger log = LoggerFactory.getLogger(OTRRestClient.class);


	private OTRRestClient(Config config) {
		String serverUrl = config.getString("server.url");
		this.config = config;
		this.webb = Webb.create();
		CookieManager cookieManager = new CookieManager();
		CookieHandler.setDefault(cookieManager);

		this.webb.setBaseUri(serverUrl);
		// webb.setDefaultHeader(Webb.HDR_CONTENT_TYPE, "application/json");
		this.ecdh = new ECDH(config);
		this.rsa = new RSA(config);
		this.keyService = KeyService.get(config);
		this.storer = Storer.get(config);
		this.storerWrapper = StorerWrapper.get(config);
		log.info("initialized with baseuri = {}", serverUrl);
	}

	public static OTRClient getInstance(Config config) {
		if (INSTANCE == null) {
			INSTANCE = new OTRRestClient(config);
		}
		return INSTANCE;
	}

	@Override
	public void register(String login, String password) throws OTRException {
		//	generate and process pre-keys
		List<String> prePublicKeys = new ArrayList<>();
		List<KeyPair> preKeyPairs = keyService.generateMessageKeys(config.getInt("keys.pre.count", 1000));
		for (KeyPair preKeyPair : preKeyPairs) {
			String publicKeyString = ECDH.publicKeyToString(preKeyPair.getPublic());
			String privateKeyString = ECDH.privateKeyToString(preKeyPair.getPrivate());
			JsonObject pre = new JsonObject();
			pre.addProperty("private", privateKeyString);
			prePublicKeys.add(publicKeyString);
			storer.put(Storer.NameSpace.PRE_KEYS, publicKeyString, pre);
		}

		// generate identity-key
		KeyPair identityKey = keyService.generateClientIdentityKeyPair();
		String publicKeyString = rsa.getKeyAsString(identityKey.getPublic());
		String privateKeyString = rsa.getKeyAsString(identityKey.getPrivate());

		JsonObject idKeyJSON = new JsonObject();
		idKeyJSON.addProperty("private", privateKeyString);
		idKeyJSON.addProperty("public", publicKeyString);
		storer.put(Storer.NameSpace.ID_KEYS, Storer.ID_KEY, idKeyJSON);

		// make http call
		Response<JSONObject> response = webb.post("/api/user/register")
				.param("login", login)
				.param("password", password)
				.param("identityPublicKey", publicKeyString)
				.param("prePublicKeys", prePublicKeys).asJsonObject();


		if (response.getStatusCode() != HttpURLConnection.HTTP_CREATED) {
			storer.remove(Storer.NameSpace.ID_KEYS);
			storer.remove(Storer.NameSpace.PRE_KEYS);
			throw new OTRException("Failed to process registration on server, server responded with status code: "
					+ response.getStatusCode());
		}
		storeUser(response, login);
	}

	@Override
	public void login(String login, String password) throws OTRException {
		String signedLogin;
		if(!loadUser(login))
		{
			// No users present on the current instance.
			// You need a keypair to even login.
			return;
		}
		try {
			PrivateKey privateKey = rsa.getPrivateKeyFromString(storerWrapper.getPrivateIdKey());
			signedLogin = rsa.sign(login, privateKey);
		} catch (Exception ex) {
			throw new OTRException("Failed to sign during logging", ex);
		}

		Response<JSONObject> response = webb.post("/api/user/login")
				.param("login", login)
				.param("password", password)
				.param("signedLogin", signedLogin).asJsonObject();

		int statusCode = response.getStatusCode();
		if (statusCode == HttpURLConnection.HTTP_OK) {
			log.info("logged in");
			storeUser(response, login);
		} else {
			throw new OTRException("Failed to login, status code received : " + statusCode);
		}
	}

	@Override
	public void logout() throws OTRException
	{
		System.out.println("Loging out!");
		String username  = storerWrapper.getUsername();

		try
		{
			String keystore = config.getString("user.keystore", "./");
			File dirs = new File(keystore);
			if(!dirs.exists()){
				dirs.mkdirs();
			}

			FileWriter fw = new FileWriter(keystore + username + "-otr.json");
			fw.write(storer.toString());
			fw.flush();
			fw.close();

			String json = new String(Files.readAllBytes(Paths.get(keystore + username + "-otr.json")));
			Type mapType = new TypeToken<Map<Storer.NameSpace, Map<String, JsonObject>>>(){}.getType();

			Map<Storer.NameSpace, Map<String, JsonObject>> map = new GsonBuilder().disableHtmlEscaping().create()
					.fromJson(json, mapType);

			System.out.println(map.toString());
		} catch (IOException e)
		{
			e.printStackTrace();
		}
	}

	private boolean loadUser(String username)
	{
		try
		{
			String keystore = config.getString("user.keystore", "./");
			File dirs = new File(keystore);
			if(!dirs.exists()){
				dirs.mkdirs();
			}
			String json = new String(Files.readAllBytes(Paths.get(keystore + username + "-otr.json")));
			Type mapType = new TypeToken<Map<Storer.NameSpace, Map<String, JsonObject>>>(){}.getType();
			Map<Storer.NameSpace, Map<String, JsonObject>> map = new GsonBuilder().disableHtmlEscaping().create()
					.fromJson(json, mapType);
			if(storerWrapper instanceof InMemoryStorerWrapper)
			{
				((InMemoryStorerWrapper) storerWrapper).loadUser(map);
				return true;
			}
		} catch (IOException e)
		{
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public void refreshMessageKeys() throws OTRException {
		Response<JSONObject> countResponse = webb.post("/api/crypto/pre-public-key/count")
				.param("userId", 1).asJsonObject();
		int existingCount = 0;
		if (countResponse.getStatusCode() == HttpURLConnection.HTTP_OK) {
			try {
				existingCount = countResponse.getBody().getInt("count");
			} catch (JSONException ex) {
				log.warn("Failed to parse response", ex);
			}
		}

		int additional = config.getInt("keys.pre.count", 1000) - existingCount;
		List<KeyPair> preKeyPairs = keyService.generateMessageKeys(additional);

		List<String> prePublicKeys = new ArrayList<>();
		for (KeyPair preKeyPair : preKeyPairs) {
			String publicKeyString = ECDH.publicKeyToString(preKeyPair.getPublic());
			String privateKeyString = ECDH.privateKeyToString(preKeyPair.getPrivate());
			JsonObject pre = new JsonObject();
			pre.addProperty("private", privateKeyString);
			prePublicKeys.add(publicKeyString);
			storer.put(Storer.NameSpace.PRE_KEYS, publicKeyString, pre);
		}
		Response<JSONObject> refreshResponse = webb.post("/api/crypto/pre-public-key/refresh")
				.param("userId", storerWrapper.getUserId())
				.param("prePublicKeys", prePublicKeys).asJsonObject();

		if (refreshResponse.getStatusCode() != HttpURLConnection.HTTP_CREATED) {
			for (KeyPair preKeyPair : preKeyPairs) {
				String pub = ECDH.publicKeyToString(preKeyPair.getPublic());
				storer.remove(Storer.NameSpace.PRE_KEYS, pub);
			}
		}
	}

	@Override
	public void readMessages() {
		int userId = storerWrapper.getUserId();
		JSONArray messages = webb.post("/api/message/receive")
				.param("userId", userId)
				.asJsonArray().getBody();
		for (int i = 0; i < messages.length(); i++) {
			String encryptedMessage;
			try {
				PrivateKey privateKey = rsa.getPrivateKeyFromString(storerWrapper.getPrivateIdKey());
				String othersPublicKeyString = rsa.decrypt(messages.getJSONObject(i).getString("partialMessageKey"), privateKey);
				String originalPublicKey = rsa.decrypt(messages.getJSONObject(i).getString("originalPublicKey"), privateKey);
				String plainSalt = rsa.decrypt(messages.getJSONObject(i).getString("salt"), privateKey);
				String signedSalt = messages.getJSONObject(i).getString("signedSalt");
				String ivStr = rsa.decrypt(messages.getJSONObject(i).getString("iv"), privateKey);

				int sendersUserId = Integer.parseInt(messages.getJSONObject(i).getString("fromUserId"));
				String sendersPublicId = getPublicIdKey(sendersUserId);
				PublicKey sendersPublicIdKey = RSA.getPublicKeyFromString(sendersPublicId);
				// verify signature
				if (!rsa.verifySignature(signedSalt, plainSalt, sendersPublicIdKey)) {
					log.warn("message from user {} is possible attack", sendersUserId);
					throw new OTRException("Signature mismatch - possible attack");
				}

				log.info("sender's identity fingerprint {}", rsa.prettyFingerPrint(sendersPublicIdKey));

				// complete DH using public key of other party and derive secret
				String derivedSecret = ecdh.generateSecret(storerWrapper.getPrivatePreKey(originalPublicKey), othersPublicKeyString);
				encryptedMessage = messages.getJSONObject(i).getString("message");
				// decrypt message
				byte[] iv = Base64.getDecoder().decode(ivStr);
				String plainTextMessage = new AES(derivedSecret, plainSalt, iv, config).decrypt(encryptedMessage);
				log.info("received message is {}", plainTextMessage);
			} catch (Exception ex) {
				log.warn("Failed to read message", ex);
			}
		}
	}

	@Override
	public void sendMessage(String message, int toUserId) throws OTRException {
		try {
			// get client-public-key
			String reciepientsPublicIdKey = getPublicIdKey(toUserId);

			log.info("received target users's RSA public key {}", reciepientsPublicIdKey);
			// get pre-public-key
			String recipientPublicPreKey = getPrePublicKey(toUserId);
			log.info("received target users's one-time pre-public key {}", recipientPublicPreKey);

			// generate key pair
			KeyPair myKeys = ecdh.generateKeyPair();
			String sendersPublicPreKey = ECDH.publicKeyToString(myKeys.getPublic());
			String sendersPrivatePreKey = ECDH.privateKeyToString(myKeys.getPrivate());

			// generate shared secret
			String secret = ecdh.generateSecret(sendersPrivatePreKey, recipientPublicPreKey);

			String salt = Utils.generateRandomSalt();
			byte[] iv = Utils.generateRandomIV();
			PrivateKey sendersPrivateIdKey = rsa.getPrivateKeyFromString(storerWrapper.getPrivateIdKey());
			String signedSalt = rsa.sign(salt, sendersPrivateIdKey);

			// encrypt message
			String encryptedMessage = new AES(secret, salt, iv, config).encrypt(message);

			// encrypt DH public key using other party's public key
			String encryptedSendersPublicPreKey = rsa.encrypt(sendersPublicPreKey, RSA.getPublicKeyFromString(reciepientsPublicIdKey));
			String encryptedRecipientPublicPreKey = rsa.encrypt(recipientPublicPreKey, RSA.getPublicKeyFromString(reciepientsPublicIdKey));
			String encryptedIV = rsa.encrypt(Base64.getEncoder().encodeToString(iv), RSA.getPublicKeyFromString(reciepientsPublicIdKey));

			String encryptedSalt = rsa.encrypt(salt, RSA.getPublicKeyFromString(reciepientsPublicIdKey));
			// send it to server
			log.info("sent status = {}", webb.post("/api/message/send")
					.param("fromUserId", storerWrapper.getUserId())
					.param("toUserId", toUserId)
					.param("message", encryptedMessage)
					.param("salt", encryptedSalt)
					.param("signedSalt", signedSalt)
					.param("iv", encryptedIV)
					.param("messageMetadata", "{\"type\":\"text\"}")
					.param("recipientPublicPreKey", encryptedRecipientPublicPreKey)
					.param("sendersPublicPreKey", encryptedSendersPublicPreKey).asString().getStatusCode());
		} catch (Exception ex) {
			throw new OTRException("Failed to send message: " + ex.getMessage(), ex);
		}
	}

	@Override
	public String getPublicIdKey(int userId) throws OTRException {
		try {
			return webb.post("/api/crypto/public-key")
					.param("userId", userId).asJsonObject().getBody().getString("publicKey");
		} catch (JSONException ex) {
			throw new OTRException("Failed to get public-id key: " + ex.getMessage(), ex);
		}
	}

	@Override
	public String getPrePublicKey(int userId) throws OTRException {
		try {
			return webb.post("/api/crypto/pre-public-key")
					.param("userId", userId).asJsonObject().getBody().getString("prePublicKey");
		} catch (JSONException ex) {
			throw new OTRException("Failed to get public-id key: " + ex.getMessage(), ex);
		}
	}

	@Override
	public String listUsers() throws OTRException
	{
		Response<JSONObject> response = webb.get("/api/user/list").asJsonObject();
		int statusCode = response.getStatusCode();
		String userList = "";
		if (statusCode == HttpURLConnection.HTTP_OK) {
			try
			{
				userList = response.getBody().getString("userList");
				log.info("Users list grabbed {}", "\n" + userList);
			} catch (JSONException e)
			{
				e.printStackTrace();
			}
		} else {
			throw new OTRException("Failed to list users, status code received : " + statusCode);
		}
		return userList;
	}

	private void storeUser(Response<JSONObject> response, String loginName) throws OTRException {
		JsonObject user = new JsonObject();
		try {
			String userId = response.getBody().getString("userId");
			log.info("registered userId = {}", userId);
			user.addProperty("userId", userId);
			user.addProperty("userName", loginName);
		} catch (JSONException jsonException) {
			throw new OTRException("Failed to read registered userId: " + jsonException.getMessage(), jsonException);
		}
		storer.put(Storer.NameSpace.USER, Storer.USER_KEY, user);
	}

}
