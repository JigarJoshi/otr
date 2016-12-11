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

package com.jigar.otr.crypto;

import com.lithium.flow.config.Config;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Enumeration;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

/**
 * Created by jigar.joshi on 11/20/16.
 */
public class ECDH {
	private final String curveName;
	private static final String ALGORITHM = "ECDH";
	private static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

	public ECDH(Config config) {
		this.curveName = config.getString("ecdh.curveName", "prime192v1");
	}


	private String doECDH(byte[] dataPrv, byte[] dataPub) throws Exception {
		KeyAgreement ka = KeyAgreement.getInstance(ALGORITHM, PROVIDER_NAME);
		ka.init(encodeToPrivateKey(dataPrv));
		ka.doPhase(encodeToPublicKey(dataPub), true);
		byte[] secret = ka.generateSecret();
		return Utils.bytesToHex(secret);
	}

	public KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER_NAME);
		kpGen.initialize(new ECGenParameterSpec(curveName), new SecureRandom());
		return kpGen.generateKeyPair();
	}

	public String generateSecret(String privateKey, String othersPublicKey) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator kpgen = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER_NAME);
		kpgen.initialize(new ECGenParameterSpec(curveName), new SecureRandom());
		byte[] dataPrivate = Base64.getDecoder().decode(privateKey);
		byte[] dataPub = Base64.getDecoder().decode(othersPublicKey);
		return doECDH(dataPrivate, dataPub);
	}

	private static byte[] decode(PublicKey key) {
		ECPublicKey ecPublicKey = (ECPublicKey) key;
		return ecPublicKey.getQ().getEncoded(true);
	}

	private static byte[] decode(PrivateKey key) {
		ECPrivateKey ecPublicKey = (ECPrivateKey) key;
		return ecPublicKey.getD().toByteArray();
	}

	public static String publicKeyToString(PublicKey publicKey) {
		return Base64.getEncoder().encodeToString(decode(publicKey));
	}

	public static String privateKeyToString(PrivateKey privateKey) {
		return Base64.getEncoder().encodeToString(decode(privateKey));
	}

	public PublicKey stringToPublicKey(String publicKey) throws Exception {
		return encodeToPublicKey(Base64.getDecoder().decode(publicKey));
	}

	public PrivateKey stringToPrivateKey(String privateKey) throws Exception {
		return encodeToPrivateKey(Base64.getDecoder().decode(privateKey));
	}

	private PublicKey encodeToPublicKey(byte[] data) throws Exception {
		ECParameterSpec params = ECNamedCurveTable.getParameterSpec(curveName);
		ECPublicKeySpec pubKey = new ECPublicKeySpec(
				params.getCurve().decodePoint(data), params);
		KeyFactory kf = KeyFactory.getInstance(ALGORITHM, PROVIDER_NAME);
		return kf.generatePublic(pubKey);
	}

	private PrivateKey encodeToPrivateKey(byte[] data) throws Exception {
		ECParameterSpec params = ECNamedCurveTable.getParameterSpec(curveName);
		ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(data), params);
		KeyFactory kf = KeyFactory.getInstance(ALGORITHM, PROVIDER_NAME);
		return kf.generatePrivate(privateKeySpec);
	}
}
