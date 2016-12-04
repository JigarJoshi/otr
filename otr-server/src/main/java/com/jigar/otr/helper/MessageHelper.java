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


package com.jigar.otr.helper;

import java.util.Date;

/**
 * Created by jigar.joshi on 11/20/16.
 */
public class MessageHelper {

	private String message;
	private String salt;
	private String signedSalt;
	private String iv;

	private String messageMetadata;
	private String partialMessageKey;
	private String originalPublicKey;

	private long fromUserId;
	private long toUserId;
	private Date sentTime;

	public String getOriginalPublicKey() {
		return originalPublicKey;
	}

	public void setOriginalPublicKey(String originalPublicKey) {
		this.originalPublicKey = originalPublicKey;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public String getMessageMetadata() {
		return messageMetadata;
	}

	public void setMessageMetadata(String messageMetadata) {
		this.messageMetadata = messageMetadata;
	}

	public long getFromUserId() {
		return fromUserId;
	}

	public void setFromUserId(long fromUserId) {
		this.fromUserId = fromUserId;
	}

	public long getToUserId() {
		return toUserId;
	}

	public void setToUserId(long toUserId) {
		this.toUserId = toUserId;
	}

	public Date getSentTime() {
		return sentTime;
	}

	public void setSentTime(Date sentTime) {
		this.sentTime = sentTime;
	}

	public String getPartialMessageKey() {
		return partialMessageKey;
	}

	public void setPartialMessageKey(String partialMessageKey) {
		this.partialMessageKey = partialMessageKey;
	}

	public String getSalt() {
		return salt;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}

	public String getSignedSalt() {
		return signedSalt;
	}

	public void setSignedSalt(String signedSalt) {
		this.signedSalt = signedSalt;
	}

	public String getIv() {
		return iv;
	}

	public void setIv(String iv) {
		this.iv = iv;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		MessageHelper that = (MessageHelper) o;

		if (fromUserId != that.fromUserId) return false;
		if (toUserId != that.toUserId) return false;
		if (message != null ? !message.equals(that.message) : that.message != null) return false;
		if (salt != null ? !salt.equals(that.salt) : that.salt != null) return false;
		if (signedSalt != null ? !signedSalt.equals(that.signedSalt) : that.signedSalt != null) return false;
		if (iv != null ? !iv.equals(that.iv) : that.iv != null) return false;
		if (messageMetadata != null ? !messageMetadata.equals(that.messageMetadata) : that.messageMetadata != null)
			return false;
		if (partialMessageKey != null ? !partialMessageKey.equals(that.partialMessageKey) : that.partialMessageKey != null)
			return false;
		if (originalPublicKey != null ? !originalPublicKey.equals(that.originalPublicKey) : that.originalPublicKey != null)
			return false;
		return sentTime != null ? sentTime.equals(that.sentTime) : that.sentTime == null;

	}

	@Override
	public int hashCode() {
		int result = message != null ? message.hashCode() : 0;
		result = 31 * result + (salt != null ? salt.hashCode() : 0);
		result = 31 * result + (signedSalt != null ? signedSalt.hashCode() : 0);
		result = 31 * result + (iv != null ? iv.hashCode() : 0);
		result = 31 * result + (messageMetadata != null ? messageMetadata.hashCode() : 0);
		result = 31 * result + (partialMessageKey != null ? partialMessageKey.hashCode() : 0);
		result = 31 * result + (originalPublicKey != null ? originalPublicKey.hashCode() : 0);
		result = 31 * result + (int) (fromUserId ^ (fromUserId >>> 32));
		result = 31 * result + (int) (toUserId ^ (toUserId >>> 32));
		result = 31 * result + (sentTime != null ? sentTime.hashCode() : 0);
		return result;
	}
}
