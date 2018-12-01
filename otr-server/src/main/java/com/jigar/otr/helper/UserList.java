package com.jigar.otr.helper;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class UserList
{
	public UserList()
	{

	}

	String userList;

	public UserList(String userList) {
		this.userList = userList;
	}

	public String getUserList() {
		return userList;
	}

	public void setUserList(String userList){
		this.userList = userList;
	}


}
