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

import java.sql.Connection;
import java.sql.SQLException;

import org.apache.commons.dbcp.BasicDataSource;

import com.jigar.otr.service.Database;

/**
 * Created by jigar.joshi on 11/9/16.
 */
public class DatabaseServiceImpl implements Database {

	private final BasicDataSource dataSource;

	public DatabaseServiceImpl(Config config) {
		this.dataSource = new BasicDataSource();
		dataSource.setUrl("jdbc:mysql://" + config.getString("sql.host") + "/" + config.getString("sql.database"));
		dataSource.setUsername(config.getString("sql.user"));
		dataSource.setPassword(config.getString("sql.password"));
		dataSource.setMaxActive(config.getInt("sql.max_connection", 100));
		dataSource.setMaxIdle(5);
		dataSource.setInitialSize(5);
		dataSource.setValidationQuery("SELECT 1");
	}

	@Override
	public Connection getConnection() throws SQLException {
		return this.dataSource.getConnection();
	}
}
