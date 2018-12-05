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

package com.jigar.otr;
/**
 * Created by jigar.joshi on 3/31/16.
 */

import com.lithium.flow.config.Config;
import com.lithium.flow.util.Main;

import java.sql.SQLException;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;

import javax.annotation.Nonnull;
import javax.servlet.DispatcherType;

import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.SessionManager;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.session.HashSessionManager;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;

import com.jigar.otr.endpoint.CryptoEndpoint;
import com.jigar.otr.endpoint.HealthCheckEndpoint;
import com.jigar.otr.endpoint.MessageEndpoint;
import com.jigar.otr.endpoint.UserEndpoint;
import com.jigar.otr.filter.AuthenticationFilter;
import com.jigar.otr.service.CryptoService;
import com.jigar.otr.service.Database;
import com.jigar.otr.service.MessageService;
import com.jigar.otr.service.UserService;
import com.jigar.otr.service.impl.CryptoServiceImpl;
import com.jigar.otr.service.impl.DatabaseServiceImpl;
import com.jigar.otr.service.impl.MessageServiceImpl;
import com.jigar.otr.service.impl.SQLUserService;


public class OTRServerMain {

	public OTRServerMain(Config config) throws Exception {
		Database db = new DatabaseServiceImpl(config);

		MessageService messageService = new MessageServiceImpl(db);
		CryptoService cryptoService = new CryptoServiceImpl(db);
		UserService userService = new SQLUserService(db, config);

		Server server = new Server(config.getInt("webserver.port", 4567));
		HandlerList handlers = new HandlerList();
		handlers.addHandler(buildApiHandler(messageService, config, userService, cryptoService));
		server.setHandler(handlers);
		server.start();
	}

	@Nonnull
	private Handler buildApiHandler(MessageService messageService, Config config, UserService userService, CryptoService cryptoService) {
		ResourceConfig resourceConfig = new ResourceConfig(HealthCheckEndpoint.class,
				MessageEndpoint.class, UserEndpoint.class, CryptoEndpoint.class);
		resourceConfig.register(new AbstractBinder() {
			@Override
			protected void configure() {
				bind(messageService).to(MessageService.class);
				bind(config).to(Config.class);
				bind(userService).to(UserService.class);
				bind(cryptoService).to(CryptoService.class);
				bind(cryptoService).to(CryptoService.class);
			}
		});
		resourceConfig.register(JacksonFeature.class);

		ServletHolder jersey = new ServletHolder(new ServletContainer(resourceConfig));
		SessionHandler sh = new SessionHandler(); // org.eclipse.jetty.server.session.SessionHandler

		ServletContextHandler contextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);

		SessionHandler sessionHandler = buildSessionHandler(config);

		contextHandler.setContextPath("/api");
		contextHandler.addServlet(jersey, "/*");
		sh.setHandler(contextHandler);
		contextHandler.setSessionHandler(sessionHandler);
		contextHandler.addBean(new HashLoginService("JCGRealm"));
		contextHandler.addFilter(AuthenticationFilter.class, "/", EnumSet.of(DispatcherType.INCLUDE, DispatcherType.REQUEST));
		return contextHandler;
	}

	private SessionHandler buildSessionHandler(Config config) {
		SessionHandler sessionHandler = new SessionHandler();
		SessionManager sm = new HashSessionManager();
		((HashSessionManager) sm).setSessionCookie(config.getString("session.cookieName", "otrsess"));
		sm.setMaxInactiveInterval(config.getInt("session.timeOutSec", (int) TimeUnit.MINUTES.toSeconds(30)));
		sessionHandler.setSessionManager(sm);
		return sessionHandler;
	}

	public static void main(String[] args) {
		Main.run();
	}
}
