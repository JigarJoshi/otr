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

import com.lithium.flow.util.Main;

import java.util.Scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jigar.otr.service.OTRClient;

/**
 * Created by jigar.joshi on 11/10/16.
 */
public class OTRClientDemoMain {

	private static final Logger log = LoggerFactory.getLogger(OTRClientDemoMain.class);

	public static void main(String[] args) throws Exception {
		apiTest();
	}

	private static void apiTest() throws Exception {
		OTRClient client = OTRClient.get(Main.config());
		// String user = Main.config().getString("user");
		while (true) {
			Scanner scanner = new Scanner(System.in);
			log.info("1. register");
			log.info("2. login");
			log.info("3. sendMessage");
			log.info("4. readMessage");
			log.info("5. list Users");
			log.info("6. logout");
			log.info("7. exit");

			String command = scanner.nextLine();
			String user = "";
			switch (command) {
				case "1":
					log.info("enter user: ");
					user = scanner.nextLine();
					log.info("enter password: ");
					String password = scanner.nextLine();
					client.register(user, password);
					break;
				case "2":
					log.info("enter user: ");
					user = scanner.nextLine();
					log.info("enter password: ");
					password = scanner.nextLine();
					client.login(user, password);
					break;
				case "3":
					log.info("Enter target: ");
					int target = Integer.valueOf(scanner.nextLine());
					log.info("Enter message: ");
					String message = scanner.nextLine();
					client.sendMessage("From " + user + ", message = " + message, target);
					break;
				case "4":
					client.readMessages();
					break;
				case "5":
					client.listUsers();
					break;
				case "6":
					client.logout();
					break;
				case "7":
					System.exit(0);
				default:
					log.error("invalid choice");
			}
		}

	}
}
