# OTR [ off the record ]

Provides framework / prototype for end-to-end encryption with perfect forward secrecy in Java

Protocol combines symmetric and asymmetric encryption algorithms [RSA, Elliptic Curve Diffie–Hellman, AES] to implement end-to-end encryption. It works on top of https protocol providing encryption in transport and storage

## Getting Started
Dependencies are managed using [Maven](https://maven.apache.org/guides/getting-started/maven-in-five-minutes.html). 

The framework uses Bouncy Castle as provider for encryption. The dependency has to be excluded from the *fat* jar because of signature verification problems.

From the following source, [](http://tomee.apache.org/bouncy-castle.html) bouncy castle is easily installed in two steps:
1. Add the Bouncy Castle provider jar to the $JAVA_HOME/jre/lib/ext directory
2. Create a Bouncy Castle provider entry in the $JAVA_HOME/jre/lib/security/java.security file

The entry to java.security will look something like the following:

> security.provider.N=org.bouncycastle.jce.provider.BouncyCastleProvider

The framework is configured to work with a mysql database. It uses the mysql-connector-v8 which may or may not be compatible with older versions on MySQL. The following line in `DataBaseServiceImpl.java` can be changed for other database usage.
> dataSource.setUrl("jdbc:mysql://" + config.getString("sql.host") + "/" + config.getString("sql.database"));

There is a schema.sql file located in the SQL directory of the otr-server. A database should be created and initialized to use this schema.

[Lithium Flow](https://github.com/lithiumtech/flow) is used for managing configuration files. The config file must be specified at runtime with a system property, and the library is included in the pom.xml.

### Configuration
There are three total configuration files, a common, server, and client. The server and client contain some required configurations for starting the application.

#### Server
The following items need to be configured before the server will work:
1. `sql.host` - include the hostname, default port used is 4567
2. `sql.user` - username of sql database
3. `sql.password` - password of sql database
4. `sql.database` - database name used when creating the sql schema mentioned above

#### Client
The following items to need to be configured before the client will work:
1. `server.url` - default port number is 4567
2. `user.keystore` - storage location for key information generated for a user

The ECDH curve can also be changed in this configuration file.

### Running
After ensuring that all of the dependencies and configurations have been taken care of, build the application with `mvn package` from the top-level directory.

Change into the server's directory and run the server with:
> java -Dconfig=server.config -cp target/*-fat.jar com.jigar.otr.OTRServerMain

Start another shell and change into the client's directory, run the client with:
> java -Dconfig=client.config -cp target/*-fat.jar com.jigar.otr.OTRClientDemoMain

Sample exchange on the same client.

User1
1. Register user1
2. Login as user1
3. Logout of the user (writes login information to disk)

User2
1. Register user2
2. Login as user2
3. Logout of the user (writes login information to disk)

- Login as user1, and list users.
- Send a message to user2 using the id identified by the list user's call, logout.
- Login to user2, receive the message.



## API
### Keys

A set of keys are generated on the client-side before interaction with the server.

##### Identity Key
During registration, client generates a 4096 bit RSA key pair, and sends the public key to server. The private key remains at client.

##### Pre-Keys
During registration, client generates large bulk of ECDH key pairs (configurable), and the public portion of these keys is sent to server. All private keys remains at client to be used as keys for encrypting communication.

### Encryption
Current implementation uses 256 bit AES Encryption.

### Protocol

#### Registration

 - User provides `login`, `password`, `public identity key`, `set of public pre-keys` ->  server returns user identification number back upon successful registration, client stores this information

#### Login

 - User provides `login`, `password` and `signedLogin` (signed login with private identity key) -> server provides `userId` (user identification number) on a successful login.

#### Logout [TODO Encrypt Stored Information]

 - User writes all key related information to the file "<username>-otr.json" in the directory defined by the "user.keystore" configuration variable. The user's information is then cleared from memory. The information is stored as plaintext.
 
#### List Users

 - User request a list of users from the server.
 
 - Server returns a list of user's with including both their userId and userName.
 
#### Send Message

 - Bob wants to send message to Alice -- Both users need to be registered in system already
 
 - Bob will request Alice's public identity key & one of her public pre-keys being stored on the server

 - Server returns public identity key and one of the Alice's public pre-keys of to Bob

 - Server will remove supplied public pre-key; if this is Alice's last public pre-key on server, the server will keep it until Alice comes back and replenishes them

 - Bob generates ECDH key pair and using Alice's ECDH public pre-key derives secret

 - Bob generates random salt and IV

 - Bob uses computed secret, salt and IV as input to AES (256 bit) to encrypt his message for Alice

 - Bob uses Alice's public identity key to encrypt Bob's ECDH public pre-key, salt, IV, and Alice's public ECDH pre-key

 - Bob signs salt with his private key

 - Bob sends server Alice's userId, encrypted message, encrypted salt, signed salt, encrypted IV, Alice's public ECDH pre-key encrypted, Bob's public ECDH pre-key encrypted and signed salt

 - Server stores all of this information

#### Receive Message

 - Alice makes a request for her messages to server by providing her userId, server validates if Alice is logged in

 - Server provides encrypted data which was submitted by Bob

 - Alice uses her private key to decrypt Alice's ECDH public pre-key, Bob's ECDH public key, salt and IV

 - Alice verifies the signed salt with Bob's public key

 - Alice checks Bob's identity fingerprint to make sure Bob is really the who Alice thinks by making sure his identity by going out of band

 - Alice then uses her ECDH private key and Bob's ECDH public key to compute secret. 

 - AES is used to decrypt message

#### Replenishing Pre-Keys

A user that has registered with the server has a public pre-key removed each time a user sends them a message. Because of this, the pre-keys must be replenished on the server's side.

 - Client maintains N number of pre-keys on server and periodically replenishes them


### Data storage [TODO]

 - Stores backup of Bob and Alice's chat

 - Alice and Bob both are asked if you want to store messages, if both agree to continue the client proceeds with backup

 - To backup, Alice's client generates a secure random key and encrypts with both Bob's public key & Alice's public key; it is then sent to server [2 keys]

 - Bob's client does the same

 - Once the server receives both the encrypted keys, it generates a random salt and keeps this on record, providing the random salt to Bob and Alice on their next ping to server in encrypted form via their public identity keys

 - Bob and Alice get the secret key for their chat storage through the server and decrypt it with their private keys, combining them to derive a secret key that only Alice and Bob know. They then send data back to server

 - These keys must remain present to client at all times protected by a master password which remains in the mind of user for backup and retrieval purpose


### License
Copyright 2016 Jigar Joshi

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
