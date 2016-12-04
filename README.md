# OTR [ off the record ]

Provides framework / prototype for end-to-end encryption and perfect forward secrecy in Java

Protocol combines symmetric and asymmetric encryption algorithms [RSA, Elliptic curve Diffie–Hellman, AES] to implement end-to-end encryption, It works on top of https

protocol provides encryption in transport and storage

### Keys

##### Identity Key
During registration, client generates RSA 4096 bit key pair, public key gets sent to server during registration, private key remains at client

##### Pre-Keys
During registration client generates large bulk of ECDH key pairs, and public portion of these keys gets sent to server during registration, all private keys remains at client

### Encryption
It uses 256 bit AES encryption

### Protocol

##### registration

 - User provides `login`, `password`, `public identity key`, `set of public pre-keys`, user gets user identification number back upon successful registration, which is stored

##### login

 - User provides `login`, `password` and `signedLogin` (signed login with private identity key), upon login server provides `userId` (user identification number) which client stores it

##### send message

 - Bob wants to send message to Alice, Both user needs to have registered in system already, Bob will request Alice's public identity key & Alice's one of the public pre-key from server server

 - Server will give public identity key and one of the public pre-key of Alice to Bob

 - Server will remove supplied public pre-key, if there is only one last public pre-key left on server, server will keep it until client comes back and replenishes them

 - Bob generates ECDH key pair and using Alice's ECDH public pre-key derives secret

 - Bob generates random salt and IV

 - Bob uses computed secret, salt and IV as input to AES (256 bit) to encrypt his message for Alice

 - Bob uses Alice's public identity key to encrypt Bob's ECDH public pre-key, salt and Alice's public ECDH pre-key

 - Bob signs salt with his private key

 - Bob sends server Alice's userId, encrypted message, encrypted salt, signed salt, encrypted IV, encrypted Alice's public ECDH pre-key, encrypted Bob's public ECDH pre-key and signed salt

 - server simply stores all these information

##### receive message

 - Alice requests for her message to server by providing her userId, server validates if Alice is logged in

 - Server provides encrypted data which was submitted by Bob

 - Alice uses her private key to decrypt Alice's ECDH public pre-key, Bob's ECDH public key, salt and IV

 - Alice verifies signedSalt with Bob's public key

 - Alice checks Bob's identity finger print and makes sure, Bob is really the one who Alice thinks by making sure his identity by going out of band

 - Alice then uses her ECDH private key, Bob's ECDH public key to compute secret and uses AES to decrypt message

##### replenishing pre-keys

 - Client maintains N number of pre-keys on server and periodically replenishes them


### Data storage [TODO]

 - To store backup of Bob and Alice's chat

 - Alice and Bob both are asked if you want to store messages, if both agrees to continue then client proceeds with backup

 - To backup Alice's client generates a secure random key and encrypts with Bob's public key & Alice's public key and sends it to server [2 keys]

 - Bob's client does the same

 - Server once receives both the encrypted keys, generates a random salt and keeps on the record and provides that random salt to Bob and Alice on their next ping to server in encrypted form via their public identity keys

 - Bob and Alice gets the secret key for their chat storage through server and decrypts with their private key and combines them to derive secret key that only Alice and Bob knows and then sends data back to server

 - These keys must remain present to client at all times protected by a master password which remains in the mind of user for backup and retrieval purpose



### License
Copyright 2016 Jigar Joshi

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
