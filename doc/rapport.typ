#import "template.typ": *

#show: project.with(
  title: "Projet",
  authors: ("Christophe Roulin",)
)

#set table(
  inset: 5pt,
  align: horizon,
)

#set text(
  hyphenate: false
)

#show table: it => [
  #set align(center)
  #it
]

#show heading: it => [
  #if it.level == 1 and it.outlined == true {
    pagebreak()
  }
  #it
]

// Temporary TODO formatting
#show "TODO": it => [
  #set text(red)
  *#it*
]

#outline()

= Description of the project
== Project Overview
The project aims to develop a robust and secure shared encrypted network file system. The system will prioritize user access, confidentiality of file and folder names, protection against active adversaries, and efficient sharing mechanisms while ensuring usability and ease of interaction.

== Project Goals and Objectives:
- *User Authentication:* Implement a user-friendly username/password authentication system requiring minimal logins for seamless user experience.
- *Security Measures:* Ensure robust protection against active adversaries while maintaining confidentiality of file and folder names.
- *Trust Model:* Assume an honest but curious server scenario, focusing on safeguarding data from potential breaches.
- *Device Flexibility:* Enable users to access the file system from various devices effortlessly.
- *Sharing and Access Control:* Facilitate folder sharing among users and implement access revocation.
- *Password Management:* Enable users to securely change their passwords.

== Features and Functionalities:
The system will provide the following key functionalities:
- *Secure File Operations:* Support secure downloading and uploading of files within the system.
- *Folder Management:* Allow users to create folders and manage their structure securely.
- *Sharing Mechanism:* Enable users to share folders securely with other authorized users.
- *Access Revocation:* Implement a secure process for revoking access to shared folders.
- *Password Change:* Provide a secure mechanism for users to change their passwords.

= System modelling
== User management
=== User registration
The server will be responsible for user registration while most of the operations will be done by the client locally.

The registration process is as follows:
#figure(
  image("project_images/user_registration.png", width: 90%),
  caption: [
    User registration
  ],
)

After the registration, the client will have to create a root folder for the user. This is described in the `Root folder` section.

=== User login
The login process is as follows:
#figure(
  image("project_images/user_login.png", width: 80%),
  caption: [
    User login
  ],
)

=== Users list
The server will maintain a list of registered users. Anyone can query the server for the list of users. The server will then return the list of users. Anyone can ask for any user's public key.

== Files and folders
The system will be based on a tree structure. Each user will have a root folder that will contain all of the user's files and folders. Each element inside a folder will have a key derived from the folder's key. The key derivation process will be done using a key derivation function (KDF), argon2id. This will allow us to easily share a folder with another user by simply sharing the folder's key.

=== Metadata
Each file and folder will have a metadata file that will contain the following information:
- *Nonces*
- *Encrypted key*
- *Encrypted name*
- *Sharing list*: The sharing list will contain the list of users that have access to the file or folder. 

=== Root folder
The root folder is a special folder that is created when a user registers. It is the only folder that has a key that is not derived from the folder's parent key since it has no parent.

The root folder creation process is as follows:
#figure(
  image("project_images/create_root_folder.png", width: 60%),
  caption: [
    Folder creation
  ],
)

=== Folder creation
#figure(
  image("project_images/create_subfolder.png", width: 100%),
  caption: [
    Folder creation
  ],
)

=== File creation
#figure(
  image("project_images/create_file.png", width: 100%),
  caption: [
    File creation
  ],
)

=== Access files and folders
The process of accessing a file or folder is as follows:
== Access root folder
#figure(
  image("project_images/access_root_folder.png", width: 60%),
  caption: [
    Accessing the root folder
  ],
)

== Access folder
#figure(
  image("project_images/access_folder.png", width: 60%),
  caption: [
    Accessing a folder
  ],
)

== Access file
#figure(
  image("project_images/access_file.png", width: 60%),
  caption: [
    Accessing a file
  ],
)

=== Traversing and cache
Accessing a specific folder will be possible only if the clients knows the encrypted path of the folder (since the folders names are encrypted and the server don't know the "real" names).

The client will cache the encrypted path of the folders that the user has accessed. This will allow the client to access the folders without having to traverse the whole tree. If the client does not have the encrypted path of a folder, it will have to traverse the tree to find the folder, decrypting each folder's name along the way.

If a folder is renamed or moved, the client will have to traverse the tree again to find the folder. This is because the encrypted path of the folder will have changed. The general idea is that the client will try to traverse the tree if the direct access throws an error.

== Sharing
=== Folder sharing
#figure(
  image("project_images/share_folder.png", width: 80%),
  caption: [
    Folder sharing
  ],
)

==== Root folder special case
The root folder cannot be shared or revoked. If a user wants to share their root folder, they will need to create a new folder inside their root folder and share that folder instead.

=== File sharing
#figure(
  image("project_images/share_file.png", width: 80%),
  caption: [
    File sharing
  ],
)

== Revoking access
The process of revoking access to a file or folder is as follows:

=== Folder
#info([*Note*: The revokation process is done recursively. If a folder is revoked, all of its subfolders and files keys need to be updated as well. If any subfolder or file was shared with another user, we'll need to send the server the new keys for those files and folders for those users to be able to access them.])
#figure(
  image("project_images/revoke_folder.png", width: 80%),
  caption: [
    Folder revokation
  ],
)

=== File
#figure(
  image("project_images/revoke_file.png", width: 100%),
  caption: [
    File revokation
  ],
)

== Server role
In our model, the server is only acting as a storage server. It does not have access to the user's private keys and cannot decrypt any of the user's files or folders. The server is only responsible for storing the user's files and folders and for sharing the user's public keys with other users. 

The server is also responsible of verifying each user identity when they register or login. This to ensure that no one tries to update something that he's not allowed to.

== Client-Server communication
TLS 1.3 will be used for client-server communication. The server will be authenticated using a valid X.509 certificate. The client will verify the server's certificate and will only communicate with the server if the certificate is valid.

When connecting to the server, the client will ask the user for the server's hostname. The client will then try to connect to the server using the hostname and will verify that the server has a valid certificate for the hostname.

The client has a trusted certificate that it will use to verify the server's certificate. If the file is a CA, the client will use it to verify the server's certificate. If the file is not a CA, the client will use it as the server's certificate.

== Threat model
The following are the various parts of our threat model:
- *Honest but curious server.* The server is assumed to be honest but curious. This means that the server will not try to attack the system but will try to learn as much as possible about the system. We can assure a perfect security against this type of adversary by encrypting everything that is sent to the server. This includes the user's files, folders, and metadata. The server cannot decrypt any of the user's data since it does not have access to the user's password. The only added capabilities that a passive adversary installed on the server would have over anyone else is the ability to bruteforce the user's password without any limitations. This is a negligible threat since the user's password is hashed using argon2id with a moderate memory and ops limit. This means that the adversary would need to spend a lot of resources to bruteforce the user's password.
- *Active adversary.* An adversary that can intercept, modify, and inject messages. We consider this adversary to be installed in between the client and the server. We are protected against this type of adversary by using TLS 1.3 for client-server communication. This ensures that the adversary cannot intercept, modify, or inject messages.
- *Stolen client device with closed session.* We assume that the client device can be stolen if the user is logged out. This is possible because once a session is closed and the user logs out, nothing stays on the device.
- *Access to server files after sharing revoked.* We assume that the server files can be accessed by user2 after user1 revoke user2 access to a file or folder even if user2 stored the folder or file key. This is because we will re-encrypt the file or folder (and everything under it) with a new key when the access is revoked. This means that the old key will not be able to decrypt the file or folder anymore.

The following are not considered part of our threat model:
- *Stolen device while openned sessions.* We do not consider the case where the device is stolen while the user is logged in. This is because the user's private key is stored in config and can be accessed by anyone with access to the device.

== Storage overhead
Here's a way to compute the storage overhead of a complete system (counting overhead only, not counting the size of original data and original name).

=== Base
$
  "nonce" = 32B\
$
$
  "aegis256 key" = 32B\
  "aegis256 encryption" = "size" + 32B\
$
$
  "ed25519 private key" = 64B\
  "ed25519 public key" = 32B\
  "x25519 encryption" = "size" + 48B\
$

=== Root folder
$ 
  1 "nonce" = 32B\
  1 "X25519 encrypted key" = 80B\
  \
  "total" = 112B
$

=== Folder
$
  2 "nonces" = 64B\
  1 "aegis256 encrypted name" = "name" + 32B\
  \
  "total" = 96B + "size of name"
$
The overhead for a folder is 96 Bytes.

=== File
$
  3 "nonces" = 96B\
  1 "aegis256 encrypted name" = "name" + 32B\
  1 "aegis256 encrypted data" = "data" + 32B\
  \
  "total" = 160B + "size of name" + "size of data"
$
The overhead for a file is 160 Bytes.

=== Sharing
For each file or folder that is shared with another user, we need to store the encrypted key for that user. This means the following overhead for each file or folder that is shared:
$
  1 "x25519 encrypted key" = 80B\
  \
  "total" = 80B
$

=== Total
The total overhead (in bytes) for a complete system can be computed using the followin formula :
$ "size" = ("users" * 112) + ("folders" * 96) + ("files" * 160) + ("shares" * 80) $

With
- `users` beeing the number of users registered in the system
- `folders` beeing the number of folders in the system
- `files` beeing the number of files in the system
- `shares` beeing the number of files and folders that are shared by a user with another user

= Cryptographic choices
== Key pairs
The system uses the curve25519 elliptic curve for key pairs.

They are used in two different shapes:
- *X25519:* Used for asymmetric encryption.
- *Ed25519:* Used for digital signatures.

=== Key pair storage
All key pair parts are stored in Ed25519 format. This format allows us to easily get the X25519 key pair from the Ed25519 key pair.

== Data hashing
Hashing data is done differently depending on the type of data. 

=== General data
For non-sensitive data, we use the `crypto_generichash` libsodium function. This function is a BLAKE2b hash function. 

This function is used to hash the following data:
- *Username* to use as nonce for the user key pair encryption.

=== Passwords
Sensitive data is hashed using the `crypto_pwhash` libsodium function. The function is configured to use the argon2id1.3 algorithm.
The parameters used are:
- *Memory limit:* `crypto_pwhash_MEMLIMIT_MODERATE`
- *Ops limit:* `crypto_pwhash_OPSLIMIT_MODERATE`

Configured with theses parameters, the function takes about 1 second to hash a password on a modern computer. This is a good tradeoff between security and usability.

This function is used to hash the following data:
- *Password* to store on the server and act as a verification layer before sending the user's encrypted private key.

== Key derivation
Key derivation is done using the `crypto_pwhash` libsodium function. The function is configured to use the argon2id1.3 algorithm.

Parameters used change depending on the type of data that we want to derive a key from.

=== Low entropy data
We consider here low entropy data to be anything coming from the user. In our case, mainly the user's password.

For low entropy data, we use the following parameters:
- *Memory limit:* `crypto_pwhash_MEMLIMIT_MODERATE`
- *Ops limit:* `crypto_pwhash_OPSLIMIT_MODERATE`

Configured with theses parameters, the function takes about 1 second to derive a key on a modern computer. This is a good tradeoff between security and usability.

=== High entropy data
We consider here high entropy data to be anything that is not coming from the user. In our case, mainly any existing key.

For high entropy data, we use the following parameters:
- *Memory limit:* `crypto_pwhash_MEMLIMIT_MIN`
- *Ops limit:* `crypto_pwhash_OPSLIMIT_MIN`

This allows us to derive a key quickly from an existing key. This is very useful here since we'll need to derive *many* keys to do any operations on the user's files and folders.

== Data encryption
=== Symmetric encryption
Symmetric encryption is done using the `crypto_aead_aegis256` libsodium function. This function is an authenticated encryption function. It has the following advantages over the standard AES-GCM encryption #link("https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aegis-256")[see official documentation]. The main advantage for us is that it allows us to use random nonces, greatly simplifying the encryption process.

=== Asymmetric encryption
Asymmetric encryption is done using the `crypto_box_seal` libsodium function. We use the user's public key (X25519) to encrypt the data.

== Data signing
We use signature only to verify the user's identity when they login using a challenge-response process. We use the `crypto_sign_detached` libsodium function to sign using the user's private key (Ed25519).

== Random data
Random data is generated using the `randombytes_buf` libsodium function. This function is cryptographically secure and is used to generate nonces and random keys.

= System architecture
== Session handling
A session is created for each user when they login. The session is used to remind ourself that the user is logged in and authenticated. The session is closed when the user logs out.

This is done by sending the client a session token when the user logs in. The client will then send this token with each request to the server. The server will then verify the token and will only respond to the request if the token is valid.

== Protocol design
Data between the client and sever is sent in JSON format. Each request will contain the following fields:
```json
{
  "session_token": "session token", # Optionnal, not needed for login and register
  "request": "request type",
  "data": "request data"
}
```
=== Request types
The request type can be one of the following
==== Register
- *register_user:* Used to register a user. The data field will contain the username, encrypted private key and public key.
- *create_root_folder:* Used to create the user's root folder. The data field will contain the encrypted root folder's key and the key's seed.

==== Login
- *get_user_password_salt:* Used to get a user's password salt. The data field will contain the username.
- *prepare_login:* Used to prepare a login. The data field will contain the username and the hashed password. The server will then send the user's encrypted private key if the hashed password is correct
- *login:* Used to login a user. The data field will contain the username. The server will then send the challenge for the user and a temporary session token.
- *verify_login:* Used to verify a login. The data field will contain the session token and the challenge response. The server will then send the final session token if the challenge response is correct.

=== User and sessions management
- *logout:* Used to logout a user. The data field will be empty.
- *change_password:* Used to change a user's password. The data field will contain the new encrypted private key, the new hashed password and the new password salt.

==== Users
- *get_users:* Used to get the list of users. The data field will be empty.
- *get_user_public_key:* Used to get a user's public key. The data field will contain the username.

==== Files and folders
- *create_folder:* Used to create a folder. The data field will contain the folder's metadata and the parent folder's path.
- *create_file:* Used to create a file. The data field will contain the file's metadata and the parent folder's path.

- *get_file:* Used to get a file's content. The data field will contain the file's path.
- *get_folder:* Used to get a folder's content. The data field will contain the folder's path.

- *list_folder:* Used to list a folder's content. The data field will contain the folder's path.

- *rename_file:* Used to rename a file. The data field will contain the file's path and the new file's encrypted name and linked seed.
- *rename_folder:* Used to rename a folder. The data field will contain the folder's path and the new folder's encrypted name and linked seed.

- *delete_file:* Used to delete a file. The data field will contain the file's path.
- *delete_folder:* Used to delete a folder. The data field will contain the folder's path.

==== Sharing
- *share_folder:* Used to share a folder. The data field will contain the folder's path, the user to share the folder with and the encrypted folder's key. If the folder is already shared with the user, the encrypted folder's key will be updated.
- *share_file:* Used to share a file. The data field will contain the file's path, the user to share the file with and the encrypted file's key. If the file is already shared with the user, the encrypted file's key will be updated.

==== Revoking access
- *revoke_folder:* Used to revoke a folder. The data field will contain the folder's path and the user to revoke the folder from. This will have the effect of removing the user's encrypted folder key.
- *revoke_file:* Used to revoke a file. The data field will contain the file's path and the user to revoke the file from. This will have the effect of removing the user's encrypted file key.

== Represenation of data
=== User
Users are stored in the server memory and saved to disk when the server is stopped.

A user is represented by the following JSON object:
```json
{
  "p_hash": "",   # Hashed password
  "p_salt": "",   # Password salt
  "b64_pk": "",   # Base64 encoded public key
  "e_b64_sk": ""  # Base64 encoded encrypted private key
}
```

=== Folder
A folder is represented by a folder in the data directory of the server. The folder's name is the folder's base64 encoded encrypted name (replacing '`/`' with '`&`'). Inside each folder is a metadata file (metadata.json) representing the folder's metadata. 

The folder's metadata is represented by the following JSON object:
```json
{
    # Key
    "b64_seed_k": "", # Base64 encoded seed key 
                      # (used to derive the folder's key from the parent folder's key)
    "e_b64_key": {    # Base64 encoded encrypted key for each user that has direct access to the folder
        "user1": "",
        "user2": "",
    },

    # Name
    "b64_seed_n": "", # Base64 encoded seed name 
                      # (used with the folder's key to encrypt the folder's name)
    "e_b64_name": "", # Base64 encoded encrypted name
}
```

=== File
A file is represented by two files in the data directory of the server. The first file is the file's content. The second file is the file's metadata (name.metadata.json).

As for a folder, the name of the file is the file's base64 encoded encrypted name replacing '`/`' with '`&`'. 

The file's metadata is represented by the following JSON object:
```json
{
    # Key
    "b64_seed_k": "", # Base64 encoded seed key 
                      # (used to derive the file's key from the parent folder's key)
    "e_b64_key": {    # Base64 encoded encrypted key for each user that has direct access to the file
        "user1": "",
        "user2": "",
    },

    # Name
    "b64_seed_n": "", # Base64 encoded seed name 
                      # (used with the file's key to encrypt the file's name)
    "e_b64_name": "", # Base64 encoded encrypted name

    # Data
    "b64_seed_d": "", # Base64 encoded seed data 
                      # (used with the file's key to encrypt the file's content)
}
```

= How to run the project
== Requirements
=== Server
- *Python:* Version 3.10 or higher to run the server
- *Pip:* To install the server's dependencies
- *docker (optional):* To run the server using docker
- *docker-compose (optional):* To run the server using docker

=== Client
==== Tools
- *CMake:* To build the project
- *Make:* To build the project
- *C++ compiler:* Supporting C++23

=== Libraries
- *libsodium:* To handle all of the cryptographic operations (#link("https://libsodium.gitbook.io/doc/installation"))
- *nlohmann_json:* Version 3.11.3 or higher to handle JSON data (#link("https://github.com/nlohmann/json"))
- *restclient-cpp:* To handle HTTP requests (#link("https://github.com/mrtazz/restclient-cpp"))

== Certificates
=== Generate selfsigned certificate
The server uses TLS 1.3 to communicate with the client. This means that the server needs a valid certificate to be able to communicate with the client.

In the `certs` directory, there is a `generate.sh` script that will generate a self-signed certificate for the server. This script will generate a certificate for the hostname `localhost`. This means that the client will need to connect to the server using this hostname.

The script will generate a `cert.pem` and a `cert.key` file in the `certs/out` folder. The server will use these files to communicate with the client.

=== Using an existing certificate
If you already have a certificate for the server, you can simply replace the `cert.pem` and `cert.key` files in the `certs/out` folder with your own files. If you want to change the path of the certificate files, you can change the docker compose file.

=== Trusting the certificate
The client is configured to only accept certificates that are either signed by a given CA or that are given. The client will search for the certificate file next to the executable with the name `cert.pem`. 

If the file is a CA, the client will use it to verify the server's certificate. If the file is not a CA, the client will use it as the server's certificate.

== Run the server
=== Using docker
At the root of the project run the following command:
```bash
docker-compose up
```
This will automatically build the server and run it.

The server will then be accessible at `https://localhost:4242`.

=== Using python
==== Install dependencies
```bash
pip3 install -r requirements.txt
```

==== Run the server
```bash
python3 wsgi.py
```

== Run the client
=== Build the project
```bash
mkdir build
cd build
cmake ..
make
```

=== Run the client
```bash
./eos
```

=== Get help
```bash
./eos --help
```

== Tests
At the root of project is a `tests.sh` file. This script will run all commands of the project and will test the output of some of them. This script is used to test the project and to make sure that everything is working as expected.

The tests require docker to be installed. They also require the client to be built and the trusted certificate to be in place.

The script will start a new server and will run all commands against it. At the end, it will stop the server. *Beware that the script will empty the data directory of the server.*

It can be run using the following command:
```bash
./tests.sh
```