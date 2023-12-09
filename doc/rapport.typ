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
  image("project_images/user_registration.svg", width: 90%),
  caption: [
    User registration
  ],
)

=== User login
The login process is as follows:
#figure(
  image("project_images/user_login.svg", width: 50%),
  caption: [
    User login
  ],
)

=== Users list
The server will maintain a list of registered users. Anyone can query the server for the list of users. The server will then return the list of users along with their public keys.

== Files and folders
The system will be based on a tree structure. Each user will have a root folder that will contain all of the user's files and folders. Each element inside a folder will have a key derived from the folder's key. The key derivation process will be done using a key derivation function (KDF), argon2id. This will allow us to easily share a folder with another user by simply sharing the folder's key.

=== Metadata
Each file and folder will have a metadata file that will contain the following information:
- *Nonces*
- *Encrypted keys*
- *Sharing list*: The sharing list will contain the list of users that have access to the file or folder. 

=== Root folder
The root folder is a special folder that is created when a user registers. It is the only folder that has a key that is not derived from the folder's parent key since it has no parent.

The root folder creation process is as follows:
#figure(
  image("project_images/create_root_folder.svg", width: 60%),
  caption: [
    Folder creation
  ],
)

=== Folder creation
#figure(
  image("project_images/create_subfolder.svg", width: 80%),
  caption: [
    Folder creation
  ],
)

=== File creation
#figure(
  image("project_images/create_file.svg", width: 100%),
  caption: [
    File creation
  ],
)

=== Access files and folders
The process of accessing a file or folder is as follows:
== Access file
#figure(
  image("project_images/access_file.svg", width: 60%),
  caption: [
    Accessing a file
  ],
)

== Access folder
TODO: Complete this
#figure(
  image("project_images/access_folder.svg", width: 60%),
  caption: [
    Accessing a folder
  ],
)

== Sharing
=== Folder sharing
#figure(
  image("project_images/share_folder.svg", width: 80%),
  caption: [
    Folder sharing
  ],
)

==== Root folder special case
The root folder cannot be shared or revoked. If a user wants to share their root folder, they will need to create a new folder inside their root folder and share that folder instead.

=== File sharing
#figure(
  image("project_images/share_file.svg", width: 80%),
  caption: [
    File sharing
  ],
)

== Revoking access
The process of revoking access to a file or folder is as follows:

=== Folder
*Note*: The revokation process is done recursively. If a folder is revoked, all of its subfolders and files keys need to be updated as well. If any subfolder or file was shared with another user, we'll need to send the server the new keys for those files and folders for those users to be able to access them.
#figure(
  image("project_images/revoke_folder.svg", width: 80%),
  caption: [
    Folder revokation
  ],
)

=== File
#figure(
  image("project_images/revoke_file.svg", width: 100%),
  caption: [
    File revokation
  ],
)

== Server role
In our model, the server is only acting as a storage server. It does not have access to the user's private keys and cannot decrypt any of the user's files or folders. The server is only responsible for storing the user's files and folders and for sharing the user's public keys with other users. 

The server is also responsible of verifying each user identity when they register or login. This to ensure that no one tries to update something that he's not allowed to.

== Client-Server communication
TLS 1.3 will be used for client-server communication. The server will be authenticated using a valid X.509 certificate. The client will verify the server's certificate and will only communicate with the server if the certificate is valid.

TODO: How is the server certificate issued ?

== Threat model
The following are the various parts of our threat model:
- *Honest but curious server.* The server is assumed to be honest but curious. This means that the server will not try to attack the system but will try to learn as much as possible about the system. We can assure a perfect security against this type of adversary by encrypting everything that is sent to the server. This includes the user's files, folders, and metadata. The server cannot decrypt any of the user's data since it does not have access to the user's password.
- *Active adversary.* An adversary that can intercept, modify, and inject messages. We consider this adversary to be installed in between the client and the server. We are protected against this type of adversary by using TLS 1.3 for client-server communication. This ensures that the adversary cannot intercept, modify, or inject messages.
- *Stolen client device with closed session.* We assume that the client device can be stolen. This is possible because once a session is closed and the user logs out, nothing stays on the device.

The following are not considered part of our threat model:
- *Offline attacks.* We do not consider offline attacks on the user's private key. Anyone can ask the server for the user's encrypted private key and try to decrypt it. Since the key is encrypted with a KDF of the user's password, it would be equivalent to bruteforce the user's password. This would be possible to prevent by asking the user to store the private key himself but this would be less user-friendly than just using a password to login.
- *Stolen device while openned sessions.* We do not consider the case where the device is stolen while the user is logged in. This is because the user's private key is stored in memory and can be accessed by anyone with access to the device.

== What could we do to protect against compromised server ?
TODO: What could we do to protect against a compromised server ? MACs or signatures everywhere

== Storage overhead
TODO: Compute the storage overhead for a file and for a folder.

= System architecture
