# Encrypted P2P Messaging App
## About The Project
This project works to implement a P2P Messaging App with a focus on encryption. First the server must be run on a machine where it will begin to listen for connections using a TCP socket. Next, up to two clients can be run on any other machine where they will begin to attempt to connect to the server. Once connected the user will be prompted to input their username. Once the server verifies that the user has input the correct username, it will connect the user to the other client. At this time the only available users are Alice and Bob who will connect to each other automatically. Once the user is connected to their peer, they will need to input their shared password at the top. This password will determine the key that will be used for symmetric encryption between the two parties. Once the user is finished messaging they can close the app where all threads and sockets will be safely closed. Furthermore, once the app is prompted to close it will save all messages to a file on the user's local machine. This allows the user to pick up where they left off before.

## Encryption Techniques Used
### Hashing The Password
* The password that the user inputs will have the total time since the epoch divided by 1000 appended to the end. This will cause the password to change every 1000 seconds. This increases security because even if the key used for encryption is discovered, the key will change in approximately sixteen minutes. This technique also works because every client will have the same time. This allows them to change keys without any key negotiation needed!
* The modified password is hashed with the SHA256 hash function. This will allow the key to always be 256 bits in length no matter what password is used. This length of key will be long enough to prevent any current brute force attacks. Furthermore, this will allow the changing time appended on the end to change the entire key. This final result will be used for encryption

### Symetric Key Encryption
* All messages will be encrypted with AES encryption using the key described above. Before encryption, messages are padded with bytes describing the length of the padding. This value will be used during decryption to remove the correct amount of padding. Once encrypted they will be sent to the server where they will then be routed to the correct client. Since the keys are stored locally, even if an attacker got access to the server, they would still not be able to observe what the messages are.
* Messages will be encrypted in CBC (Cipher Block Chaining) mode. This allows similar messages to have very different ciphertexts. For example Bob could send Alice "ok" multiple times but an attacker would be unable to observe this. The IV that is used for encryption will be appended to the beginning of the ciphertext to be used for decryption.

## Benefits Of The Design
* Changing the key according to the time allows for a very simple but effective way of protecting the key. This avoids the necessity of key negotiation whether through RSA or Diffie-Hellman key exchange. Furthermore, it also allows messages to be decrypted if they were not previously done so before the key changed. All that is needed to decrypt each message is for the time to be stored with them. Finally, because of this, it allows messages to easily be saved in a file and decrypted later.
* Using a shared password that is remembered by each client can also provide some benefits. If the password is simply remembered then there is no way for the key to be found on any device. Furthermore, since the password is kept by only the users, the server will never have access to the key and cannot view the plaintext on its own.

## Future Improvments
This application can still be expanded in a couple ways. First, this app currently only supports two users, Bob and Alice. However, this app's architecture could allow it to easily support more than two users without a large rework. Second, this app only uses symmetric encryption which requires the users to trust each other. If this app is expanded to support more users, it could also benefit by adding asymmetric encryption algorithms such as RSA. Finally, this app's GUI could be expanded upon to offer users more information. User's could potentially view who is connected to the server and choose who they wish to speak to in the app.

## Libraries and Modules Used For Encryption And GUI
### pycryptodome
Pycryptodome was used to implement AES encryption between users and create random bytes for the initialization vector.
### hashlib
Hashlib was used to hash the key with SHA256.
### tkinter
Tkinter was used to implement all of the GUI within the app.
