# File_Storage_System

A small project attempting to create a filestorage system. Designed and Created alongside Yanru Zhou, a fellow student at UC Berkeley.

File Storage:

  Data is encrypted on the file with RSA-OAEP/sha512 public key encryption using the
user’s public key. Then HMAC is evaluated using the fileHashKey and the encrypted data.
After, it is wrapped up with the encrypted data itself and storedt in the DataStore. Then
the metadata is created, which has information about the location of the file data, the owner, the file
symmetric key used for encryption, and the fileHashKey. Similarly, the metadata is encrypted
using the symmetric key, and the hash is calculated using the encrypted data. After that, it is wrapped,
and stored in the datastore. A note of the location of the metadata is made and saved as
a part of userdata.

File Sharing:

  For a file to be shared with another user, the system must have the file already stored with
the address of the file and the symmetric/hash pair of keys. When the file is shared with another
user, then the user should receive a copy of the address of the file (including metadata), as well
as the key to decrypt the original file, in the form of a byteArray. This string itself could be
encrypted using RSA encryption so that sending it over an insecure channel will not allow it to
be accessed by a malicious third party. It is also signed digitally and includes the verification key,
which will allow the recipient to make sure that the file has not been tampered with and is still
integrous. All of this information is in dataStore using an accessToken as the uuid.

Access Revoke Process:

  The owner must first verify that they are actually the original owner of the file by
decrypting the owner metadata using their personal private key. If the owner chooses to revoke
another user’s access to the file, the owner can then create the copy of the current file. They will
then recreate the full process for storing a file, re-encrypting and wrapping the data and
metadata. This copy of the file should generate a new address and a new set of keys where only
the owner has access to. The data and metadata should also have new addresses that will be hard
for others to find. If there are still some other users that have access to this file, the new address
and new decryption keys should be sent to them as well (not implemented). Then, the owner can
completely delete the original file that the revoked users had access to.

Some attacks this is safe against:

Man in the Middle:

Even if a third party adversary tried to intercept the byte array that contained the address
and the decryption key of the file while the file was being shared to another user, the third party
would still not be able to gain access to the file. That is because the strings have already been
RSA encrypted with the recipient’s public key, so only the user given shared access can decrypt
the string, since the only way to decrypt the sent data would be to have the private key of the
recipient.

Having Full Database Access:

If someone was to gain access to the full database, they still will not be able to gain any
information without complete data on the user with permissions to the file, since there is nothing
in the datastore that is not encrypted at least with one method.

Trying to edit a file through the backend:

Since every file will have the pair of keys (including the calculated HMAC using the
encrypted data for each file), trying to modify a file without having permission as a user will
result in an error immediately due to an HMAC mismatch, both with the metadata and the
filedata itself.
