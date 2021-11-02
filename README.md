# Basic File Encryptor
Basic OTP encrypt and decrypt using a PBKDF2 key and an AES128 CBC cypher

# Usage

FileEncryptor.java (encrypt mode) (infile) (outfile) (passphrase)

## Encrypt mode

Create a file which you wish to encrypt. Run the program in mode E for encrypt, along with the path for a desired output file (which will be created if it doesn't exist) as well as a passphrase from which the secret key will be generated from.

Absolute paths can be used if run with root privileges. If no path is specified (as below) the file will be created in the local folder.

E.g. Java FileEncryptor.java E infile.txt crypt.bin Str0ngPassPhrase433$

## Decrypt mode

Assuming you have generated an ecrypted file, run the program in mode D for decrypt with the path for the encrypted file, the name for an output file and the passphrase used for encryption.

E.g. Java FileEncryptor.java D crypt.bin outfile.txt Str0ngPassPhrase433$
