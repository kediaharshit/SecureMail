# CS6500 - Assignment 2 Secure Email
The objective of this project is to implement the various components of a security-enhanced EMAIL system similar to PGP (Pretty Good Privacy) and GnuPG which is based on the openPGP standard.

#### CONF - Confidentiality only

#### AUIN - Authentication/Integrity only

#### COAI - Confidentiality and Integrity

Details on how to run, sample input commands are given in file sample_cmds.txt

###### Files: 
1. lab2.py : python program as specified in problem statement.
2. usernames.txt : file containing 11 distinct usernames for which can be used to test the program, new names can be added.
3. README : has instrutions and sample cases to run.

###### Instructions:
1. Used library cryptography, https://pypi.org/project/cryptography
2. Use the format from the problem statement, can change _sender, receiver_ names for testing. Can also change _inputfile, outputfile_ as reuqired. Finally, we can also select the DigestAlgo among one of "sha512, sha3-512", and EncryptionAlgo among one of "des_ede3-cbc, aes-256-cbc".
3. Remember to keep the RSA key size same during further testing as kept for CreateKeys. You can create keys for everyone at the beginning, and use the same set of keys for all further executions of the program.
4. For simplicity, all usernames are in lower-case alphabets


### Sample Commands:

Initialization: python3 lab2.py CreateKeys usernames.txt 2048

--------------------------------------------------------------------------------------------------
CONF: 
1. between bob and alice, using SHA512 and AES

	1. python3 lab2.py CreateMail CONF bob alice msg.txt enc_conf.txt sha512 aes-256-cbc 2048
	2. python3 lab2.py ReadMail CONF bob alice enc_conf.txt dec_conf.txt sha512 aes-256-cbc 2048

2. between jim and pam, using SHA3-512 and 3DES

	1. python3 lab2.py CreateMail CONF jim pam msg.txt enc_conf.txt sha3-512 des-ede3-cbc 2048
	2. python3 lab2.py ReadMail CONF jim pam enc_conf.txt dec_conf.txt sha3-512 des-ede3-cbc 2048

--------------------------------------------------------------------------------------------------
AUIN:
1. between tim and rob, using SHA512 and 3DES

	1. python3 lab2.py CreateMail AUIN tim rob msg.txt enc_auin.txt sha512 des-ede3-cbc 2048
	2. python3 lab2.py ReadMail AUIN tim rob enc_auin.txt dec_auin.txt sha512 des-ede3-cbc 2048

2. between kathy and nancy, using SHA3-512 and AES

	1. python3 lab2.py CreateMail AUIN kathy nancy msg.txt enc_auin.txt sha3-512 aes-256-cbc 2048
	2. python3 lab2.py ReadMail AUIN kathy nancy enc_auin.txt dec_auin.txt sha3-512 aes-256-cbc 2048

--------------------------------------------------------------------------------------------------
COAI
1. between harry and darth, using SHA3-512 and AES

	1. python3 lab2.py CreateMail COAI harry darth msg.txt enc_coai.txt sha3-512 aes-256-cbc 2048
	2. python3 lab2.py ReadMail COAI harry darth enc_coai.txt dec_coai.txt sha3-512 aes-256-cbc 2048

2. between charlie and gary, using SHA512 and 3DES

	1. python3 lab2.py CreateMail COAI charlie gary msg.txt enc_coai.txt sha512 des-ede3-cbc 2048
	2. python3 lab2.py ReadMail COAI charlie gary enc_coai.txt dec_coai.txt sha512 des-ede3-cbc 2048


#### Conclusion:
1. The above given sequence of commands use different keys at every stage, using all 12 user keys.
2. It also checks all combination of hash and encryption functions given.
3. The command sequence given has used RSA keys of length 2048. Entire exercise can be repeated for other key size too.
4. typescript record for all these runs are also attached
