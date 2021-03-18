import cryptography
import base64
import sys
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def create_keys(usernamefile, keylen):
    fp = open(usernamefile, 'r')
    names = fp.read().split()

    for name in names:
        puk = name + '_pub_' + str(keylen) +'.txt'
        prk = name + '_priv_' +str(keylen) + '.txt'
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size = keylen,)        
        
        priv_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
        
        f_priv = open(prk, 'w')
        f_priv.write(priv_pem.decode('utf8'))
        f_priv.close() 
        
        public_key = private_key.public_key()
        
        pub_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        
        f_pub = open(puk, 'w')
        f_pub.write(pub_pem.decode('utf8'))
        f_pub.close()
    return
        
def conf(sender, receiver, msgFile, outputFile, hashAlgo, encAlgo, RSAkeylen):
    '''
    1) generate session key, IV
    2) encrypt message using given enc Algo
    3) encrypt session key, IV using receivers public key
    4) print in base64 format
    '''
    
    rec_pub_file = open(receiver+'_pub_'+str(RSAkeylen)+'.txt','r')
    rec_pub_pem = bytes(rec_pub_file.read(), encoding='utf8')
    rec_pub_rsa = serialization.load_pem_public_key(rec_pub_pem)
    rec_pub_file.close()
        
    # step-1
    if encAlgo == 'des-ede3-cbc':
        sess_keylen = 192//8
        block_size = 64//8
        sess_key = os.urandom(sess_keylen)        
        iv = os.urandom(block_size)
        cipher = Cipher(algorithms.TripleDES(sess_key), modes.CBC(iv))
        encryptor = cipher.encryptor()    
    elif encAlgo == 'aes-256-cbc':
        sess_keylen = 256//8
        block_size = 128//8
        sess_key = os.urandom(sess_keylen)
        iv = os.urandom(block_size)
        cipher = Cipher(algorithms.AES(sess_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
    else:
        print('invaid encryption algo, use one among des-ede3-cbc, aes-256-cbc')
        exit(0)
    
    if hashAlgo == 'sha512':
        hashFn = hashes.SHA512
    elif hashAlgo == 'sha3-512':
        hashFn = hashes.SHA3_512
    else:
        print('invaid digest/hash algorithm name')
        exit(0)
        
    # step-2
    f_msg = open(msgFile,'r')
    msg = bytes(f_msg.read(), encoding='utf8')
    f_msg.close()
    
    if len(msg)%block_size > 0:
        pad_length = block_size - len(msg)%block_size
        msg = msg + (b'\x00' * pad_length)    
    
    c_text2 = encryptor.update(msg) + encryptor.finalize()
    
    # step 3
    key_iv = sess_key + iv
    
    try:
        c_text1 = rec_pub_rsa.encrypt(key_iv, padding.OAEP(mgf=padding.MGF1(algorithm=hashFn()), algorithm=hashFn(), label=None))
    except:
        print("RSA encryption with receiver public key failed")
        return
    #step 4
    outfp = open(outputFile, 'w')

    base64_ctext1 = base64.b64encode(c_text1)
    base64_ctext2 = base64.b64encode(c_text2)
    outfp.write(base64_ctext1.decode('utf8'))
    outfp.write('\n')
    outfp.write(base64_ctext2.decode('utf8'))    
    
    outfp.close()
    return

def read_conf(sender, receiver, cipherFile, outputFile, hashAlgo, encAlgo, RSAkeylen):
    '''
    1) get private key of receiver
    2) get session key,IV from first line
    3) get encrypted msg from 2nd line
    4) decrypt
    '''
    rec_priv_file = open(receiver+'_priv_'+str(RSAkeylen)+'.txt', 'r', )
    rec_priv_pem = bytes(rec_priv_file.read(), encoding = 'utf8')
    rec_priv_rsa = serialization.load_pem_private_key(rec_priv_pem, None)
    rec_priv_file.close()
    
    if encAlgo == 'des-ede3-cbc':
        sess_keylen = 192//8
        block_size = 64//8        
    elif encAlgo == 'aes-256-cbc':
        sess_keylen = 256//8
        block_size = 128//8
    else:
        print('invaid encryption algo, use one among des-ede3-cbc, aes-256-cbc')
        exit(0)
    
    if hashAlgo == 'sha512':
        hashFn = hashes.SHA512
    elif hashAlgo == 'sha3-512':
        hashFn = hashes.SHA3_512
    else:
        print('invaid digest/hash algorithm name')
        exit(0)
    
    f_cipher = open(cipherFile, 'r')
    total = f_cipher.read().split()
    line1 = total[0]
    line2 = total[1]
    f_cipher.close()
    
    enc_key_iv = base64.b64decode(line1)
    enc_msg = base64.b64decode(line2)
    
    try:
        key_iv = rec_priv_rsa.decrypt(enc_key_iv, padding.OAEP(mgf=padding.MGF1(algorithm=hashFn()), algorithm=hashFn(),label=None))
    except:
        print("RSA decryption with receiver private key failed")
        return
        
    sess_key = key_iv[0:sess_keylen]
    iv = key_iv[sess_keylen: sess_keylen+block_size]
    
    if encAlgo == 'des-ede3-cbc':
        cipher = Cipher(algorithms.TripleDES(sess_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
    elif encAlgo == 'aes-256-cbc':
        cipher = Cipher(algorithms.AES(sess_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
    
    dec_msg = decryptor.update(enc_msg) + decryptor.finalize()
    for i in range(0, len(dec_msg)):
        if dec_msg[i] == 0:
            break    
    dec_msg = dec_msg[0:i]
    
    outFile = open(outputFile, 'w')
    outFile.write(dec_msg.decode('utf8'))
    outFile.close()    
    return
    
def auin(sender, receiver, msgFile, outputFile, hashAlgo, encAlgo, RSAkeylen):
    '''
    1) Generate hash of msg text
    2) encrypt (1) using senders private key
    3) write (2) and msg in base64 format
    '''
    
    snd_priv_file = open(sender+'_priv_'+str(RSAkeylen)+'.txt', 'r', )
    snd_priv_pem = bytes(snd_priv_file.read(), encoding = 'utf8')
    snd_priv_rsa = serialization.load_pem_private_key(snd_priv_pem, None)
    snd_priv_file.close()
    
    f_msg = open(msgFile,'r')
    msg = bytes(f_msg.read(), encoding='utf8')
    f_msg.close()
    
    if hashAlgo == 'sha512':
        hashFn = hashes.SHA512
    elif hashAlgo == 'sha3-512':
        hashFn = hashes.SHA3_512
    else:
        print('invaid digest/hash algorithm name')
        exit(0)
    
    digest = hashes.Hash(hashFn())
    digest.update(msg)
    hash_msg = digest.finalize()
    # print(hash_msg)
    
    cipher_hash = snd_priv_rsa.sign(hash_msg, padding.PSS(mgf=padding.MGF1(hashFn()),salt_length=padding.PSS.MAX_LENGTH), utils.Prehashed(hashFn()))    
    
    base64_chash = base64.b64encode(cipher_hash)
    base64_msg = base64.b64encode(msg)
    
    outfp = open(outputFile, 'w')
    outfp.write(base64_chash.decode('utf8'))
    outfp.write('\n')
    outfp.write(base64_msg.decode('utf8'))
    return
    
def read_auin(sender, receiver, cipherFile, outputFile, hashAlgo, encAlgo, RSAkeylen):
    '''
    1) decrypt hash using senders public key
    2) calculate hash of msg text
    3) match them
    '''
    snd_pub_file = open(sender+'_pub_'+str(RSAkeylen)+'.txt','r')
    snd_pub_pem = bytes(snd_pub_file.read(), encoding='utf8')
    snd_pub_rsa = serialization.load_pem_public_key(snd_pub_pem)
    snd_pub_file.close()
    
    f_cipher = open(cipherFile, 'r')
    total = f_cipher.read().split()
    line1 = total[0]
    line2 = total[1]
    f_cipher.close()
    
    enc_hash = base64.b64decode(line1)
    msg = base64.b64decode(line2)
    
    if hashAlgo == 'sha512':
        hashFn = hashes.SHA512
    elif hashAlgo == 'sha3-512':
        hashFn = hashes.SHA3_512
    else:
        print('invaid digest/hash algorithm name')
        exit(0)

    digest = hashes.Hash(hashFn())
    digest.update(msg)
    hash_msg = digest.finalize()
    # print(hash_msg)

    try:    
        snd_pub_rsa.verify(enc_hash, hash_msg, padding.PSS(mgf=padding.MGF1(hashFn()), salt_length=padding.PSS.MAX_LENGTH), utils.Prehashed(hashFn()))
    except:
        print("Signature doesnt match")
        return
    
    outFile = open(outputFile, 'w')
    outFile.write(msg.decode('utf8'))
    outFile.close()     

    return

def coai(sender, receiver, msgFile, outputFile, hashAlgo, encAlgo, RSAkeylen):
    
    '''
    1) generate msg hash
    2) encrypt (1) with senders private key
    3) (2||msg) encrypted using AES/3DES, by generating session key, iv
    4) session key, iv is encrypted using receiver's public key
    5) print to file in 2 lines
    '''
    
    rec_pub_file = open(receiver+'_pub_'+str(RSAkeylen)+'.txt','r')
    rec_pub_pem = bytes(rec_pub_file.read(), encoding='utf8')
    rec_pub_rsa = serialization.load_pem_public_key(rec_pub_pem)
    rec_pub_file.close()
    
    
    
    if hashAlgo == 'sha512':
        hashFn = hashes.SHA512
    elif hashAlgo == 'sha3-512':
        hashFn = hashes.SHA3_512
    else:
        print('invaid digest/hash algorithm name')
        exit(0)
  
def read_coai(sender, receiver, msgFile, outputFile, hashAlgo, encAlgo, RSAkeylen):
    if hashAlgo == 'sha512':
        hashFn = hashes.SHA512
    elif hashAlgo == 'sha3-512':
        hashFn = hashes.SHA3_512
    else:
        print('invaid digest/hash algorithm name')
        exit(0)
  
if __name__ == "__main__":
    argc = len(sys.argv)
    if(argc < 2):
        print('invalid execution instructions')
        exit(0)
        
    mode = sys.argv[1]
    
    if(mode == 'CreateKeys'):
        
        if not argc == 4:
            print('incorrect parameters')
            exit(0)
        usernames = sys.argv[2]
        RSAsize = int(sys.argv[3])
        create_keys(usernames, RSAsize)
        
    elif(mode == 'CreateMail'):
        if not argc==10:
            print('incorrect parameters')
            exit(0)
        
        op = sys.argv[2]
        sender = sys.argv[3]
        recver = sys.argv[4]
        inputFile = sys.argv[5]
        outputFile = sys.argv[6]
        hashAlgo = sys.argv[7]
        encAlgo = sys.argv[8]
        RSAsize = int(sys.argv[9])
        
        if op=='CONF':
            conf(sender, recver, inputFile, outputFile, hashAlgo, encAlgo, RSAsize)
        elif op=='AUIN':
            auin(sender, recver, inputFile, outputFile, hashAlgo, encAlgo, RSAsize)
        elif op=='COAI':
            coai(sender, recver, inputFile, outputFile, hashAlgo, encAlgo, RSAsize)
        else:
            print('invalid operation type')
            exit(0)
            
    elif(mode == 'ReadMail'):
        if not argc==10:
            print('incorrect parameters')
            exit(0)
        
        op = sys.argv[2]
        sender = sys.argv[3]
        recver = sys.argv[4]
        inputFile = sys.argv[5]
        outputFile = sys.argv[6]
        hashAlgo = sys.argv[7]
        encAlgo = sys.argv[8]
        RSAsize = int(sys.argv[9])
        
        if op=='CONF':
            read_conf(sender, recver, inputFile, outputFile, hashAlgo, encAlgo, RSAsize)
        elif op=='AUIN':
            read_auin(sender, recver, inputFile, outputFile, hashAlgo, encAlgo, RSAsize)
        elif op=='COAI':
            coai(sender, recver, inputFile, outputFile, hashAlgo, encAlgo, RSAsize)
        else:
            print('invalid operation type')
            exit(0)
    else:
        print('invalid commands')
    