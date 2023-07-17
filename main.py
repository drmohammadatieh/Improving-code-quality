from curses import has_colors
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512,SHA384,SHA256, SHA, MD5
from Crypto import Random

hash = 'SHA-256'

def newkeys(keysize):
    '''Generate private and public RSA keys'''
    random_generator = Random.new().read
    key = RSA.generate(keysize, random_generator)
    private, public = key, key.public_key()
    return public, private


def encrypt(message, pub_key):
    '''Encrypts a message using a public key using RSA algorithm'''
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message.encode('utf-8'))


def decrypt(ciphertext,private_key):
    'Decrypts a cipher message using a private key'
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)

def sign(message, private_key, hashAlg=hash):
    '''Creates a signature for Authorization purposes'''
    hash = hashAlg
    signer = PKCS1_v1_5.new(private_key)
    
    if (hash == "SHA-512"):
          digest = SHA512.new()
    elif (hash == "SHA-384"):
        digest = SHA384.new()
    elif (hash == "SHA-256"):
        digest = SHA256.new()
    elif (hash == "SHA-1"):
        digest = SHA.new()
    else:
      digest = MD5.new()

    # Hash the message
    digest.update(message.encode('utf-8'))

    # Return the signature
    return signer.sign(digest)

def verify(message, signature, pub_key):
    '''Authenticate that identify of the sender by verifying the digital
    signature matches
    the digest created by the public key
    '''
    signer = PKCS1_v1_5.new(pub_key)

    if (hash == "SHA-512"):
          digest = SHA512.new()
    elif (hash == "SHA-384"):
        digest = SHA384.new()
    elif (hash == "SHA-256"):
        digest = SHA256.new()
    elif (hash == "SHA-1"):
        digest = SHA.new()
    else:
      digest = MD5.new()
    digest.update(message.encode('utf-8')) 
    return signer.verify(digest, signature)


# Create public and private keys to be used for RSA encryption
pub_key, private_key = newkeys(1024)
# Create a message that will be encrypted later
message = "Hello, my name is Mohammad"
# Create a digital signature for authorization purposes
digital_signature = sign(message,private_key)
# Verify the identity of the sender; return True if authenticated
authenticated_sender = verify(message,digital_signature,pub_key)
# Encrypt the message
encrypted_message = encrypt(message,pub_key)
# Decrypt the message and print it
print(decrypt(encrypted_message,private_key))
