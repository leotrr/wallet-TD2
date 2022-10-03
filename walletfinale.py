# -*- coding: utf-8 -*-
"""
Created on Sat Oct  1 19:17:58 2022

@author: leotr
"""
import os
import binascii
import hashlib
import unicodedata
import secrets
import sys
import hmac
import ecdsa
from ecdsa.curves import SECP256k1
import codecs

from ecdsa.ecdsa import int_to_string, string_to_int

def padd_binary(bin_str: str, size: int) -> str:
    """
    Pads a binary string with zeros to the left
    :param bin_str: binary string to pad
    :param size: size of the padded string
    :return: padded binary string
    """
    for _ in range(size - len(bin_str)):
        bin_str = '0' + bin_str
    return bin_str

def byte_to_binary(b: bytes, size: int) -> str:
    """
    Converts a byte to a binary string
    :param byte: byte to convert
    :param size: size of the binary string
    :return: binary string
    """
    order = -1 if sys.byteorder == 'little' else 1
    bin_n = bin(int.from_bytes(b, byteorder='big'))[2:]
    return padd_binary(bin_n, size)
entropy_bytes = secrets.token_bytes(16)
entropy = byte_to_binary(entropy_bytes, 128)
hash = hashlib.sha256(entropy_bytes).digest()
entropy_hash = byte_to_binary(hash, 256)


binaire=entropy+entropy_hash[:4]

print(entropy + entropy_hash[:4])
liste=[]
      
with open("french.txt", "r", encoding="utf-8") as f:
     for w in f.readlines():
        liste.append(w.strip())

liste_mots = []
for i in range(len(binaire) // 11):
    
    index = int(binaire[i*11 : (i+1)*11], 2)
    
    liste_mots.append(liste[index])

phrase = " ".join(liste_mots)
print(" votre seed est :" + phrase)

#IMPORTER LA SEED
normalized_mnemonic = unicodedata.normalize("NFKD", phrase)
password = ""
normalized_passphrase = unicodedata.normalize("NFKD", password)

passphrase = "mnemonic" + normalized_passphrase
mnemonic = normalized_mnemonic.encode("utf-8")
passphrase = passphrase.encode("utf-8")

bin_seed = hashlib.pbkdf2_hmac("sha512", mnemonic, passphrase, 2048)

print('BIP39 SEED ' + str(binascii.hexlify(bin_seed[:64])))

#chain m

seed = binascii.unhexlify(binaire)  

I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest() 
Il, Ir = I[:32], I[32:]  # Divide HMAC into "Left" and "Right" section of 32 bytes each :) 

#generer clé publique privé

secret = Il # partie de gauche  HMAC pour private key
chain = Ir # partie de droite HMAC pour chain code

k_priv = ecdsa.SigningKey.from_string(secret, curve=ecdsa.SECP256k1)


k_priv_bytes=k_priv.to_string()


k_priv_hex=codecs.encode(k_priv_bytes, 'hex')

private_key=k_priv_hex.decode("utf-8")

print("Votre clé privé est: " + str(private_key))



#generer clé public
public_key_raw = ecdsa.SigningKey.from_string(k_priv_bytes, curve=ecdsa.SECP256k1).verifying_key
public_key_bytes = public_key_raw.to_string()

public_key_hex = codecs.encode(public_key_bytes, 'hex')

public_key = (b'04' + public_key_hex).decode("utf-8")
print("Votre clé publique est :" + str(public_key))

print(' code chain : ' + str(codecs.encode(chain, 'hex')))












 








