# !/usr/bin/python
import os
import sys
import hashlib
import base64
import requests
import json
import datetime
from time import sleep
from concurrent.futures import ThreadPoolExecutor

if sys.platform == "linux":
    os.system("clear")
else:
    os.system("cls")

wordlist_hashes = []
finds = False

print("""\033[1;31m
 _____         _   ____                      _   
|  |  |___ ___| |_|    \ ___ ___ ___ _ _ ___| |_ 
|     | .'|_ -|   |  |  | -_|  _|  _| | | . |  _|
|__|__|__,|___|_|_|____/|___|___|_| |_  |  _|_|  
                                    |___|_|\033[m
            Instagram: \033[32m@nanoxsec\033[m
""")
start = datetime.datetime.now()
if sys.version >= "3":
    hash_user = str(input("Hash: ")).strip()
    print("\n\033[1m@ Start in {}\033[m\n".format(start))
    print("\033[1m[\033[1;32m + \033[m\033[1m]\033[m \033[1mIdentificando hash...\033[m\n")
    tipo_hash = requests.get("https://hashes.com/en/api/identifier?hash={}".format(hash_user))
    tipo_resu = json.loads(tipo_hash.text)
    tipo_pego = tipo_resu["algorithms"][0].lower()

def worker(hash_user,hashed):
    with open("Decripted.txt", "a") as decrypted:
        decrypted.write(f"{hash_user}:{palavra}\n")


def tentar_crack(hash_user, tipo_pego):
    global palavra
    try:
        with open("senhas.txt", "r", encoding="latin-1") as file:
            for c, x in enumerate(file):
                palavra = x.strip().replace("\n","")
                palavra_bytes = palavra.encode("utf-8")

                if tipo_pego == "base64 encoded string":
                    try:
                        resultado = base64.b64decode(hash_user).decode()
                        print(f"\033[1;32mSenha:\033[m \033[1m{resultado}\033[m")
                        return True
                    except Exception:
                        return False

                func_map = {
                    "md5": hashlib.md5,
                    "sha1": hashlib.sha1,
                    "sha256": hashlib.sha256,
                    "sha384": hashlib.sha384,
                    "sha3-224": hashlib.sha224,
                    "sha512": hashlib.sha512,
                }

                if tipo_pego in func_map:
                    hashed = func_map[tipo_pego](palavra_bytes).hexdigest()
                    if hashed == hash_user:
                        print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] \033[1;32m[*] Senha:\033[m \033[1m{palavra}\033[m")
                        worker(hash_user, hashed)
                        finds = True
                        return True
                    else:
                        print(f"\033[1;33m[{datetime.datetime.now().strftime('%H:%M:%S')}]\033[m \033[31m[-] Senha testada:\033[m\033[1;2m {palavra} --> [{hash_user}]\033[m")
    except Exception as e:
        print(f"Erro ao processar: {e}")
    return False


if __name__ == "__main__":
    with ThreadPoolExecutor(max_workers=120) as executor:
        executor.map(worker, wordlist_hashes)

    if tentar_crack(hash_user, tipo_pego):
        fim2 = datetime.datetime.now() - start
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] \033[1;mTempo cracked -->\033[m \033[1;36m{fim2}\033[m\n")
        sys.exit()
    elif not finds:
        print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] \033[1m[ ! ]\033[m \033[1;31mHash não encontrada.\033[m")
