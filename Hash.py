# !/usr/bin/python

# Script feito para a quebra de senhas!
# suporta enconders: md5.sha1,sha256,sha384,sha512,base64
# para utilizar é simples: VOcê precisa ter uma wordlist grande no mesmo arquivo do script!
# A wordlist deverá ter o nome de senhas.txt
# execute o script e coloque a senha que ta com a hash
# espere ele quebrar!

#by Nano

import os
import sys
import hashlib
import base64
import requests
import json
import datetime
import time
from time import sleep
from concurrent.futures import ThreadPoolExecutor

if sys.platform == "linux":
    os.system("clear")
else:
    os.system("cls")

wordlist_hashes = []
finds = False

print("""\033[1;35m
    __  __           __       ____                             __ 
   / / / /___ ______/ /_     / __ \___  ____________  ______  / /_
  / /_/ / __ `/ ___/ __ \   / / / / _ \/ ___/ ___/ / / / __ \/ __/
 / __  / /_/ (__  ) / / /  / /_/ /  __/ /__/ /  / /_/ / /_/ / /_  
/_/ /_/\__,_/____/_/ /_/  /_____/\___/\___/_/   \__, / .___/\__/  
                                               /____/_/           
            Instagram: \033[1;33m@nanoxsec\033[m

#####################################################
\033[1;31mSuportes\033[m: md5,sha1,sha256,sha512,base64,sha384,sha224
#####################################################
\n""".format(str(sys.version[0:6])))
start = datetime.datetime.now()
if sys.version >= "1":
    hash_user = str(input("Hash: ")).strip()
    print("\n\033[1m@ Start in {}\033[m\n".format(start))
    print("\033[1m[\033[1;32m + \033[m\033[1m]\033[m \033[1mIdentificando hash...\033[m")
    tipo_hash = requests.get("https://hashes.com/en/api/identifier?hash={}".format(hash_user))
    tipo_resu = json.loads(tipo_hash.text)
    tipo_pego = tipo_resu["algorithms"][0].lower()


def worker(hash_user,hashed):
    with open("Decripted.txt", "a") as decrypted:
        decrypted.write(f"{hash_user}:{palavra}\n")

def tentar_crack(hash_user, tipo_pego):
    try:
        print(f"\033[1m[\033[1;32m + \033[m\033[1m]\033[m \033[1mTipo da Hash:\033[m \033[1;32m{tipo_pego}\033[m\n")

        func_map = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha3-384": hashlib.sha3_384,
            "sha3-224": hashlib.sha3_224,
            "sha512": hashlib.sha512,
            "sha224": hashlib.sha224,
            "sha3-256": hashlib.sha3_256,
            "sha3-512": hashlib.sha3_512,

        }

        if tipo_pego not in func_map and tipo_pego != "base64 encoded string":
            print("Tipo de hash não suportado.")
            return False

        tamanho_barra = 40
        total_bytes = os.path.getsize("senhas.txt")
        ultimo_update = 0
        contador = 0
        inicio = time.time()

        if tipo_pego != "base64 encoded string":
            target_hash = bytes.fromhex(hash_user)
            hash_func = func_map[tipo_pego]

        with open("senhas.txt", "rb") as file:
            while True:
                posicao = file.tell()
                linha = file.readline()

                if not linha:
                    break

                contador += 1
                palavra = linha.strip()

                if tipo_pego == "base64 encoded string":
                    try:
                        resultado = base64.b64decode(hash_user).decode()
                        print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] \033[1;32m[*] Senha quebrada:\033[m \033[1m{resultado}\033[m")
                        return True
                    except:
                        return False

                hashed = hash_func(palavra).digest()

                if hashed == target_hash:
                    senha = palavra.decode(errors="ignore")

                    progresso = posicao / total_bytes
                    blocos = int(tamanho_barra * progresso)
                    barra = "█" * blocos + "-" * (tamanho_barra - blocos)
                    porcentagem = progresso * 100

                    tempo_total = time.time() - inicio
                    hps = int(contador / tempo_total) if tempo_total > 0 else 0

                    print(f"\r[{barra}] {porcentagem:6.2f}% | {hps} \033[1;36mH/s\033[m | \033[1;31mETA\033[m: 00:00:00 | \033[1;31mSenha\033[m: {senha[:25]:25}")
                    print(
                        f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] "
                        f"\033[1;32m[*] Senha quebrada:\033[m \033[1m{senha}\033[m"
                    )

                    with open("Decripted.txt", "a") as decrypted:
                        decrypted.write(f"{hash_user}:{senha}\n")

                    return True

                # Atualiza 10x por segundo
                agora = time.time()
                if agora - ultimo_update > 0.1:
                    progresso = posicao / total_bytes
                    blocos = int(tamanho_barra * progresso)
                    barra = "█" * blocos + "-" * (tamanho_barra - blocos)
                    porcentagem = progresso * 100

                    tempo_total = agora - inicio
                    hps = int(contador / tempo_total) if tempo_total > 0 else 0

                    restante_bytes = total_bytes - posicao
                    velocidade_bytes = posicao / tempo_total if tempo_total > 0 else 0
                    eta_segundos = int(restante_bytes / velocidade_bytes) if velocidade_bytes > 0 else 0

                    eta_formatado = time.strftime("%H:%M:%S", time.gmtime(eta_segundos))

                    sys.stdout.write(
                        f"\r[{barra}] {porcentagem:6.2f}% | {hps:6d} \033[1;36mH/s\033[m | \033[1;31mETA\033[m: {eta_formatado} | \033[1;31mSenha\033[m: {palavra.decode(errors='ignore')[:25]:25}"
                    )
                    sys.stdout.flush()

                    ultimo_update = agora

        print()
        return False

    except Exception as e:
        print(f"\nErro: {e}")
        return False

if __name__ == "__main__":
    with ThreadPoolExecutor(max_workers=120) as executor:
        executor.map(worker, wordlist_hashes)

    if tentar_crack(hash_user, tipo_pego):
        fim2 = datetime.datetime.now() - start
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] \033[1;m\033[1;32m[*]\033[m \033[1;36mTempo total:\033[m -->\033[m \033[1;36m{fim2}\033[m\n")
        sys.exit()
    elif not finds:
        print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] \033[1m[ ! ]\033[m \033[1;31mHash não encontrada.\033[m")
