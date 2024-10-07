# !/usr/bin/python
import os
import sys
import hashlib
import base64
import requests
import json
import datetime
from time import sleep

# limpando a tela
if sys.platform == "linux":
	os.system("clear")
else:
	os.system("cls")

wordlist_hashes = []
arquivo = False
finds = False

# baner
print("""
 _   _           _      ______                           _   
| | | |         | |     |  _  \                         | |  
| |_| | __ _ ___| |__   | | | |___  ___ _ __ _   _ _ __ | |_ 
|  _  |/ _` / __| '_ \  | | | / _ \/ __| '__| | | | '_ \| __|
| | | | (_| \__ \ | | | | |/ /  __/ (__| |  | |_| | |_) | |_ 
\_| |_/\__,_|___/_| |_| |___/ \___|\___|_|   \__, | .__/ \__|
                                              __/ | |        
                                             |___/|_|        
		\033[1m[\033[m\033[1;31m+\033[m\033[1m]\033[m \033[1mCoded by:\033[m \033[1;31mNano\033[m
""")

print("""
[ 1 ] - Descriptografar uma hash
[ 2 ] - Carregar um arquivo de hashes
	""")

# coletando entrada
try:
	entrada_user = str(input("\033[1m\033[m\033[1;36m>>> \033[m")).strip()
	start = datetime.datetime.now()

except KeyboardInterrupt:
	print("\033[1m[\033[1;31m OFF \033[m\033[1m]\033[m \033[1mSaindo...\033[m\n")
	raise SystemExit
if entrada_user == "2":
	arquivo = True
	nome_arquivo = str(input("Nome do arquivo: ")).strip()
	print()
	if nome_arquivo.endswith(".txt"):
		with open(nome_arquivo,"r") as file:
			for Hashes in file:
				formatadas = Hashes.replace("\n","")
				if formatadas not in wordlist_hashes:
					wordlist_hashes.append(formatadas)
		file.close()
	else:
		print("Insira um .txt no final do nome do arquivo!\n")
		raise SystemExit

# coletando o tipo da hash
if entrada_user == "1":
	hash_user = str(input("Hash: ")).strip()
	start = datetime.datetime.now()
	print("\n\033[1m@ Start in {}\033[m\n".format(start))
	print("\033[1m[\033[1;32m + \033[m\033[1m]\033[m \033[1mIdentificando hash...\033[m\n")
	tipo_hash = requests.get("https://hashes.com/en/api/identifier?hash={}".format(hash_user))
	tipo_resu = json.loads(tipo_hash.text)
	tipo_pego = tipo_resu["algorithms"][0].lower()

# decripting
if arquivo:
	for HashesInWordlist in wordlist_hashes:
		hash_user = HashesInWordlist
		tipo_hash = requests.get("https://hashes.com/en/api/identifier?hash={}".format(hash_user))
		tipo_resu = json.loads(tipo_hash.text)
		tipo_pego = tipo_resu["algorithms"][0].lower()
		with open("senhas.txt","r") as file:
			for c,x in enumerate(file):
				encrypt1 = x.replace("\n","").strip().encode("utf-8")
				if tipo_pego == "base64 encoded string":
					try:
						resultado = base64.b64decode(hash_user).decode()
					except base64.binascii.Error:
						print("\033[1m[\033[m\033[1;31m!\033[m\033[1m]\033[m\033[1m Hash não encontrada...\033[m")
					else:
						print("\033[1;32mSenha:\033[m \033[1m{}\033[m".format(resultado))
						fim2 = datetime.datetime.now() - start
						print("\033[1;mTempo cracked -->\033[m \033[1;36m{}\033[m\n".format(fim2))
						with open("Decripted.txt","a") as decrypted:
							decrypted.write("{} : {}\n".format(hash_user,resultado))
						decrypted.close()
						finds = True
						break
				elif tipo_pego == "sha1":
					encrypt2 = hashlib.sha1(encrypt1).hexdigest()
					if encrypt2 == hash_user:
						print("\n\033[1;32mSenha:\033[m \033[1m{}\033[m".format(encrypt1.decode()))
						fim2 = datetime.datetime.now() - start
						print("\033[1;mTempo cracked -->\033[m \033[1;36m{}\033[m\n".format(fim2))
						with open("Decripted.txt","a") as decrypted:
							decrypted.write("{} : {}\n".format(hash_user,encrypt1.decode()))
						decrypted.close()
						finds = True
						break
					else:
						print("\033[1;36m[\033[m \033[1m{}\033[m \033[1;36m]\033[m \033[1m-->\033[m \033[1m{}\033[m \033[1;33m[ {} ]\033[m".format(c,encrypt2,tipo_pego.upper()))
				elif tipo_pego == "md5":
					encrypt2 = hashlib.md5(encrypt1).hexdigest()
					if encrypt2 == hash_user:
						print("\n\033[1;32mSenha:\033[m \033[1m{}\033[m".format(encrypt1.decode()))
						fim2 = datetime.datetime.now() - start
						print("\033[1;mTempo cracked -->\033[m \033[1;36m{}\033[m\n".format(fim2))
						with open("Decripted.txt","a") as decrypted:
							decrypted.write("{} : {}\n".format(hash_user,encrypt1.decode()))
						decrypted.close()
						finds = True
						break
					else:
						print("\033[1;36m[\033[m \033[1m{}\033[m \033[1;36m]\033[m \033[1m-->\033[m \033[1m{}\033[m \033[1;33m[ {} ]\033[m".format(c,encrypt2,tipo_pego.upper()))
				elif tipo_pego == "sha256":
					encrypt2 = hashlib.sha256(encrypt1).hexdigest()
					if encrypt2 == hash_user:
						print("\n\033[1;32mSenha:\033[m \033[1m{}\033[m".format(encrypt1.decode()))
						fim2 = datetime.datetime.now() - start
						print("\033[1;mTempo cracked -->\033[m \033[1;36m{}\033[m\n".format(fim2))
						with open("Decripted.txt","a") as decrypted:
							decrypted.write("{} : {}\n".format(hash_user,encrypt1.decode()))
						decrypted.close()
						finds = True
						break
					else:
						print("\033[1;36m[\033[m \033[1m{}\033[m \033[1;36m]\033[m \033[1m-->\033[m \033[1m{}\033[m \033[1;33m[ {} ]\033[m".format(c,encrypt2,tipo_pego.upper()))
				elif tipo_pego == "sha384":
					encrypt2 = hashlib.sha384(encrypt1).hexdigest()
					if encrypt2 == hash_user:
						print("\n\033[1;32mSenha:\033[m \033[1m{}\033[m".format(encrypt1.decode()))
						fim2 = datetime.datetime.now() - start
						print("\033[1;mTempo cracked -->\033[m \033[1;36m{}\033[m\n".format(fim2))
						with open("Decripted.txt","a") as decrypted:
							decrypted.write("{} : {}\n".format(hash_user,encrypt1.decode()))
						decrypted.close()
						finds = True
						break
					else:
						print("\033[1;36m[\033[m \033[1m{}\033[m \033[1;36m]\033[m \033[1m-->\033[m \033[1m{}\033[m \033[1;33m[ {} ]\033[m".format(c,encrypt2,tipo_pego.upper()))
				elif tipo_pego == "sha3-224":
					encrypt2 = hashlib.sha224(encrypt1).hexdigest()
					if encrypt2 == hash_user:
						print("\n\033[1;32mSenha:\033[m \033[1m{}\033[m".format(encrypt1.decode()))
						fim2 = datetime.datetime.now() - start
						print("\033[1;mTempo cracked -->\033[m \033[1;36m{}\033[m\n".format(fim2))
						with open("Decripted.txt","a") as decrypted:
							decrypted.write("{} : {}\n".format(hash_user,encrypt1.decode()))
						decrypted.close()
						finds = True
						break
					else:
						print("\033[1;36m[\033[m \033[1m{}\033[m \033[1;36m]\033[m \033[1m-->\033[m \033[1m{}\033[m \033[1;33m[ {} ]\033[m".format(c,encrypt2,tipo_pego.upper()))
				elif tipo_pego == "sha512":
					encrypt2 = hashlib.sha512(encrypt1).hexdigest()
					if encrypt2 == hash_user:
						print("\n\033[1;32mSenha:\033[m \033[1m{}\033[m".format(encrypt1.decode()))
						fim2 = datetime.datetime.now() - start
						print("\033[1;mTempo cracked -->\033[m \033[1;36m{}\033[m\n".format(fim2))
						with open("Decripted.txt","a") as decrypted:
							decrypted.write("{} : {}\n".format(hash_user,encrypt1.decode()))
						decrypted.close()
						finds = True
						break
					else:
						print("\033[1;36m[\033[m \033[1m{}\033[m \033[1;36m]\033[m \033[1m-->\033[m \033[1m{}\033[m \033[1;33m[ {} ]\033[m".format(c,encrypt2,tipo_pego.upper()))
			file.close()
else:
	with open("senhas.txt","r") as file:
		for c,x in enumerate(file):
			encrypt1 = x.replace("\n","").strip().encode("utf-8")
			if tipo_pego == "sha1":
				encrypt2 = hashlib.sha1(encrypt1).hexdigest()
				if encrypt2 == hash_user:
					print("\n\033[1;32mSenha:\033[m \033[1m{}\033[m".format(encrypt1.decode()))
					fim2 = datetime.datetime.now() - start
					print("\033[1;mTempo cracked -->\033[m \033[1;36m{}\033[m\n".format(fim2))
					sys.exit()
				else:
					print("\033[1;36m[\033[m \033[1m{}\033[m \033[1;36m]\033[m \033[1m-->\033[m \033[1m{}\033[m \033[1;33m[ {} ]\033[m".format(c,encrypt2,tipo_pego.upper()))
			elif tipo_pego == "md5":
				encrypt2 = hashlib.md5(encrypt1).hexdigest()
				if encrypt2 == hash_user:
					print("\n\033[1;32mSenha:\033[m \033[1m{}\033[m".format(encrypt1.decode()))
					fim2 = datetime.datetime.now() - start
					print("\033[1;mTempo cracked -->\033[m \033[1;36m{}\033[m\n".format(fim2))
					sys.exit()
				else:
					print("\033[1;36m[\033[m \033[1m{}\033[m \033[1;36m]\033[m \033[1m-->\033[m \033[1m{}\033[m \033[1;33m[ {} ]\033[m".format(c,encrypt2,tipo_pego.upper()))
			elif tipo_pego == "sha256":
				encrypt2 = hashlib.sha256(encrypt1).hexdigest()
				if encrypt2 == hash_user:
					print("\n\033[1;32mSenha:\033[m \033[1m{}\033[m".format(encrypt1.decode()))
					fim2 = datetime.datetime.now() - start
					print("\033[1;mTempo cracked -->\033[m \033[1;36m{}\033[m\n".format(fim2))
					sys.exit()
				else:
					print("\033[1;36m[\033[m \033[1m{}\033[m \033[1;36m]\033[m \033[1m-->\033[m \033[1m{}\033[m \033[1;33m[ {} ]\033[m".format(c,encrypt2,tipo_pego.upper()))
			elif tipo_pego == "sha384":
				encrypt2 = hashlib.sha384(encrypt1).hexdigest()
				if encrypt2 == hash_user:
					print("\n\033[1;32mSenha:\033[m \033[1m{}\033[m".format(encrypt1.decode()))
					fim2 = datetime.datetime.now() - start
					print("\033[1;mTempo cracked -->\033[m \033[1;36m{}\033[m\n".format(fim2))
					sys.exit()
				else:
					print("\033[1;36m[\033[m \033[1m{}\033[m \033[1;36m]\033[m \033[1m-->\033[m \033[1m{}\033[m \033[1;33m[ {} ]\033[m".format(c,encrypt2,tipo_pego.upper()))
			elif tipo_pego == "sha3-224":
				encrypt2 = hashlib.sha224(encrypt1).hexdigest()
				if encrypt2 == hash_user:
					print("\n\033[1;32mSenha:\033[m \033[1m{}\033[m".format(encrypt1.decode()))
					fim2 = datetime.datetime.now() - start
					print("\033[1;mTempo cracked -->\033[m \033[1;36m{}\033[m\n".format(fim2))
					sys.exit()
				else:
					print("\033[1;36m[\033[m \033[1m{}\033[m \033[1;36m]\033[m \033[1m-->\033[m \033[1m{}\033[m \033[1;33m[ {} ]\033[m".format(c,encrypt2,tipo_pego.upper()))
			elif tipo_pego == "sha512":
				encrypt2 = hashlib.sha512(encrypt1).hexdigest()
				if encrypt2 == hash_user:
					print("\n\033[1;32mSenha:\033[m \033[1m{}\033[m".format(encrypt1.decode()))
					fim2 = datetime.datetime.now() - start
					print("\033[1;mTempo cracked -->\033[m \033[1;36m{}\033[m\n".format(fim2))
					sys.exit()
				else:
					print("\033[1;36m[\033[m \033[1m{}\033[m \033[1;36m]\033[m \033[1m-->\033[m \033[1m{}\033[m \033[1;33m[ {} ]\033[m".format(c,encrypt2,tipo_pego.upper()))
		file.close()
# final
if not finds:
	fim = datetime.datetime.now() - start
	print("\n\033[1m[\033[m\033[1;31m!\033[m\033[1m]\033[m \033[1m Não Encontrado!\033[m")
	print("\033[1m[\033[m\033[1;31m#\033[m\033[1m]\033[1;m Tempo -->\033[m \033[1;36m{}\033[m\n".format(fim))
