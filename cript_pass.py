from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import tkinter as tk
from tkinter import filedialog


class MyCript:
    def __init__(self) -> None:
        pass

    def get_directory(self) -> str:
        root = tk.Tk()
        root.withdraw()  # Esconde a janela principal
        dir_path = filedialog.askdirectory()
        return str(dir_path)

    def do_cript(self):
        print("Escolha um senha para a criptografia")
        passw = input("Senha: ").encode("utf-8")
        salt_cript = os.urandom(16)

        # Usar PBKDF2 para gerar uma chave a partir da senha
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_cript,
            iterations=100000,
            backend=default_backend(),
        )

        # A chave deve ser codificada em base64
        chave = base64.urlsafe_b64encode(kdf.derive(passw))

        cipher_suite = Fernet(chave)

        print("Selecione o diretório onde deseja fazer a criptografia")
        dir_f = self.get_directory()

        for root, dirs, files in os.walk(dir_f):
            for file in files:
                try:
                    file_path = os.path.join(root, file)

                    with open(file_path, "rb") as f:
                        dados = f.read()

                        dados_criptografados = cipher_suite.encrypt(dados)
                        encrypted_file_path = file_path + ".encrypted"

                        with open(encrypted_file_path, "wb") as f:
                            f.write(dados_criptografados)

                        os.remove(file_path)
                except Exception as e:
                    print(f"Erro ao processar o arquivo: {e}")

        # Gen Salt File
        with open("salt.txt", "wb") as f:
            f.write(salt_cript)

    def do_decript(self):
        passw = input("Senha: ").encode("utf-8")

        print("Selecione o diretório do Salt")
        salt_dir = self.get_directory()

        # Ler o salt usado durante a criptografia
        with open(os.path.join(salt_dir, "salt.txt"), "rb") as f:
            salt = f.read()

        # Descriptografar um arquivo
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )

        chave = base64.urlsafe_b64encode(kdf.derive(passw))

        cipher_suite = Fernet(chave)

        print("Selecione o diretório dos arquivos a serem descriptografados")
        dir_f = self.get_directory()

        for root, dirs, files in os.walk(dir_f):
            try:
                for file in files:
                    if file.endswith(".encrypted"):
                        file_path = os.path.join(root, file)
                        with open(file_path, "rb") as f:
                            dados_criptografados = f.read()

                        dados_descriptografados = cipher_suite.decrypt(
                            dados_criptografados
                        )

                        decrypted_file_path = file_path.removesuffix(".encrypted")

                        with open(decrypted_file_path, "wb") as f:
                            f.write(dados_descriptografados)

                        os.remove(file_path)
            except Exception as e:
                print(f"Erro ao processar o arquivo: {e}")


cript = MyCript()
print(
    """

██       ██████   ██████ ██   ██         ██ ███    ██ 
██      ██    ██ ██      ██  ██          ██ ████   ██ 
██      ██    ██ ██      █████           ██ ██ ██  ██ 
██      ██    ██ ██      ██  ██          ██ ██  ██ ██ 
███████  ██████   ██████ ██   ██ ███████ ██ ██   ████ 
                                                      
                                                      
                                                       
"""
)
while True:
    print("1 - Criptografar")
    print("2 - Descriptografar")
    print("3 - Sair\r")
    option = int(input("-> "))
    if option == 1:
        cript.do_cript()
    elif option == 2:
        cript.do_decript()
    elif option == 3:
        break
    else:
        print("Escolha uma opção válida")

# p
