from cryptography.fernet import Fernet
import shutil
import os
import easygui
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def kfp(password):
    return Fernet(base64.urlsafe_b64encode(PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        iterations=100000,
    ).derive(password)))

def encrypt_file(filenames, params):
    encryption_password = easygui.passwordbox(msg='Enter encryption password', title='FileLocker').encode('utf-8')
    try:
        fern = kfp(encryption_password)
        for file in filenames:
            to_enc = open(file, 'rb')
            enc_this = open(file+'.filelock', 'wb')

            while True:
                data = to_enc.read(65536)
                if len(data) == 0:
                    break

                enc_this.write(base64.b64encode(fern.encrypt(data)))
            to_enc.close()
            enc_this.close()
            os.remove(file)
    except:
        easygui.exceptionbox()

def decrypt_file(filenames, params):
    encryption_password = easygui.passwordbox(msg='Enter decryption password', title='FileLocker').encode('utf-8')
    try:
        fern = kfp(encryption_password)
        for file in filenames:
            to_dec = open(file, 'rb')
            dec_this = open(file.split('.filelock')[0], 'wb')

            while True:
                data = to_dec.read(65536)
                if len(data) == 0:
                    break

                dec_this.write(fern.decrypt(base64.b64decode(data)))
            to_dec.close()
            dec_this.close()
            os.remove(file)
    except:
        easygui.exceptionbox()

def encrypt_folder(filenames, params):
    print(filenames)
    encryption_password = easygui.passwordbox(msg='Enter encryption password', title='FileLocker').encode('utf-8')
    try:
        fern = kfp(encryption_password)
        for file in filenames:
            shutil.make_archive(file, format='zip', root_dir=file)
            shutil.rmtree(file)
            to_enc = open(file.rstrip(os.sep)+'.zip', 'rb')
            enc_this = open(file.rstrip(os.sep)+'.dirlock', 'wb')

            while True:
                data = to_enc.read(65536)
                if len(data) == 0:
                    break

                enc_this.write(base64.b64encode(fern.encrypt(data)))
            to_enc.close()
            enc_this.close()
            os.remove(file.rstrip(os.sep)+'.zip')
    except:
        easygui.exceptionbox()

def decrypt_folder(filenames, params):
    encryption_password = easygui.passwordbox(msg='Enter decryption password', title='FileLocker').encode('utf-8')
    try:
        fern = kfp(encryption_password)
        for file in filenames:
            to_dec = open(file, 'rb')
            dec_this = open(file.split('.dirlock')[0]+'.zip', 'wb')

            while True:
                data = to_dec.read(65536)
                if len(data) == 0:
                    break

                dec_this.write(fern.decrypt(base64.b64decode(data)))
            to_dec.close()
            dec_this.close()
            os.remove(file)
            shutil.unpack_archive(file.split('.dirlock')[0]+'.zip', format='zip', extract_dir=file.split('.dirlock')[0])
            os.remove(file.split('.dirlock')[0]+'.zip')
    except:
        easygui.exceptionbox()