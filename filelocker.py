from cryptography.fernet import Fernet
import shutil
import os
import easygui
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import logging

logging.basicConfig(format='%(filename)s:%(lineno)s:%(levelname)s @ %(asctime)s > %(message)s', level=logging.DEBUG)

def kfp(password):
    return Fernet(base64.urlsafe_b64encode(PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        iterations=100000,
    ).derive(password)))

def encrypt_file(filenames, params):
    logging.info(f'Encrypting files @ {str(filenames)}')
    encryption_password = easygui.passwordbox(msg='Enter encryption password', title='FileLocker').encode('utf-8')
    try:
        fern = kfp(encryption_password)
        logging.info('Generated key from password.')
        for file in filenames:
            to_enc = open(file, 'rb')
            enc_this = open(file+'.filelock', 'wb')

            block_count = 0
            while True:
                data = to_enc.read(1048576)
                if len(data) == 0:
                    break
                
                logging.debug(f'Read block {str(block_count)}')
                enc_this.write(base64.b64encode(fern.encrypt(data))+b'\n')
                block_count += 1
            to_enc.close()
            enc_this.close()
            os.remove(file)
    except:
        easygui.exceptionbox()

def decrypt_file(filenames, params):
    logging.info(f'Decrypting files @ {str(filenames)}')
    encryption_password = easygui.passwordbox(msg='Enter decryption password', title='FileLocker').encode('utf-8')
    try:
        fern = kfp(encryption_password)
        logging.info('Generated key from password.')
        for file in filenames:
            to_dec = open(file, 'rb')
            dec_this = open(file.split('.filelock')[0], 'wb')

            block_count = 0
            while True:
                dat = to_dec.readline()
                if len(dat) == 0:
                    break
                logging.debug(f'Read block {str(block_count)}')
                dec_this.write(fern.decrypt(base64.b64decode(dat)))
                block_count += 1

            to_dec.close()
            dec_this.close()
            os.remove(file)
    except:
        easygui.exceptionbox()

def encrypt_folder(filenames, params):
    logging.info(f'Encrypting folders @ {str(filenames)}')
    encryption_password = easygui.passwordbox(msg='Enter encryption password', title='FileLocker').encode('utf-8')
    try:
        fern = kfp(encryption_password)
        logging.info('Generated key from password.')
        for file in filenames:
            logging.info('Generating temporary archive.')
            shutil.make_archive(file, format='zip', root_dir=file)
            shutil.rmtree(file)
            to_enc = open(file.rstrip(os.sep)+'.zip', 'rb')
            enc_this = open(file.rstrip(os.sep)+'.dirlock', 'wb')

            block_count = 0
            while True:
                data = to_enc.read(1048576)
                if len(data) == 0:
                    break
                
                logging.debug(f'Read block {str(block_count)}')
                enc_this.write(base64.b64encode(fern.encrypt(data))+b'\n')
                block_count += 1
            to_enc.close()
            enc_this.close()
            os.remove(file.rstrip(os.sep)+'.zip')
    except:
        easygui.exceptionbox()

def decrypt_folder(filenames, params):
    logging.info(f'Decrypting folders @ {str(filenames)}')
    encryption_password = easygui.passwordbox(msg='Enter decryption password', title='FileLocker').encode('utf-8')
    try:
        fern = kfp(encryption_password)
        logging.info('Generated key from password.')
        for file in filenames:
            to_dec = open(file, 'rb')
            dec_this = open(file.split('.dirlock')[0]+'.zip', 'wb')

            block_count = 0
            while True:
                dat = to_dec.readline()
                if len(dat) == 0:
                    break
                logging.debug(f'Read block {str(block_count)}')
                dec_this.write(fern.decrypt(base64.b64decode(dat)))
                block_count += 1

            to_dec.close()
            dec_this.close()
            os.remove(file)
            shutil.unpack_archive(file.split('.dirlock')[0]+'.zip', format='zip', extract_dir=file.split('.dirlock')[0])
            os.remove(file.split('.dirlock')[0]+'.zip')
    except:
        easygui.exceptionbox()