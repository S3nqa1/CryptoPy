from PIL import Image
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import time


def convert_to_RGB(data):
    r, g, b = tuple(map(lambda d: [data[i] for i in range(0, len(data)) if i % 3 == d], [0, 1, 2]))
    pixels = tuple(zip(r, g, b))
    return pixels


print('Menu:')
print('Options:\n  1 - AES Encryption\n  2 -  AES Decryption\n  '
      '3 - DES Encryption\n  4 - DES Decryption\n 5 - Encrypt Image\n 6 - Decrypt Image\n  0 - Exit')
while True:
    option = int(input('\nEnter option to choose the action: '))
    if option == 0:
        print('\nExit.')
        break
    elif option == 1:
        key = bytes(input('Enter key (16 bytes): '), 'utf-8')
        mode = str(input('Enter mode (ECB/CBC): '))
        aes = AES.new(key, AES.MODE_ECB)
        if mode == 'ECB':
            aes = AES.new(key, AES.MODE_ECB)
        elif mode == 'CBC':
            iv = bytes(input('Enter initialization vector: '), 'utf-8')
            aes = AES.new(key, AES.MODE_CBC, iv=iv)
        else:
            print('Incorrect value. System exit.')
            SystemExit(0)
        plaintext = open('plaintext.txt', 'r').read().replace('\n', '').replace(' ', '')
        print('File is read! Start encrypting...')
        start = time.time()
        ciphertext = aes.encrypt(pad(bytes(plaintext, 'utf-8'), block_size=16))
        print('Encrypted!\nTime spent: ', time.time() - start)
        with open('encrypted_text_AES.txt', 'w') as f:
            f.write(str(ciphertext))
    elif option == 2:
        key = bytes(input('Enter key (16 bytes): '), 'utf-8')
        mode = str(input('Enter mode (ECB/CBC): '))
        aes = AES.new(key, AES.MODE_ECB)
        if mode == 'ECB':
            aes = AES.new(key, AES.MODE_ECB)
        elif mode == 'CBC':
            iv = bytes(input('Enter initialization vector: '), 'utf-8')
            aes = AES.new(key, AES.MODE_CBC, iv=iv)
        else:
            print('Incorrect value. System exit.')
            SystemExit(0)
        ciphertext = open('encrypted_text_AES.txt', 'r').read()
        print('File is read! Start decrypting...')
        start = time.time()
        plaintext = unpad(aes.decrypt(eval(ciphertext)), block_size=16)
        print('Decrypted!\nTime spent: ', time.time() - start)
        with open('decrypted_text_AES.txt', 'wb') as f:
            f.write(plaintext)
    elif option == 3:
        key = bytes(open('binary_key.txt', 'r').read(), 'utf-8')
        mode = str(input('Enter mode (ECB/CBC): '))
        des = DES.new(key, DES.MODE_ECB)
        if mode == 'ECB':
            des = DES.new(key, DES.MODE_ECB)
        elif mode == 'CBC':
            des = DES.new(key, DES.MODE_CBC)
        plaintext = bytes(open('plaintext.txt', 'r').read().replace('\n', '').replace(' ', ''), 'utf-8')
        start = time.time()
        print('Start: ', start)
        ciphertext = des.encrypt(pad(plaintext, block_size=64))
        ct = b64encode(ciphertext).decode('utf-8')
        print('Time spent: ', time.time() - start)
        with open('encrypted_text_DES.txt', 'w') as f:
            f.write(str(ct))
    elif option == 4:
        key = bytes((open('binary_key.txt', 'r').read()), 'utf-8')
        mode = str(input('Enter mode (ECB/CBC): '))
        des = DES.new(key, DES.MODE_ECB)
        if mode == 'ECB':
            des = DES.new(key, DES.MODE_ECB)
        elif mode == 'CBC':
            des = DES.new(key, DES.MODE_CBC)

        ciphertext = bytes(open('encrypted_text_DES.txt', 'r').read().replace('\n', '').replace(' ', ''), 'utf-8')
        ciphertext = b64decode(ciphertext)
        start = time.time()
        print('Start: ', start)
        plaintext = unpad(des.decrypt(ciphertext), block_size=64)
        print('Time spent: ', time.time() - start)
        with open('decrypted_text_DES.txt', 'w') as f:
            f.write(str(plaintext))
    elif option == 5:
        print("CHOOSE ENCRYPTION STANDART:\n 1 - DES\n 2 - AES\n 0 - Back\n")
        next_option = int(input("enter option:"))
        if next_option == 1:
            key = bytes((open('binary_key.txt', 'r').read()), 'utf-8')
            mode = str(input('Enter mode (ECB/CBC): '))
            des = DES.new(key, DES.MODE_ECB)
            if mode == 'ECB':
                des = DES.new(key, DES.MODE_ECB)
            elif mode == 'CBC':
                des = DES.new(key, DES.MODE_CBC)

            im = Image.open(input("enter image name: "))
            data = im.convert("RGB").tobytes()
            original = len(data)
            start = time.time()
            new = convert_to_RGB(des.encrypt(pad(data, block_size=64))[:original])
            print('Time spent: ', time.time() - start)
            im2 = Image.new(im.mode, im.size)
            im2.putdata(new)
            im2.save("encrypted_image.bmp")
        elif next_option == 2:
            key = bytes(input('Enter key (16 bytes): '), 'utf-8')
            mode = str(input('Enter mode (ECB/CBC): '))
            aes = AES.new(key, AES.MODE_ECB)
            if mode == 'ECB':
                aes = AES.new(key, AES.MODE_ECB)
            elif mode == 'CBC':
                iv = bytes(input('Enter initialization vector: '), 'utf-8')
                aes = AES.new(key, AES.MODE_CBC, iv=iv)

            im = Image.open(input("enter image name: "))
            data = im.convert("RGB").tobytes()
            original = len(data)
            start = time.time()
            new = convert_to_RGB(aes.encrypt(pad(data, block_size=16))[:original])
            print('Time spent: ', time.time() - start)
            im2 = Image.new(im.mode, im.size)
            im2.putdata(new)
            im2.save("encrypted_image.bmp")
        elif next_option == 0:
            print("<----- BACK")
    elif option == 6:
        print("CHOOSE ENCRYPTION STANDART:\n 1 - DES\n 2 - AES\n 0 - Back\n")
        next_option = int(input("enter option:"))
        if next_option == 1:
            key = bytes((open('binary_key.txt', 'r').read()), 'utf-8')
            mode = str(input('Enter mode (ECB/CBC): '))
            des = DES.new(key, DES.MODE_ECB)
            if mode == 'ECB':
                des = DES.new(key, DES.MODE_ECB)
            elif mode == 'CBC':
                des = DES.new(key, DES.MODE_CBC)

            im = Image.open(input("enter image name: "))
            data = im.convert("RGB").tobytes()
            original = len(data)
            start = time.time()
            new = convert_to_RGB(des.decrypt(pad(data, block_size=64))[:original])
            print('Time spent: ', time.time() - start)
            im2 = Image.new(im.mode, im.size)
            im2.putdata(new)
            im2.save("decrypted_image.bmp")
        elif next_option == 2:
            key = bytes(input('Enter key (16 bytes): '), 'utf-8')
            mode = str(input('Enter mode (ECB/CBC): '))
            aes = AES.new(key, AES.MODE_ECB)
            if mode == 'ECB':
                aes = AES.new(key, AES.MODE_ECB)
            elif mode == 'CBC':
                iv = bytes(input('Enter initialization vector: '), 'utf-8')
                aes = AES.new(key, AES.MODE_CBC, iv=iv)

            im = Image.open(input("enter image name: "))
            data = im.convert("RGB").tobytes()
            original = len(data)
            start = time.time()
            new = convert_to_RGB(aes.encrypt(pad(data, block_size=64))[:original])
            print('Time spent: ', time.time() - start)
            im2 = Image.new(im.mode, im.size)
            im2.putdata(new)
            im2.save("encrypted_image.bmp")
        elif next_option == 0:
            print("<----- BACK")
    else:
        print('Incorrect value. System exit.')
        SystemExit(0)
