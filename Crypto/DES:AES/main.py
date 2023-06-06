from Des import DES
from Aes import AES
import time


while True:
    print("CHOOSE ENCRYPTION STANDART:\n 1 - DES\n 2 - AES\n 0 - Exit\n")
    option = int(input("Enter option: "))
    if option == 0:
        print('\nExit.')
        time.sleep(2.0)
        break
    elif option == 1:
        my_des = DES()
        DES.menu(my_des)
    elif option == 2:
        key = bytes(input('Enter master key for AES (16 bytes): '), 'utf-8')
        aes = AES(key)
        AES.menu(aes)
