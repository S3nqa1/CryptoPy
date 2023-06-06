import string
import random


data = [string.ascii_uppercase, string.ascii_lowercase, string.digits, string.punctuation]

CheckOptions = {"Len": False,
                "Upercase": False,
                "Lowercase": False,
                "Digits": False,
                "Punctuation": False,
                "Stability": False,
                }


def keygen(l):
    keyData = data[0] + data[1] + data[2] + data[3]
    finalString = ""
    for i in range(0, l):
        index = random.randint(0, len(keyData)-1)
        finalString += keyData[index]
    return finalString


def keyCheck(l):
    key = keygen(l)
    def checkkk(input):
        for i in range(len(input)):
            if input[i] in key:
                return True
        return False

    A = len(string.ascii_letters + string.digits + string.punctuation)
    S = A**l
    V = 100 * 12
    T = 12
    P = 1/(10)**4

    S_ = round(V*T*(10**4))


    if len(key) >= 8:
        CheckOptions["Len"] = True

    CheckOptions["Upercase"] = checkkk(data[0])
    CheckOptions["Lowercase"] = checkkk(data[1])
    CheckOptions["Digits"] = checkkk(data[2])
    CheckOptions["Punctuation"] = checkkk(data[3])

    if S_ <= S:
        CheckOptions["Stability"] = True
    else:
        recomL = l
        expextS = S
        while S_ >= expextS:
            expextS = A**recomL
            recomL += 1
        CheckOptions["Stability"] = "recomend len " + str(recomL)

    return key




while True:
    print("Menu\n1 - Generate key\n0 - Exit")
    option = int(input("Enter option:"))

    if option == 1:

        l = int(input("Enter key lenght = "))
        key = keyCheck(l)
        
        print(f"KEY --> {key}")
        print(CheckOptions)

        
    if option == 0:
        print("EXITING")
        break



