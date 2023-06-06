import time

n = int(input('Enter:'))
while True:
    if n % 2 == 0:
        n = n / 2
    else:
        n = n* 3 +1
    time.sleep(0.5)
    print(n)