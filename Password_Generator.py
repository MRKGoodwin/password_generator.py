''' Build a password generator that inputs the amount of max and min charaters
and prints random numbers in between the amountand uses at least one capitol letter,
lowercase letter, at least 3 numbers, and special charaters.
'''

import os
import random
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


password1 = b'YouShallNotPass!$'
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000,
)
key = base64.urlsafe_b64encode(kdf.derive(password1))
key_return = Fernet(key)

def generator():
    '''
    Generator is a random password generator based on user input
    '''
    # characters used for password input based on user input.
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    maxcharacter = int(input("Enter amout of Max Charaters: "))
    mincharacter = int(input("Enter amount of Min Charaters: "))
    numbersstr = "0123456789"
    special = ",\"!@#$%^&*()_+}{|:|\"<>?~`"
    upperalphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    #Base list of options in a 2d sequence to stack for password
    useable_options = [list(alphabet),]
    yesvalues = ["yes", "Yes", "yeah", "ok", "okay","y"]
    spcharacter = (input("Are special Charaters required?: "))
    if spcharacter.lower() in yesvalues:
        useable_options.append(list(special))

    numbers = (input("Are numbers required?: "))
    if numbers.lower() in yesvalues:
        useable_options.append(list(numbersstr))

    upper_case_char = (input("Are capitol letter required?: "))
    if upper_case_char.lower() in yesvalues:
        useable_options.append(list(upperalphabet))

    passwordstrlen = random.randrange(mincharacter, maxcharacter)
    # flattening list to 1d to make it easier for pull stack
    flattened_list = sum(useable_options, [])
    password = ""
    for dpass in range(passwordstrlen):
        password += (random.choice(flattened_list))
    # print(password)
    return password
class Burner:
    def __init__(self) -> None:
        pass
        
    def enctyption():
        site_input = (input('Enter site name: ',))
        outside_password = generator()
        site_input_byte = bytes(site_input, 'utf-8')
        #Symetric encryption for password

        #encrypts password into file
        bytepass = bytes(outside_password, 'utf-8')
        token = key_return.encrypt(bytepass)

        with open('pwd.csv', 'a', encoding='utf-8') as pfcsv:
            pfcsv.write(f'{site_input_byte}, {token}\n')

        #decrypts password from file
        dectoken = key_return.decrypt(token)

        with open("pfile.txt", "w", encoding='utf-8') as pfile1:
            key_return.encrypt(b'pfile1')
            pfile1.write(f'token{token}, {key_return}')
        return

    def main():
        print(key_return)
        gen_run = input("Would you like to create or retrieve? ")
        create_ = "create"

        if gen_run in create_:
            enctyption()
        
        else :
            site_input = (input('Enter site name: ',))
            with open('pwd.csv','r', encoding='utf-8') as read_csv:
                line = read_csv
                for line in read_csv:
                
                    if line.startswith(f'b\'{site_input}\''):
                        fresh_cut = line.split('b\'')
                        cut_decrypt = bytes(fresh_cut[2], 'utf-8')
            with open('pfile.txt', 'r', encoding='utf-8') as read_pfile:
                pline = read_pfile
                for pline in read_pfile:
                    if pline.startswith(f'tokenb\'{}\''):
                        pass
                    
                        print_output = key_return.decrypt(cut_decrypt)
                        print(print_output)

                        # print(cut_decrypt)
                        # print(fresh_cut)

    if __name__ == "__main__":
        main()