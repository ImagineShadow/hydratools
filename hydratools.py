#Libraries
try:
    import datetime
    import time
    import hashlib,base64
    import os,platform,sys,time
except:
    print '[-] Importing library failed !'
    quit()

# Encryption Hash Functions
def MD5():
    hash_md5 = hashlib.md5(password).hexdigest()
    return hash_md5

def SHA1():
    hash_sha1 = hashlib.sha1(password).hexdigest()
    return hash_sha1

def  SHA224():
    hash_sha224 = hashlib.sha224(password).hexdigest()
    return hash_sha224

def SHA256():
    hash_sha256 = hashlib.sha256(password).hexdigest()
    return hash_sha256

def SHA384():
    hash_sha384 = hashlib.sha384(password).hexdigest()
    return hash_sha384

def SHA512():
    hash_sha512 = hashlib.sha512(password).hexdigest()
    return hash_sha512

def whirlpool():
    hash_whirlpool = hashlib.new('whirlpool')
    hash_whirlpool.update(password)
    hash_whirlpool = hash_whirlpool.hexdigest()
    return hash_whirlpool

def ripemd160():
   hash_ripemd160 = hashlib.new('ripemd160')
   hash_ripemd160.update(password)
   hash_ripemd160 = hash_ripemd160.hexdigest()
   return hash_ripemd160

def MD4():
    hash_md4 = hashlib.new('md4')
    hash_md4.update(password)
    hash_md4 = hash_md4.hexdigest()
    return hash_md4
#here
#make md4 cracker.
def MD5rev():
    hash_md5rev = hashlib.md5(password).hexdigest()
    hash_md5rev = hash_md5rev[::-1]
    return hash_md5rev

def encode_base64():
    encoded = str(base64.b64encode(password))
    return encoded

# Decryption Hash Functions

def crack_md5():
    print ''
    counter = 1
    lines = 0
    hash_input = raw_input('Enter your Hash : ')
    if len(hash_input) == 32:
        print ''
        listpath = raw_input('Enter your wordlist path : ')
        print ''
        try:
            passwdlist = open(listpath,'r')
        except:
            print '\n[-] File not found !'
            quit()
        with open(listpath,'r') as file:
            for line in file:
                wordlst = line.split()
                lines += 1
        print '[+] Loaded passwords :',lines,'\n'
        timer1 = datetime.datetime.now()
        timer1sec = timer1.second
        timer1mili = timer1.microsecond
        for brute in passwdlist:
            password = hashlib.md5(brute.strip()).hexdigest()
            counter += 1
            z = brute.replace('\n', '')
            sys.stdout.write("\r[*] Trying Password ... : " + str(z))
            sys.stdout.flush()
            if hash_input == password:
                timer2 = datetime.datetime.now()
                timer2sec = timer2.second
                timer2mili = timer2.microsecond
                if timer2sec > timer1sec:
                    timesec = timer2sec - timer1sec
                else:
                    timesec = timer1sec - timer2sec
                if timer2mili > timer1mili:
                    timemili = timer2mili - timer1mili
                else:
                    timemili = timer1mili - timer2mili
                time = str(timesec)+'.'+str(timemili)
                print '\n\n[+] Password cracked successfully in ('+time+') second !\n'
                print '[+] Password :',brute
                break
        else:
            print '\n\n[-] Password not found !'
    else:
        print '\n\n[-] Invalid Hash !'

def crack_md5rev():
    print ''
    counter = 1
    lines = 0
    hash_input = raw_input('Enter your Hash : ')
    if len(hash_input) == 32:
        hash_input = hash_input[::-1]
        print ''
        listpath = raw_input('Enter your wordlist path : ')
        print ''
        try:
            passwdlist = open(listpath,'r')
        except:
            print '\n[-] File not found !'
            quit()
        with open(listpath,'r') as file:
            for line in file:
                wordlst = line.split()
                lines += 1
        print '[+] Loaded passwords :',lines,'\n'
        timer1 = datetime.datetime.now()
        timer1sec = timer1.second
        timer1mili = timer1.microsecond
        for brute in passwdlist:
            password = hashlib.md5(brute.strip()).hexdigest()
            counter += 1
            z = brute.replace('\n', '')
            sys.stdout.write("\r[*] Trying Password ... : " + str(z))
            sys.stdout.flush()
            if hash_input == password:
                timer2 = datetime.datetime.now()
                timer2sec = timer2.second
                timer2mili = timer2.microsecond
                if timer2sec > timer1sec:
                    timesec = timer2sec - timer1sec
                else:
                    timesec = timer1sec - timer2sec
                if timer2mili > timer1mili:
                    timemili = timer2mili - timer1mili
                else:
                    timemili = timer1mili - timer2mili
                time = str(timesec)+'.'+str(timemili)
                print '\n\n[+] Password cracked successfully in ('+time+') second !\n'
                print '[+] Password :',brute
                break
        else:
            print '\n\n[-] Password not found !'
    else:
        print '\n\n[-] Invalid Hash !'

def crack_sha1():
    print ''
    counter = 1
    lines = 0
    hash_input = raw_input('Enter your Hash : ')
    if len(hash_input) == 40:

        print ''
        listpath = raw_input('Enter your wordlist path : ')
        print ''
        try:
            passwdlist = open(listpath,'r')
        except:
            print '\n[-] File not found !'
            quit()
        with open(listpath,'r') as file:
            for line in file:
                wordlst = line.split()
                lines += 1
        print '[+] Loaded passwords :',lines,'\n'
        timer1 = datetime.datetime.now()
        timer1sec = timer1.second
        timer1mili = timer1.microsecond
        for brute in passwdlist:
            password = hashlib.sha1(brute.strip()).hexdigest()
            counter += 1
            z = brute.replace('\n', '')
            sys.stdout.write("\r[*] Trying Password ... : " + str(z))
            sys.stdout.flush()
            if hash_input == password:
                timer2 = datetime.datetime.now()
                timer2sec = timer2.second
                timer2mili = timer2.microsecond
                if timer2sec > timer1sec:
                    timesec = timer2sec - timer1sec
                else:
                    timesec = timer1sec - timer2sec
                if timer2mili > timer1mili:
                    timemili = timer2mili - timer1mili
                else:
                    timemili = timer1mili - timer2mili
                time = str(timesec)+'.'+str(timemili)
                print ''
                print '\n[+] Password cracked successfully in ('+time+') second !\n'
                print '[+] Password :',brute
                break
        else:
            print '\n\n[-] Password not found !'
    else:
        print '\n\n[-] Invalid Hash !'


def crack_sha224():
    print ''
    counter = 1
    lines = 0
    hash_input = raw_input('Enter your Hash : ')
    if len(hash_input) == 56:
        print ''
        listpath = raw_input('Enter your wordlist path : ')
        print ''
        try:
            passwdlist = open(listpath,'r')
        except:
            print '\n[-] File not found !'
            quit()
        with open(listpath,'r') as file:
            for line in file:
                wordlst = line.split()
                lines += 1
        print '[+] Loaded passwords :',lines,'\n'
        timer1 = datetime.datetime.now()
        timer1sec = timer1.second
        timer1mili = timer1.microsecond
        for brute in passwdlist:
            password = hashlib.sha224(brute.strip()).hexdigest()
            counter += 1
            z = brute.replace('\n', '')
            sys.stdout.write("\r[*] Trying Password ... : " + str(z))
            sys.stdout.flush()
            if hash_input == password:
                timer2 = datetime.datetime.now()
                timer2sec = timer2.second
                timer2mili = timer2.microsecond
                if timer2sec > timer1sec:
                    timesec = timer2sec - timer1sec
                else:
                    timesec = timer1sec - timer2sec
                if timer2mili > timer1mili:
                    timemili = timer2mili - timer1mili
                else:
                    timemili = timer1mili - timer2mili
                time = str(timesec)+'.'+str(timemili)
                print ''
                print '\n[+] Password cracked successfully in ('+time+') second !\n'
                print '[+] Password :',brute
                break
        else:
            print '\n\n[-] Password not found !' 
    else:
        print '\n\n[-] Invalid Hash !'

def crack_sha256():
    print ''
    counter = 1
    lines = 0
    hash_input = raw_input('Enter your Hash : ')
    if len(hash_input) == 64:
        print ''
        listpath = raw_input('Enter your wordlist path : ')
        print ''
        try:
            passwdlist = open(listpath,'r')
        except:
            print '\n[-] File not found !'
            quit()
        with open(listpath,'r') as file:
            for line in file:
                wordlst = line.split()
                lines += 1
        print '[+] Loaded passwords :',lines,'\n'
        timer1 = datetime.datetime.now()
        timer1sec = timer1.second
        timer1mili = timer1.microsecond
        for brute in passwdlist:
            password = hashlib.sha256(brute.strip()).hexdigest()
            counter += 1
            z = brute.replace('\n', '')
            sys.stdout.write("\r[*] Trying Password ... : " + str(z))
            sys.stdout.flush()
            if hash_input == password:
                timer2 = datetime.datetime.now()
                timer2sec = timer2.second
                timer2mili = timer2.microsecond
                if timer2sec > timer1sec:
                    timesec = timer2sec - timer1sec
                else:
                    timesec = timer1sec - timer2sec
                if timer2mili > timer1mili:
                    timemili = timer2mili - timer1mili
                else:
                    timemili = timer1mili - timer2mili
                time = str(timesec)+'.'+str(timemili)
                print ''
                print '\n[+] Password cracked successfully in ('+time+') second !\n'
                print '[+] Password :',brute
                break
        else:
            print '\n\n[-] Password not found !'
    else:
        print '\n\n[-] Invalid Hash !'


def crack_sha384():
    print ''
    counter = 1
    lines = 0
    hash_input = raw_input('Enter your Hash : ')
    if len(hash_input) == 96:
        print ''
        listpath = raw_input('Enter your wordlist path : ')
        print ''
        try:
            passwdlist = open(listpath,'r')
        except:
            print '\n[-] File not found !'
            quit()
        with open(listpath,'r') as file:
            for line in file:
                wordlst = line.split()
                lines += 1
        print '[+] Loaded passwords :',lines,'\n'
        timer1 = datetime.datetime.now()
        timer1sec = timer1.second
        timer1mili = timer1.microsecond
        for brute in passwdlist:
            password = hashlib.sha384(brute.strip()).hexdigest()
            counter += 1
            z = brute.replace('\n', '')
            sys.stdout.write("\r[*] Trying Password ... : " + str(z))
            sys.stdout.flush()
            if hash_input == password:
                timer2 = datetime.datetime.now()
                timer2sec = timer2.second
                timer2mili = timer2.microsecond
                if timer2sec > timer1sec:
                    timesec = timer2sec - timer1sec
                else:
                    timesec = timer1sec - timer2sec
                if timer2mili > timer1mili:
                    timemili = timer2mili - timer1mili
                else:
                    timemili = timer1mili - timer2mili
                time = str(timesec)+'.'+str(timemili)
                print ''
                print '\n[+] Password cracked successfully in ('+time+') second !\n'
                print '[+] Password :',brute
                break
        else:
            print '\n\n[-] Password not found !'
    else:
        print '\n\n[-] Invalid Hash !'
def crack_sha512():
    print ''
    counter = 1
    lines = 0
    hash_input = raw_input('Enter your Hash : ')
    if len(hash_input) == 128:
        print ''
        listpath = raw_input('Enter your wordlist path : ')
        print ''
        try:
            passwdlist = open(listpath,'r')
        except:
            print '\n[-] File not found !'
            quit()
        with open(listpath,'r') as file:
            for line in file:
                wordlst = line.split()
                lines += 1
        print '[+] Loaded passwords :',lines,'\n'
        timer1 = datetime.datetime.now()
        timer1sec = timer1.second
        timer1mili = timer1.microsecond
        for brute in passwdlist:
            password = hashlib.sha512(brute.strip()).hexdigest()
            counter += 1
            z = brute.replace('\n', '')
            sys.stdout.write("\r[*] Trying Password ... : " + str(z))
            sys.stdout.flush()
            if hash_input == password:
                timer2 = datetime.datetime.now()
                timer2sec = timer2.second
                timer2mili = timer2.microsecond
                if timer2sec > timer1sec:
                    timesec = timer2sec - timer1sec
                else:
                    timesec = timer1sec - timer2sec
                if timer2mili > timer1mili:
                    timemili = timer2mili - timer1mili
                else:
                    timemili = timer1mili - timer2mili
                time = str(timesec)+'.'+str(timemili)
                print ''
                print '\n[+] Password cracked successfully in ('+time+') second !\n'
                print '[+] Password :',brute
                break
        else:
            print '\n\n[-] Password not found !'
    else:
        print '\n\n[-] Invalid Hash !'

def decode_base64():
    print ''
    print "[*] This type of algorithm don't need wordlist !\n"
    hash_input = raw_input('Enter your Hash : ')
    decoded = str(base64.b64decode(hash_input))
    print '\n[+] Password decoded successfully !\n'
    print '[+] Password :',decoded

def identify():
    if len(input_hash) == 32:
        print '\n[+] MD5 / MD5 Reverse / MD4'
    elif len(input_hash) == 40:
        print '\n[+] SHA-1 / MySQL5 / Ripemd160'
    elif len(input_hash) == 13:
        print '\n[+] DES(Unix)'
    elif len(input_hash) == 16:
        print '\n[+] MySQL / DES(Oracle Hash)'
    elif len(input_hash) == 41 & input_hash.startswith('*'):
        print '\n[+] MySQL5'
    elif len(input_hash) == 64:
        print '\n[+] SHA-256'
    elif len(input_hash) == 56:
        print '\n[+] SHA-224'
    elif len(input_hash) == 96:
        print '\n[+] SHA-384 / SHA-384(HMAC)'
    elif len(input_hash) == 128:
        print '\n[+] SHA-512 / Whirlpool'
    elif len(input_hash) == 34 & input_hash.startswith('$1$'):
        print '\n[+] MD5(Unix)'
    elif len(input_hash) == 37 & input_hash.startswith('$apr1$'):
        print '\n[+] MD5(APR)'
    elif len(input_hash) == 34 & input_hash.startswith('$H$'):
        print '\n[+] MD5(phpBB3)'
    elif len(input_hash) == 34 & input_hash.startswith('$P$'):
        print '\n[+] MD5(Wordpress)'
    elif len(input_hash) == 39 & input_hash.startswith('$5$'):
        print '\n[+] SHA-256(Unix)'
    elif len(input_hash) == 39 & input_hash.startswith('$6$'):
        print '\n[+] SHA-512(Unix)'
    elif len(input_hash) == 24 & input_hash.endswith('=='):
        print '\n[+] MD5(Base-64)'
    elif len(input_hash) == 28 & input_hash.endswith('='):
        print '\n[+] SHA-1(Base-64)'
    elif len(input_hash) == 40 & input_hash.endswith('=='):
        print '\n[+] SHA-224(Base-64)'
    elif len(input_hash) == 88 & input_hash.endswith('=='):
        print '\n[+] SHA-512(Base-64)'
    elif len(input_hash) == 44 & input_hash.endswith('='):
        print '\n[+] SHA-256(Base-64)'
    else:
        print '\n[-] Invalid Input/ Unidentified'

plat = str(platform.platform())
if plat.startswith('Linux'):
    os.system('reset')
else:
    os.system('cls')

author ='''
  _    _           _             _______          _     
 | |  | |         | |           |__   __|        | |    
 | |__| |_   _  __| |_ __ __ _     | | ___   ___ | |___ 
 |  __  | | | |/ _` | '__/ _` |    | |/ _ \ / _ \| / __|
 | |  | | |_| | (_| | | | (_| |    | | (_) | (_) | \__ \ 
 |_|  |_|\__, |\__,_|_|  \__,_|    |_|\___/ \___/|_|___/
          __/ |                                         
         |___/                                         by GoldenEagle from Sec World team
                                                       Autor: @UnknownBlackHat
                                                       Channel: @Sec_World
'''
print author
print '''  Select your option from the menu : \n
    1) Encryption
    2) Decryption
    3) Hash Identifier\n
    0) Exit\n\n'''
option = raw_input('Hydra >> ')
print ''
print ''
if option == '1':
    print '  1) Password Encryptor\n'
    print '  0) Exit\n'
    option = raw_input('Hydra (Encryption) >> ' )
    print ''
    if option == '1':
        password = raw_input('Enter your password : ')
        if option == '1':
            print '''  \n\nSelect your Hash Algorithm :\n
    1) MD4
    2) MD5
    3) MD5 Reverse
    4) SHA-1
    5) SHA-224
    6) SHA-256
    7) SHA-384
    8) SHA-512
    9) ripemd160
    10) whirlpool
    11) Base64
    99) All algorithm\n
    0) Exit\n'''
            select_hash = raw_input('Hydra (Password Encryptor) >> ' )
            if select_hash == '1':
                print '\n[+] Your password in MD4 algorithm is : ',MD4()
            elif select_hash == '2':
                print '\n[+] Your password in MD5 algorithm is : ',MD5()
            elif select_hash == '3':
                print '\n[+] Your password in MD5 Reverse algorithm is : ',MD5rev()
            elif select_hash == '4':
                print '\n[+] Your password in SHA-1 algorithm is : ',SHA1()
            elif select_hash == '5':
                print '\n[+] Your password in SHA-224 algorithm is : ',SHA224()
            elif select_hash == '6':
                print '\n[+] Your password in SHA-256 algorithm is : ',SHA256()
            elif select_hash == '7':
                print '\n[+] Your password in SHA-384 algorithm is : ',SHA384()
            elif select_hash == '8':
                print '\n[+] Your password in SHA-512 algorithm is : ',SHA512()
            elif select_hash == '9':
                print '\n[+] Your password in ripemd160 algorithm is : ',ripemd160()
            elif select_hash == '10':
                print '\n[+] Your password in whirlpool algorithm is : ',whirlpool()
            elif select_hash == '11':
                print '\n[+] Your password in Base64 algorithm is : ',encode_base64()
            elif select_hash == '99':
                print '''\n[+] Your password in MD4 algorithm is : {}
\n[+] Your password in MD5 algorithm is : {}
\n[+] Your password in MD5 Reverse algorithm is : {}
\n[+] Your password in SHA-1 algorithm is : {}
\n[+] Your password in SHA-224 algorithm is : {}
\n[+] Your password in SHA-256 algorithm is : {}
\n[+] Your password in SHA-384 algorithm is : {}
\n[+] Your password in SHA-512 algorithm is : {}
\n[+] Your password in ripemd160 algorithm is : {}
\n[+] Your password in whirlpool algorithm is : {}
\n[+] Your password in Base64 algorithm is : {}'''.format(MD4(),MD5(),MD5rev(),SHA1(),SHA224(),SHA256(),SHA384(),SHA512(),ripemd160(),whirlpool(),encode_base64())
            elif select_hash == '0':
                print '[*] Exiting...'
                quit()

            else:
                print '\n[-] Invalid input'
                quit()

        else:
            print '\n[-] Invalid input'
            quit()

    elif option == '0':
        print '[*] Exiting...'
        quit()
    else:
        print '\n[-] Invalid input'
        quit()

elif option == '2':
    print '    1) Hash Decryptor\n'
    print '    0) Exit\n\n'
    option = raw_input('Hydra (Decryption) >> ' )
    print ''
    if option == '1':
        print '''
  Select your Hash Algorithm :\n
    1) MD5
    2) MD5 Reverse
    3) SHA-1
    4) SHA-224
    5) SHA-256
    6) SHA-384
    7) SHA-512
    8) Base64\n
    0) Exit\n'''
        select_hash = raw_input('Hydra (Hash Decryptor) >> ' )

        if select_hash == '1':
            crack_md5()

        elif select_hash == '2':
            crack_md5rev()

        elif select_hash == '3':
            crack_sha1()

        elif select_hash == '4':
            crack_sha224()

        elif select_hash == '5':
            crack_sha256()

        elif select_hash == '6':
            crack_sha384()

        elif select_hash == '7':
            crack_sha512()

        elif select_hash == '8':
            decode_base64()

        elif select_hash == '0':
            print '[*] Exiting...'
            quit()

        else:
            print '\n[-] Invalid input'
            quit()
    elif option == '0':
        print '[*] Exiting...'
        quit()

    else:
        print '\n[-] Invalid input'
        quit()

elif option == '3':
    input_hash = raw_input('Enter your Hash : ')
    identify()

elif option == '0':
    print '[*] Exiting...'
    quit()

else:
    print '\n[-] Invalid input' 
    quit()