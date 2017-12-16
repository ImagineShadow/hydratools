#Libraries
from colored import fg,bg,attr
import datetime
import time
import hashlib,base64
import os,platform,sys,time

#Funtions
def reset():
    os.system("reset")

def clear():
    os.system("cls")
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
            print '\n%s[-]%s File not found !' % (fg(196),attr(0))
            quit()
        with open(listpath,'r') as file:
            for line in file:
                wordlst = line.split()
                lines += 1
        print '%s[+]%s Loaded passwords :' % (fg(46),attr(0)),lines,'\n'
        timer1 = datetime.datetime.now()
        timer1sec = timer1.second
        timer1mili = timer1.microsecond
        for brute in passwdlist:
            password = hashlib.md5(brute.strip()).hexdigest()
            counter += 1
            z = brute.replace('\n', '')
            sys.stdout.write("\r%s[*]%s Trying Password ... : " % (fg(68),attr(0)) + str(z))
            sys.stdout.flush()
            if hash_input == password:
                timer2 = datetime.datetime.now()
                timer2sec = timer2.second
                timer2mili = timer2.microsecond
                if timer2sec > timer1sec:
                    timesec = timer2sec - timer1sec
                if timer1sec > timer2sec:
                    timesec = timer1sec - timer2sec
                if timer2mili > timer1mili:
                    timemili = timer2mili - timer1mili
                if timer1mili > timer2mili:
                    timemili = timer1mili - timer2mili
                timing = str(timesec)+'.'+str(timemili)
                print ''
                print '\n%s[+]%s Password cracked successfully in' % (fg(46),attr(0)) ,'('+timing+') second !\n'
                print '%s[+]%s Password :' % (fg(46),attr(0)),brute
                break
        else:
            print '\n\n%s[-]%s Password not found !' % (fg(196),attr(0))
    else:
        print '\n\n%s[-]%s Invalid Hash !' % (fg(196),attr(0))

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
            print '\n%s[-]%s File not found !' % (fg(196),attr(0))
            quit()
        with open(listpath,'r') as file:
            for line in file:
                wordlst = line.split()
                lines += 1
        print '%s[+]%s Loaded passwords :' % (fg(46),attr(0)),lines,'\n'
        timer1 = datetime.datetime.now()
        timer1sec = timer1.second
        timer1mili = timer1.microsecond
        for brute in passwdlist:
            password = hashlib.md5(brute.strip()).hexdigest()
            counter += 1
            z = brute.replace('\n', '')
            sys.stdout.write("\r%s[*]%s Trying Password ... : " % (fg(68),attr(0)) + str(z))
            sys.stdout.flush()
            if hash_input == password:
                timer2 = datetime.datetime.now()
                timer2sec = timer2.second
                timer2mili = timer2.microsecond
                if timer2sec > timer1sec:
                    timesec = timer2sec - timer1sec
                if timer1sec > timer2sec:
                    timesec = timer1sec - timer2sec
                if timer2mili > timer1mili:
                    timemili = timer2mili - timer1mili
                if timer1mili > timer2mili:
                    timemili = timer1mili - timer2mili
                timing = str(timesec)+'.'+str(timemili)
                print ''
                print '\n%s[+]%s Password cracked successfully in' % (fg(46),attr(0)) ,'('+timing+') second !\n'
                print '%s[+]%s Password :' % (fg(46),attr(0)),brute
                break
        else:
            print '\n\n%s[-]%s Password not found !' % (fg(196),attr(0))
    else:
        print '\n\n%s[-]%s Invalid Hash !' % (fg(196),attr(0))

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
            print '\n%s[-]%s File not found !' % (fg(196),attr(0))
            quit()
        with open(listpath,'r') as file:
            for line in file:
                wordlst = line.split()
                lines += 1
        print '%s[+]%s Loaded passwords :' % (fg(46),attr(0)),lines,'\n'
        timer1 = datetime.datetime.now()
        timer1sec = timer1.second
        timer1mili = timer1.microsecond
        for brute in passwdlist:
            password = hashlib.sha1(brute.strip()).hexdigest()
            counter += 1
            z = brute.replace('\n', '')
            sys.stdout.write("\r%s[*]%s Trying Password ... : " % (fg(68),attr(0)) + str(z))
            sys.stdout.flush()
            if hash_input == password:
                timer2 = datetime.datetime.now()
                timer2sec = timer2.second
                timer2mili = timer2.microsecond
                if timer2sec > timer1sec:
                    timesec = timer2sec - timer1sec
                if timer1sec > timer2sec:
                    timesec = timer1sec - timer2sec
                if timer2mili > timer1mili:
                    timemili = timer2mili - timer1mili
                if timer1mili > timer2mili:
                    timemili = timer1mili - timer2mili
                timing = str(timesec)+'.'+str(timemili)
                print ''
                print '\n%s[+]%s Password cracked successfully in' % (fg(46),attr(0)) ,'('+timing+') second !\n'
                print '%s[+]%s Password :' % (fg(46),attr(0)),brute
                break
        else:
            print '\n\n%s[-]%s Password not found !' % (fg(196),attr(0))
    else:
        print '\n\n%s[-]%s Invalid Hash !' % (fg(196),attr(0))


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
            print '\n%s[-]%s File not found !' % (fg(196),attr(0))
            quit()
        with open(listpath,'r') as file:
            for line in file:
                wordlst = line.split()
                lines += 1
        print '%s[+]%s Loaded passwords :' % (fg(46),attr(0)),lines,'\n'
        timer1 = datetime.datetime.now()
        timer1sec = timer1.second
        timer1mili = timer1.microsecond
        for brute in passwdlist:
            password = hashlib.sha224(brute.strip()).hexdigest()
            counter += 1
            z = brute.replace('\n', '')
            sys.stdout.write("\r%s[*]%s Trying Password ... : " % (fg(68),attr(0)) + str(z))
            sys.stdout.flush()
            if hash_input == password:
                timer2 = datetime.datetime.now()
                timer2sec = timer2.second
                timer2mili = timer2.microsecond
                if timer2sec > timer1sec:
                    timesec = timer2sec - timer1sec
                if timer1sec > timer2sec:
                    timesec = timer1sec - timer2sec
                if timer2mili > timer1mili:
                    timemili = timer2mili - timer1mili
                if timer1mili > timer2mili:
                    timemili = timer1mili - timer2mili
                timing = str(timesec)+'.'+str(timemili)
                print ''
                print '\n%s[+]%s Password cracked successfully in' % (fg(46),attr(0)) ,'('+timing+') second !\n'
                print '%s[+]%s Password :' % (fg(46),attr(0)),brute
                break
        else:
            print '\n\n%s[-]%s Password not found !' % (fg(196),attr(0))
    else:
        print '\n\n%s[-]%s Invalid Hash !' % (fg(196),attr(0))

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
            print '\n%s[-]%s File not found !' % (fg(196),attr(0))
            quit()
        with open(listpath,'r') as file:
            for line in file:
                wordlst = line.split()
                lines += 1
        print '%s[+]%s Loaded passwords :' % (fg(46),attr(0)),lines,'\n'
        timer1 = datetime.datetime.now()
        timer1sec = timer1.second
        timer1mili = timer1.microsecond
        for brute in passwdlist:
            password = hashlib.sha256(brute.strip()).hexdigest()
            counter += 1
            z = brute.replace('\n', '')
            sys.stdout.write("\r%s[*]%s Trying Password ... : " % (fg(68),attr(0)) + str(z))
            sys.stdout.flush()
            if hash_input == password:
                timer2 = datetime.datetime.now()
                timer2sec = timer2.second
                timer2mili = timer2.microsecond
                if timer2sec > timer1sec:
                    timesec = timer2sec - timer1sec
                if timer1sec > timer2sec:
                    timesec = timer1sec - timer2sec
                if timer2mili > timer1mili:
                    timemili = timer2mili - timer1mili
                if timer1mili > timer2mili:
                    timemili = timer1mili - timer2mili
                timing = str(timesec)+'.'+str(timemili)
                print ''
                print '\n%s[+]%s Password cracked successfully in' % (fg(46),attr(0)) ,'('+timing+') second !\n'
                print '%s[+]%s Password :' % (fg(46),attr(0)),brute
                break
        else:
            print '\n\n%s[-]%s Password not found !' % (fg(196),attr(0))
    else:
        print '\n\n%s[-]%s Invalid Hash !' % (fg(196),attr(0))


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
            print '\n%s[-]%s File not found !' % (fg(196),attr(0))
            quit()
        with open(listpath,'r') as file:
            for line in file:
                wordlst = line.split()
                lines += 1
        print '%s[+]%s Loaded passwords :' % (fg(46),attr(0)),lines,'\n'
        timer1 = datetime.datetime.now()
        timer1sec = timer1.second
        timer1mili = timer1.microsecond
        for brute in passwdlist:
            password = hashlib.sha384(brute.strip()).hexdigest()
            counter += 1
            z = brute.replace('\n', '')
            sys.stdout.write("\r%s[*]%s Trying Password ... : " % (fg(68),attr(0)) + str(z))
            sys.stdout.flush()
            if hash_input == password:
                timer2 = datetime.datetime.now()
                timer2sec = timer2.second
                timer2mili = timer2.microsecond
                if timer2sec > timer1sec:
                    timesec = timer2sec - timer1sec
                if timer1sec > timer2sec:
                    timesec = timer1sec - timer2sec
                if timer2mili > timer1mili:
                    timemili = timer2mili - timer1mili
                if timer1mili > timer2mili:
                    timemili = timer1mili - timer2mili
                timing = str(timesec)+'.'+str(timemili)
                print ''
                print '\n%s[+]%s Password cracked successfully in' % (fg(46),attr(0)) ,'('+timing+') second !\n'
                print '%s[+]%s Password :' % (fg(46),attr(0)),brute
                break
        else:
            print '\n\n%s[-]%s Password not found !' % (fg(196),attr(0))
    else:
        print '\n\n%s[-]%s Invalid Hash !' % (fg(196),attr(0))

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
            print '\n%s[-]%s File not found !' % (fg(196),attr(0))
            quit()
        with open(listpath,'r') as file:
            for line in file:
                wordlst = line.split()
                lines += 1
        print '%s[+]%s Loaded passwords :' % (fg(46),attr(0)),lines,'\n'
        timer1 = datetime.datetime.now()
        timer1sec = timer1.second
        timer1mili = timer1.microsecond
        for brute in passwdlist:
            password = hashlib.sha512(brute.strip()).hexdigest()
            counter += 1
            z = brute.replace('\n', '')
            sys.stdout.write("\r%s[*]%s Trying Password ... : " % (fg(68),attr(0)) + str(z))
            sys.stdout.flush()
            if hash_input == password:
                timer2 = datetime.datetime.now()
                timer2sec = timer2.second
                timer2mili = timer2.microsecond
                if timer2sec > timer1sec:
                    timesec = timer2sec - timer1sec
                if timer1sec > timer2sec:
                    timesec = timer1sec - timer2sec
                if timer2mili > timer1mili:
                    timemili = timer2mili - timer1mili
                if timer1mili > timer2mili:
                    timemili = timer1mili - timer2mili
                timing = str(timesec)+'.'+str(timemili)
                print ''
                print '\n%s[+]%s Password cracked successfully in' % (fg(46),attr(0)) ,'('+timing+') second !\n'
                print '%s[+]%s Password :' % (fg(46),attr(0)),brute
                break
        else:
            print '\n\n%s[-]%s Password not found !' % (fg(196),attr(0))
    else:
        print '\n\n%s[-]%s Invalid Hash !' % (fg(196),attr(0))

def crack_base64():
    print ''
    print "%s[*]%s This type of algorithm don't need wordlist !\n" % (fg(68),attr(0))
    hash_input = raw_input('Enter your Hash : ')
    decoded = str(base64.b64decode(hash_input))
    print '\n%s[+]%s Password cracked successfully !\n' % (fg(46),attr(0))
    print '%s[+]%s Password :' % (fg(46),attr(0)),decoded

def identify():
    if len(input_hash) == 32:
        print '\n%s[+]%s MD5 / MD5 Reverse / MD4' % (fg(46),attr(0))
    elif len(input_hash) == 40:
        print '\n%s[+]%s SHA-1 / MySQL5 / Ripemd160' % (fg(46),attr(0))
    elif len(input_hash) == 13:
        print '\n%s[+]%s DES(Unix)' % (fg(46),attr(0))
    elif len(input_hash) == 16:
        print '\n%s[+]%s MySQL / DES(Oracle Hash)' % (fg(46),attr(0))
    elif len(input_hash) == 41 & input_hash.startswith('*'):
        print '\n%s[+]%s MySQL5' % (fg(46),attr(0))
    elif len(input_hash) == 64:
        print '\n%s[+]%s SHA-256' % (fg(46),attr(0))
    elif len(input_hash) == 56:
        print '\n%s[+]%s SHA-224' % (fg(46),attr(0))
    elif len(input_hash) == 96:
        print '\n%s[+]%s SHA-384 / SHA-384(HMAC)' % (fg(46),attr(0))
    elif len(input_hash) == 128:
        print '\n%s[+]%s SHA-512 / Whirlpool' % (fg(46),attr(0))
    elif len(input_hash) == 34 & input_hash.startswith('$1$'):
        print '\n%s[+]%s MD5(Unix)' % (fg(46),attr(0))
    elif len(input_hash) == 37 & input_hash.startswith('$apr1$'):
        print '\n%s[+]%s MD5(APR)' % (fg(46),attr(0))
    elif len(input_hash) == 34 & input_hash.startswith('$H$'):
        print '\n%s[+]%s MD5(phpBB3)' % (fg(46),attr(0))
    elif len(input_hash) == 34 & input_hash.startswith('$P$'):
        print '\n%s[+]%s MD5(Wordpress)' % (fg(46),attr(0))
    elif len(input_hash) == 39 & input_hash.startswith('$5$'):
        print '\n%s[+]%s SHA-256(Unix)' % (fg(46),attr(0))
    elif len(input_hash) == 39 & input_hash.startswith('$6$'):
        print '\n%s[+]%s SHA-512(Unix)' % (fg(46),attr(0))
    elif len(input_hash) == 24 & input_hash.endswith('=='):
        print '\n%s[+]%s MD5(Base-64)' % (fg(46),attr(0))
    elif len(input_hash) == 28 & input_hash.endswith('='):
        print '\n%s[+]%s SHA-1(Base-64)' % (fg(46),attr(0))
    elif len(input_hash) == 40 & input_hash.endswith('=='):
        print '\n%s[+]%s SHA-224(Base-64)' % (fg(46),attr(0))
    elif len(input_hash) == 88 & input_hash.endswith('=='):
        print '\n%s[+]%s SHA-512(Base-64)' % (fg(46),attr(0))
    elif len(input_hash) == 44 & input_hash.endswith('='):
        print '\n%s[+]%s SHA-256(Base-64)' % (fg(46),attr(0))
    else:
        print '\n%s[-]%s Invalid Input/ Unidentified' % (fg(196),attr(0))

plat = str(platform.platform())
if plat.startswith('Linux'):
    reset()
else:
    clear()

author ='''                                          ##################################################################################
                                          #    ___ ___            .___                ___________           .__            #
                                          #   /   |   \ ___.__. __| _/___________     \__    ___/___   ____ |  |   ______  #
                                          #  /    ~    <   |  |/ __ |\_  __ \__  \      |    | /  _ \ /  _ \|  |  /  ___/  #
                                          #  \    Y    /\___  / /_/ | |  | \// __ \_    |    |(  <_> |  <_> )  |__\___ \   #
                                          #   \___|_  / / ____\____ | |__|  (____  /    |____| \____/ \____/|____/____  >  #
                                          #         \/  \/         \/            \/                                   \/   #
                                          ##################################################################################\n
                                                          %s[+]%s  Contact me on Telegram : %s@DarknessEagle%s  %s[+]%s\n
                                                  %s[*]%s  Contact me on Gmail : DarknessEagle.Pentester@gmail.com  %s[*]%s\n\n\n
''' % (fg(46),attr(0),fg(39),attr(0),fg(46),attr(0),fg(68),attr(0),fg(68),attr(0))
print author
print '  Select your option from the menu : \n'
print '    1) Encryption'
print '    2) Decryption'
print '    3) Hash Identifier\n'
print '    0) Exit\n\n'
option = int(input('Hydra >> '))
print ''
print ''
if option == 1:
    print '  Select your tool :\n'
    print '  1) Password Encryptor\n'
    print '  0) Exit\n'
    option = int(input('Hydra (%sEncryption%s) >> ' % (fg(196),attr(0))))
    print ''
    if option == 1:
        password = raw_input('Enter your password : ')
        if option == 1:
            print ''
            print ''
            print '  Select your Hash Algorithm :\n'
            print '    1) MD4'
            print '    2) MD5'
            print '    3) MD5 Reverse'
            print '    4) SHA-1'
            print '    5) SHA-224'
            print '    6) SHA-256'
            print '    7) SHA-384'
            print '    8) SHA-512'
            print '    9) ripemd160'
            print '    10) whirlpool'
            print '    11) Base64'
            print '    99) All algorithm\n'
            print '    0) Exit\n'
            sel_hash = int(input('Hydra (%sPassword Encryptor%s) >> ' % (fg(196),attr(0))))
            if sel_hash == 1:
                print '\n%s[+]%s Your password in MD4 algorithm is : ' % (fg(46),attr(0)) ,MD4()
            elif sel_hash == 2:
                print '\n%s[+]%s Your password in MD5 algorithm is : ' % (fg(46),attr(0)) ,MD5()
            elif sel_hash == 3:
                print '\n%s[+]%s Your password in MD5 Reverse algorithm is : ' % (fg(46),attr(0)) ,MD5rev()
            elif sel_hash == 4:
                print '\n%s[+]%s Your password in SHA-1 algorithm is : ' % (fg(46),attr(0)) ,SHA1()
            elif sel_hash == 5:
                print '\n%s[+]%s Your password in SHA-224 algorithm is : ' % (fg(46),attr(0)) ,SHA224()
            elif sel_hash == 6:
                print '\n%s[+]%s Your password in SHA-256 algorithm is : ' % (fg(46),attr(0)) ,SHA256()
            elif sel_hash == 7:
                print '\n%s[+]%s Your password in SHA-384 algorithm is : ' % (fg(46),attr(0)) ,SHA384()
            elif sel_hash == 8:
                print '\n%s[+]%s Your password in SHA-512 algorithm is : ' % (fg(46),attr(0)) ,SHA512()
            elif sel_hash == 9:
                print '\n%s[+]%s Your password in ripemd160 algorithm is : ' % (fg(46),attr(0)) ,ripemd160()
            elif sel_hash == 10:
                print '\n%s[+]%s Your password in whirlpool algorithm is : ' % (fg(46),attr(0)) ,whirlpool()
            elif sel_hash == 11:
                print '\n%s[+]%s Your password in Base64 algorithm is : ' % (fg(46),attr(0)) ,encode_base64()
            elif sel_hash == 99:
                print '\n%s[+]%s Your password in MD4 algorithm is : ' % (fg(46),attr(0)) ,MD4()
                print '\n%s[+]%s Your password in MD5 algorithm is : ' % (fg(46),attr(0)) ,MD5()
                print '\n%s[+]%s Your password in MD5 Reverse algorithm is : ' % (fg(46),attr(0)) ,MD5rev()
                print '\n%s[+]%s Your password in SHA-1 algorithm is : ' % (fg(46),attr(0)) ,SHA1()
                print '\n%s[+]%s Your password in SHA-224 algorithm is : ' % (fg(46),attr(0)) ,SHA224()
                print '\n%s[+]%s Your password in SHA-256 algorithm is : ' % (fg(46),attr(0)) ,SHA256()
                print '\n%s[+]%s Your password in SHA-384 algorithm is : ' % (fg(46),attr(0)) ,SHA384()
                print '\n%s[+]%s Your password in SHA-512 algorithm is : ' % (fg(46),attr(0)) ,SHA512()
                print '\n%s[+]%s Your password in ripemd160 algorithm is : ' % (fg(46),attr(0)) ,ripemd160()
                print '\n%s[+]%s Your password in whirlpool algorithm is : ' % (fg(46),attr(0)) ,whirlpool()
                print '\n%s[+]%s Your password in Base64 algorithm is : ' % (fg(46),attr(0)) ,encode_base64()
            elif sel_hash == 0:
                print '%s[*]%s Exiting...' % (fg(68),attr(0))
                quit()

            else:
                print '\n%s[-]%s Invalid input' % (fg(196),attr(0))
                quit()

        else:
            print '\n%s[-]%s Invalid input' % (fg(196),attr(0))
            quit()

    elif option == 0:
        print '%s[*]%s Exiting...' % (fg(68),attr(0))
        quit()
    else:
        print '\n%s[-]%s Invalid input' % (fg(196),attr(0))
        quit()

elif option == 2:
    print '  Select your tool :\n'
    print '    1) Hash Decryptor\n'
    print '    0) Exit\n\n'
    option = int(input('Hydra (%sDecryption%s) >> ' % (fg(196),attr(0))))
    print ''
    if option == 1:
        print ''
        print '  Select your Hash Algorithm :\n'
        print '    1) MD5'
        print '    2) MD5 Reverse'
        print '    3) SHA-1'
        print '    4) SHA-224'
        print '    5) SHA-256'
        print '    6) SHA-384'
        print '    7) SHA-512'
        print '    8) Base64\n'
        print '    0) Exit\n'
        sel_hash = int(input('Hydra (%sHash Decryptor%s) >> ' % (fg(196),attr(0))))

        if sel_hash == 1:
            crack_md5()

        elif sel_hash == 2:
            crack_md5rev()

        elif sel_hash == 3:
            crack_sha1()

        elif sel_hash == 4:
            crack_sha224()

        elif sel_hash == 5:
            crack_sha256()

        elif sel_hash == 6:
            crack_sha384()

        elif sel_hash == 7:
            crack_sha512()

        elif sel_hash == 8:
            crack_base64()

        elif sel_hash == 0:
            print '%s[*]%s Exiting...' % (fg(68),attr(0))
            quit()

        else:
            print '\n%s[-]%s Invalid input' % (fg(196),attr(0))
            quit()
    elif option == 0:
        print '%s[*]%s Exiting...' % (fg(68),attr(0))
        quit()

    else:
        print '\n%s[-]%s Invalid input' % (fg(196),attr(0))
        quit()

elif option == 3:
    input_hash = raw_input('Enter your Hash : ')
    identify()

elif option == 0:
    print '%s[*]%s Exiting...' % (fg(68),attr(0))
    quit()

else:
    print '\n%s[-]%s Invalid input crack_' % (fg(196),attr(0))
    quit()
