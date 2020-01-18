#!/usr/bin/python3
# Tried to use Ruby example from video by Ron Bowes, couldn't figure out how to "substring" hex values in Ruby. So, here's a Python version
# https://github.com/CounterHack/reversing-crypto-talk-public
# Created by Hodorsec for SANS HHC 2019 Challenge

# BUG: Doesn't pad very well yet, so resulting decrypted file is missing the first 8 bytes

# Requirements:
# python3 -m pip install PyCryptodome

from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import sys, os, magic

key_length = DES.block_size                                 # DES-CBC is 8 bytes

def print_help():
    print("\n[*] Usage: " + sys.argv[0] + "\t\t\t<encrypted_filename_with_.enc_extension> <filename_to_decrypt> <time_in_epoch_start> <time_in_epoch_end> <debug>\n")
    print("[*] <encrypted_filename_with_.enc_extension>:\t\tEncrypted file as encrypted with the \"elfscrow.exe\" file")
    print("[*] <filename_to_decrypt:\t\t\t\tFile to decrypt, output in \"out\" directory")
    print("[*] <time_in_epoch_start:\t\t\t\tTime in UNIX EPOCH format, start")
    print("[*] <time_in_epoch_end:\t\t\t\t\tTime in UNIX EPOCH format, end")
    print("[*] <debug>\t\t\t\t\t\tDebug during guessing to see stats. 0 to disable, 1 to enable\n")

def generate_key(time):
    seed = time                                             # UNIX EPOCH in seconds is being used as a seed
    keys = bytearray()
    for i in range(key_length):
        seed = (0x343fd * seed + 0x269ec3)                  # MS VC Implementation of random for LCG
        key = hex(seed >> 16 & 0x7fff & 0x0ff)[-2:]         # Convert to hex, shift right two bytes and trim the last two characters due to length
                                                            # Tried this in ruby, didn't work out due to substring'ing with hex values
        if 'x' in key:
            key = key.replace('x','0')                      # Added due to crashes of non-hexedecimal fromhex error
        key = bytes.fromhex(key)                        
        keys.append(key[0])
    return keys

def check_file(possible_file, possible_key):
    """ Try to guess the filetype, based on the magic MIME type of the file """
    print("\nPossible files found: ")
    for filename in possible_file:
        print("File: " + filename + ". Filetype: " + magic.from_file(filename))
    print("\nPossible keys found: ")
    for key in possible_key:
        print("Key: " + key)
    print("\n")

def decrypt(key, data):
    """ Simple DES-CBC decryption, uses unpadding """
    cipher = DES.new(key, DES.MODE_CBC, data[:key_length])
    return unpad(cipher.decrypt(data[key_length:]), key_length)

def main():
    """ Here the magic happens """
    global file_num                                         # Used to count possible valid files and number them

    # Check input parameters
    if len(sys.argv) < 6:
        print_help()
        exit(1)
    else:
        # Check argument values
        file_read = sys.argv[1]
        write_path = os.path.dirname(__file__) + "out"
        file_write = os.path.join(write_path, sys.argv[2])
        epoch_begin = int(sys.argv[3])
        epoch_end = int(sys.argv[4])
        possible_file = []
        possible_key = []
        debug = int(sys.argv[5])
        
        if not os.path.isdir(write_path):
            try:
                os.mkdir(write_path)
            except OSError:
                print("[!] Cannot create directory %s" % write_path + ". Exiting...")
                print_help()
                exit(1)
        elif epoch_begin > epoch_end:
            print("[!] Epoch starttime begins after stoptime ends. Exiting...")
            print_help()
        elif debug == 1:
            debug = True
    
    try:
        with open(file_read, "rb") as data:
            data = data.read()
            file_num = 1

            for i in range(epoch_begin, epoch_end):
                key = generate_key(i)
                if debug:
                    print("Attempting key: " + key.hex() + " for iteration " + str(i-epoch_begin) + " of total " + str(epoch_end-epoch_begin) + ". " + str(file_num-1) + " file(s) written.")
                try:
                    decrypted = decrypt(key,data)
                    if b"PDF" in decrypted:
                        file_to_write = f"{file_write}_{file_num}"
                        with open(file_to_write, 'wb') as file_writer:
                            print(f"Possible correct key '{key.hex()}'.  Writing to " + file_to_write)
                            file_writer.write(decrypted)
                            
                            possible_key.append(key.hex())
                            possible_file.append(file_write + "_" + str(file_num))
                            
                            file_num += 1
                except Exception as ex:
                    # print(ex)                                   # When padding is incorrect, skip to next key
                    pass
                except KeyboardInterrupt as ex:
                    print("Interrupted...")
                    check_file(possible_file, possible_key)     # Print status of possible keys and files
                    exit(1)

            check_file(possible_file, possible_key)             # Print status of possible keys and files
    except Exception as ex:
        print(ex)
        exit(1)
    
if __name__ == "__main__":
    main()





