import os

import strings as s

from dotenv import load_dotenv

from hashlib import blake2b
from cryptography.fernet import Fernet

import json


class Manager:
    def __init__(self, crypto_path: str, env_name: str) -> None:
        load_dotenv(f'{crypto_path}\\{env_name}')
        #loads .env file with env vars

        self.max_length: int = 22
        #deprecated

        self.digest_size: int = 64
        #the size for B2b digests. Needs to be static in order to verify hash.

        self.indent: int = 4
        #indent for the json dumps

        self.crypto_path = crypto_path
        #folder where encryption is dealt with

        self.env_name = env_name
        #name of the .env file

        self.stash_path = f'.\\{self.crypto_path}\\{s.Internal.passwords_file_name}'
        #path to encrypted passwords

        self.encrypted_bio: str = os.getenv(s.Internal.encoded_key_name)
        #hashed private key (B2b)

        self.biological: str = ''
        #initialize attribute that will hold the private key when user inputs it

        self.hash_key: bytes = os.getenv(s.Internal.hash_key_name).encode(s.Internal.encoding)
        #the public key to hash the user input and compare digests

        self.encrypter: Fernet = ""
        #initialize encrypter object as str because can't initialize empty Fernet object

        with open(self.stash_path, 'r') as stash_handle:
            self.encrypted_passwords: dict[str, str] = json.load(stash_handle)
            #load encrypted passwords json file and save it as a dict in self

    #removed __str__ attribute due to security concerns

    def salt(self, string: str) -> bytes:
        return string.center(self.max_length, s.Internal.filler_character).encode(s.Internal.encoding)
        #deprecated

    def log_biology(self, password: str):
        self.biological = password.encode(s.Internal.encoding)
        #saves the private key as utf-8 bytes to attribute

        self.encrypter = Fernet(self.biological)
        #finally initializes the real Fernet encrypter with the provided private key


    def add_password(self) -> None: #adds service and password pair to the self dict and rewrites the json file
        service: str = input(f'\n{s.External.Manager.prompt_service}')
        #prompt the user for the name of the service

        password: bytes = input(f'{s.External.Manager.prompt_password}').encode(s.Internal.encoding)
        #prompt the user for the password

        self.encrypted_passwords[service] = self.encrypter.encrypt(password).decode(s.Internal.encoding)
        #encrypts the password given and appends it to the self dict as string (decoding utf-8)

        json_handler: json = json.dumps(self.encrypted_passwords, indent=self.indent)
        #serialize the self dict

        with open(f'.\\{self.crypto_path}\\{s.Internal.passwords_file_name}', 'w') as handle:
            handle.write(json_handler)
            #rewrite the json file with the new password

    def remove_password(self) -> None: #remove service and password pair from the self dict and rewrite the json file
        service: str = input(f'\n{s.External.Manager.prompt_service}')
        #prompt the user for the name of the service to remove

        self.encrypted_passwords.pop(service)
        #remove service from the self dict

        json_handler: json = json.dumps(self.encrypted_passwords, indent=self.indent)
        #serialize self dict

        with open(self.stash_path, 'w') as handle:
            handle.write(json_handler)
            #rewrite json file without the removed password

            print(s.External.Manager.removed_password.format(serv=service))
            #print confirmation to the user that the service/password was removed

    def edit_password(self) -> None: #edit a password (won't affect the service)
        service: str = input(f'\n{s.External.Manager.prompt_service}')
        #prompt the user for a service to edit the password of

        password: bytes = input(f'\n{s.External.Manager.prompt_new_password}').encode(s.Internal.encoding)
        #prompt the user for a new password to be replaced in the dict

        self.encrypted_passwords[service] = self.encrypter.encrypt(password).decode(s.Internal.encoding)
        #emplace the new password to the existing service in the self dict

        json_handler: json = json.dumps(self.encrypted_passwords, indent=self.indent)
        #serialize self dict

        with open(f'.\\{self.crypto_path}\\{s.Internal.passwords_file_name}', 'w') as handle:
            handle.write(json_handler)
            #rewrite the json file with the edited password

            print(s.External.Manager.edit_success)
            #confirm that the editing succeeded to the user

    def check_global_pass(self, user_in) -> bool: #checks whether the private key provided matches the hash
        check_digest = blake2b(key=self.hash_key, digest_size=self.digest_size)
        #create B2b object with public key and a static digest size

        check_digest.update(user_in.encode(s.Internal.encoding))
        #include the provided key in the digest

        return check_digest.hexdigest() == self.encrypted_bio
        #returns true if the provided key matches the hash in env vars. otherwise false


class Menu:
    def __init__(self) -> None:
        self.user_input: str = ' '
        #initialize the user input as a space since blank space is the exit command in this class

        self.pass_handler: Manager = Manager(s.Internal.crypto_folder, s.Internal.env_name)
        #initialize Manager object with the path to the crypto folder and the name of the .env file

        self.callbacks: dict[str, callable] = {'a': self.pass_handler.add_password,
                                               'r': self.pass_handler.remove_password,
                                               'e': self.pass_handler.edit_password}
        #to be called by the user through commands

    def request_global(self) -> None: #requests private key
        while self.user_input != '': #blank space is exit
            self.user_input = input(s.External.Menu.prompt_global_pass)
            #record user's provided private key

            if self.pass_handler.check_global_pass(self.user_input):
                self.mainloop()
                #if new hash matches stored hash, grant access (doesn't decrypt passwords)

            print(s.External.Menu.wrong_pass)
            #else inform the user that the private key is wrong

    def mainloop(self) -> None:
        self.pass_handler.log_biology(self.user_input)
        '''since you can only access this function after providing the valid private key, log the private key provided
           by the user as an attribute, as the env hash is not retrievable'''

        while self.user_input != '': #blank space is exit
            print(f'\n{s.External.Menu.available}\n')
            #prints the header that shows available passwords

            for index, service in enumerate(self.pass_handler.encrypted_passwords.keys()):
                print(service, end=' - ')

                if (index+1) % 11 == 10:
                    print()

                #print 10 services in a row and then newline
            print('\n')
            #then newline

            self.user_input = input(s.External.Menu.commands)
            #prompt the user for a service or one of the available commands and log it

            try:
                encrypted_pass = self.pass_handler.encrypted_passwords[self.user_input]
                #try to fetch an existing service with the input provided

                print(self.pass_handler.encrypter.decrypt(encrypted_pass).decode(s.Internal.encoding), end='\n\n')
                #decrypt in the print statement directly so the decrypted pass doesn't stay in memory

            except KeyError: #if the service doesn't exist
                try:
                    self.callbacks[self.user_input]()
                    #try to run a command from the callbacks attribute

                except KeyError: #if the command doesn't exist
                    print(s.External.Menu.not_found)
                    #inform the user that the command doesn't exist



def main() -> None:
    foo = Menu() #create Menu object

    foo.request_global() #enter Menu mainloop by first requesting
                         #the private key

if __name__ == '__main__':
    main() #only run main if not in import