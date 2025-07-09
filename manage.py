import os

import strings as s

from dotenv import load_dotenv

from hashlib import blake2b
from cryptography.fernet import Fernet

import json


class Manager:
    def __init__(self, crypto_path: str, env_name: str) -> None:
        load_dotenv(f'{crypto_path}\\{env_name}')

        self.max_length: int = 22
        self.digest_size: int = 64
        self.indent: int = 4
        self.crypto_path = crypto_path
        self.env_name = env_name
        self.stash_path = f'.\\{self.crypto_path}\\{s.Internal.passwords_file_name}'

        self.encrypted_bio: str = os.getenv(s.Internal.encoded_key_name)
        self.biological: str = ''
        self.hash_key: bytes = os.getenv(s.Internal.hash_key_name).encode(s.Internal.encoding)

        self.encrypter: Fernet = ""

        with open(self.stash_path, 'r') as stash_handle:
            self.encrypted_passwords: dict[str, str] = json.load(stash_handle)

    def __str__(self):
        return str(self.encrypted_bio)

    def salt(self, string: str) -> bytes:
        return string.center(self.max_length, s.Internal.filler_character).encode(s.Internal.encoding)

    def log_biology(self, password: str):
        self.biological = password.encode(s.Internal.encoding)
        self.encrypter = Fernet(self.biological)


    def add_password(self) -> None:
        service: str = input(f'\n{s.External.Manager.prompt_service}')
        password: bytes = input(f'{s.External.Manager.prompt_password}').encode(s.Internal.encoding)

        self.encrypted_passwords[service] = self.encrypter.encrypt(password).decode(s.Internal.encoding)
        json_handler: json = json.dumps(self.encrypted_passwords, indent=self.indent)

        with open(f'.\\{self.crypto_path}\\{s.Internal.passwords_file_name}', 'w') as handle:
            handle.write(json_handler)

    def remove_password(self) -> None:
        service: str = input(f'\n{s.External.Manager.prompt_service}')
        print(s.External.Manager.removed_password.format(serv=service))
        self.encrypted_passwords.pop(service)

        json_handler: json = json.dumps(self.encrypted_passwords, indent=self.indent)

        with open(self.stash_path, 'w') as handle:
            handle.write(json_handler)

    def edit_password(self) -> None:
        service: str = input(f'\n{s.External.Manager.prompt_service}')
        password: bytes = input(f'\n{s.External.Manager.prompt_new_password}').encode(s.Internal.encoding)

        self.encrypted_passwords[service] = self.encrypter.encrypt(password).decode(s.Internal.encoding)

        json_handler: json = json.dumps(self.encrypted_passwords, indent=self.indent)

        with open(f'.\\{self.crypto_path}\\{s.Internal.passwords_file_name}', 'w') as handle:
            handle.write(json_handler)
            print(s.External.Manager.edit_success)

    def check_global_pass(self, user_in) -> bool:
        check_digest = blake2b(key=self.hash_key, digest_size=self.digest_size)

        check_digest.update(user_in.encode(s.Internal.encoding))

        return check_digest.hexdigest() == self.encrypted_bio


class Menu:
    def __init__(self) -> None:
        self.user_input: str = ' '
        self.pass_handler: Manager = Manager(s.Internal.crypto_folder, s.Internal.env_name)
        self.callbacks: dict[str, callable] = {'a': self.pass_handler.add_password,
                                               'r': self.pass_handler.remove_password,
                                               'e': self.pass_handler.edit_password}

    def request_global(self) -> None:
        while self.user_input != '':
            self.user_input = input(s.External.Menu.prompt_global_pass)

            if self.pass_handler.check_global_pass(self.user_input):
                self.mainloop()
            print(s.External.Menu.wrong_pass)

    def mainloop(self) -> None:
        self.pass_handler.log_biology(self.user_input)

        while self.user_input != '':
            print(f'\n{s.External.Menu.available}\n')

            for index, service in enumerate(self.pass_handler.encrypted_passwords.keys()):
                print(service, end=' - ')

                if (index+1) % 11 == 10:
                    print()
            print('\n')

            self.user_input = input(s.External.Menu.commands)

            try:
                encrypted_pass = self.pass_handler.encrypted_passwords[self.user_input]
                print(self.pass_handler.encrypter.decrypt(encrypted_pass).decode(s.Internal.encoding), end='\n\n')
            except KeyError:
                try:
                    self.callbacks[self.user_input]()
                except KeyError:
                    print(s.External.Menu.not_found)



def main() -> None:
    foo = Menu()

    foo.request_global()

if __name__ == '__main__':
    main()