from dataclasses import dataclass

@dataclass(frozen=True)
class Internal:
    hash_key_name: str = "PUBLIC_KEY"
    encoded_key_name: str = "PRIVATE_KEY"
    crypto_folder: str = "crypto"
    env_name: str = '.env'
    passwords_file_name: str = "stash.json"
    hash_file: str = "hash.pkl"
    filler_character: str = '$'
    encoding: str = 'utf-8'

@dataclass(frozen=True)
class External:
    @dataclass(frozen=True)
    class Menu:
        prompt_global_pass: str = "Please enter the global password: "
        wrong_pass: str = "The password is incorrect."
        available: str = "Your saved passwords: "
        commands: str = "[A]dd a new password\n[E]dit an existing password\n[R]emove a password\n\nCommand: "
        not_found: str = "Command not found."

    @dataclass(frozen=True)
    class Manager:
        prompt_service: str = "Name of the service: "
        prompt_password: str = "Password: "
        prompt_new_password: str = "Enter the new password to be replaced: "
        edit_success: str = "Password has been updated successfully."
        removed_password: str = "Removed {serv}'s password from file."