from cryptography.fernet import Fernet
from hashlib import blake2b

from tkinter.simpledialog import askstring
from tkinter.messagebox import showinfo
import pyclip

def main():
    public_key: str = askstring("Public key",
                                "Please enter a public key (can be anything and you won't have to remember it): ")
    private_key: str = Fernet.generate_key().decode('utf-8')

    hasher = blake2b(key=public_key.encode('utf-8'), digest_size=64)
    hasher.update(private_key.encode('utf-8'))

    private_key_hash = hasher.hexdigest()

    with open(".\\crypto\\.env", "w") as env_handle:
        env_handle.write(f'PUBLIC_KEY={public_key}\nPRIVATE_KEY={private_key_hash}')

    pyclip.copy(private_key)
    showinfo("Private key",
             f"Your private key is: {private_key}, it's been copied to your clipboard.\nDon't lose it, it won't be recoverable after you copy something else.")

main()