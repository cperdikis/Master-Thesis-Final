from pqcrypto.kem.kyber512 import generate_keypair, decrypt, encrypt


def print_hi(name):
    # Alice generates a (public, secret) key pair
    public_key, secret_key = generate_keypair()

    # Bob derives a secret (the plaintext) and encrypts it with Alice's public key to produce a ciphertext
    ciphertext, plaintext_original = encrypt(public_key)

    # Alice decrypts Bob's ciphertext to derive the now shared secret
    plaintext_recovered = decrypt(secret_key, ciphertext)

    print(len(ciphertext))

    print(len(public_key))

    print("Plain text original: ", plaintext_original)

    print("Plain text recovered: ", plaintext_recovered)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
