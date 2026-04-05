from chacha20.cipher import chacha20_encrypt, chacha20_decrypt

key   = bytes(range(32))
nonce = bytes(range(12))

message = b"Afaq loves Data Engineering!"
print(f"Plaintext:  {message.decode()}")

ct = chacha20_encrypt(message, key, nonce, counter=1)
print(f"Ciphertext: {ct.hex()}")

pt = chacha20_decrypt(ct, key, nonce, counter=1)
print(f"Decrypted:  {pt.decode()}")

assert pt == message
print("\nRound-trip successful!")