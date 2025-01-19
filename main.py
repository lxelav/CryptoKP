from algorithm import rc6, cryptoContext, seprent, deffiehellman

#RC6
key = b"0123456789abcdefxfsdfewfdvdffwr"  # 16 байт
iv = b"1234567890abcdef"   # 16 байт
cipher = rc6.RC6(R=20, key=key)  # Предположим, что RC6 уже реализован
context = cryptoContext.CryptoContext(cipher, mode="ECB", padding=cryptoContext.PaddingScheme.PKCS7, iv=iv)

plaintext = b"helloworld"
ciphertext = context.encrypt(plaintext)
decrypted = context.decrypt(ciphertext)
print(ciphertext)
print(decrypted)

assert plaintext == decrypted, "Ошибка в шифровании/расшифровании"

#Seprent
key = b'mykeys123124'

p = deffiehellman.generate_large_prime()  # Простое число
g = 5   # Генератор

a_private, a_public = deffiehellman.diffie_hellman(p, g)

# Сторона B
b_private, b_public = deffiehellman.diffie_hellman(p, g)

# Обмен ключами и вычисление общего секрета
shared_secret_a = deffiehellman.compute_shared_secret(b_public, a_private, p)
shared_secret_b = deffiehellman.compute_shared_secret(a_public, b_private, p)

key = bytes.fromhex(deffiehellman.hash_shared_key(shared_secret_a))
iv = b"1234567890abcdef"   # 16 байт
cipher = seprent.Serpent(key=key)
context = cryptoContext.CryptoContext(cipher, mode="ECB", padding=cryptoContext.PaddingScheme.PKCS7, iv=iv)

plaintext = b"helloworld"
ciphertext = context.encrypt(plaintext)
decrypted = context.decrypt(ciphertext)
print(ciphertext)
print(decrypted)

assert plaintext == decrypted, "Ошибка в шифровании/расшифровании"

# Шифрование файла
with open("data/test_input.txt", "rb") as f:
    image_bytes = f.read()

encrypted_bytes = context.encrypt(image_bytes)
with open("encrypted_text.bin", "wb") as f:
    f.write(encrypted_bytes)

# Расшифрование file
with open("encrypted_text.bin", "rb") as f:
    encrypted_bytes = f.read()

decrypted_bytes = context.decrypt(encrypted_bytes)
with open("decrypted_text.txt", "wb") as f:
    f.write(decrypted_bytes)

print("Шифрование и расшифрование завершены!")