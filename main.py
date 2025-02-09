from gRPC import cryptoContext, deffiehellman, rc6, serpent

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

key = deffiehellman.hash_shared_key(shared_secret_a)
iv = b"1234567890abcdef"   # 16 байт
cipher = seprent.Serpent(key=b'mykeys123124')
context = cryptoContext.CryptoContext(cipher, mode="ECB", padding=cryptoContext.PaddingScheme.PKCS7, iv=iv)

plaintext = b"helloworld"
ciphertext = context.encrypt(plaintext)
decrypted = context.decrypt(ciphertext)
print(ciphertext)
print(decrypted)

assert plaintext == decrypted, "Ошибка в шифровании/расшифровании"
