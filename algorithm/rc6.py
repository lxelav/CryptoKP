from abc import ABC, abstractmethod
import struct

wsl

class RC6(SymmetricEncryption):
    def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        """Шифрование RC6"""
        # Реализация RC6 из предыдущего примера
        plaintext = self.pad_data(plaintext)
        L, R = struct.unpack(">2I", plaintext)
        S = self.key_expansion(key)

        for i in range(20):  # 20 раундов RC6
            L = self.rotate_left(L ^ S[2 * i], 5) + R
            R = self.rotate_left(R ^ S[2 * i + 1], 5) + L

        return struct.pack(">2I", L, R)

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Дешифрование RC6"""
        ciphertext = self.pad_data(ciphertext)
        L, R = struct.unpack(">2I", ciphertext)
        S = self.key_expansion(key)

        for i in range(19, -1, -1):
            R = self.rotate_right(R - L, 5) ^ S[2 * i + 1]
            L = self.rotate_right(L - R, 5) ^ S[2 * i]

        return struct.pack(">2I", L, R)

    def pad_data(self, data):
        if len(data) < 8:
            data += b'\x00' * (8 - len(data))
        elif len(data) > 8:
            data = data[:8]
        return data

    def rotate_left(self, value, n):
        return ((value << n) | (value >> (32 - n))) & 0xFFFFFFFF

    def rotate_right(self, value, n):
        return ((value >> n) | (value << (32 - n))) & 0xFFFFFFFF

    def key_expansion(self, key):
        return [0] * 44  # Простая заглушка


# Пример использования:

def encrypt_and_decrypt_demo():
    key = b'1234567890abcdef'  # Ключ для AES и RC6 (16 байт)
    plaintext = b'Hello, this is a test message!'

    # Работа с RC6
    rc6 = RC6()
    rc6_encrypted = rc6.encrypt(plaintext, key)
    print(f"RC6 Encrypted: {rc6_encrypted}")
    rc6_decrypted = rc6.decrypt(rc6_encrypted, key)
    print(f"RC6 Decrypted: {rc6_decrypted}")


if __name__ == "__main__":
    encrypt_and_decrypt_demo()
