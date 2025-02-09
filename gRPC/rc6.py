import symmetricCipherABC
import struct

class RC6(symmetricCipherABC.SymmetricCipher):
    def __init__(self, R, key, strip_extra_nulls=False, bytes_count=16):
        self.bytes_count = self.block_size = bytes_count
        self.block_size = bytes_count
        self.w = (bytes_count // 4) * 8
        self.R = R
        self.key = key
        self.strip_extra_nulls = strip_extra_nulls

        self.T = 2*R + 4
        self.w8 = self.w // 8
        self.mod = 2 ** self.w
        self.mask = self.mod - 1
        self.b = len(key)
        self.round_keys = []

        self.set_key()

    def set_key(self, key=b"0"):
        if key != b"0":
            self.key = key
        self.__keyAlign()
        self.__keyExtend()
        self.__shuffle()

    def __lshift(self, val, n):
        n %= self.w
        return ((val << n) & self.mask) | ((val & self.mask) >> (self.w - n)) & self.mask

    def __rshift(self, val, n):
        n %= self.w
        return ((val & self.mask) >> n) | (val << (self.w - n) & self.mask)

    def __const(self):
        if self.w == 16:
            return 0xB7E1, 0x9E37 #P, Q values
        elif self.w == 32:
            return 0xB7E15163, 0x9E3779B9
        elif self.w == 64:
            return 0xB7E151628AED2A6B, 0x9E3779B97F4A7C15

    def __keyAlign(self):
        if self.b == 0:  # key is empty
            self.c = 1
        elif self.b % self.w8:
            self.key += b'\x00' * (self.w8 - self.b % self.w8)  # fill key with \x00 bytes
            self.b = len(self.key)
            self.c = self.b // self.w8
        else:
            self.c = self.b // self.w8

        L = [0] * self.c
        for i in range(self.b - 1, -1, -1):
            L[i // self.w8] = (L[i // self.w8] << 8) + self.key[i]
        self.L = L

    def __keyExtend(self):
        P, Q = self.__const()
        self.S = [(P + i * Q) % self.mod for i in range(self.T)]

    def __shuffle(self):
        i, j, A, B = 0, 0, 0, 0
        for k in range(3 * max(self.c, self.T)):
            A = self.S[i] = self.__lshift((self.S[i] + A + B), 3)
            B = self.L[j] = self.__lshift((self.L[j] + A + B), A + B)
            i = (i + 1) % self.T
            j = (j + 1) % self.c

        self.round_keys = self.S

    def encrypt(self, plaintext: bytes) -> bytes:
        """Шифрование блока данных."""
        if len(plaintext) * 8 != 4 * self.w: #Проверка блока на 128 бит
            raise ValueError(f"Размер блока должен быть {self.bytes_count} байт (128 бит)")

        #Преобразование входных данных в 4 32-битных слов
        A, B, C, D = struct.unpack('<4I', plaintext)

        B = (B + self.round_keys[0]) & 0xFFFFFFFF
        D = (D + self.round_keys[1]) & 0xFFFFFFFF

        # r(20) раундов шифрования
        for i in range(1, self.R+1):
            t = self.__lshift(B * (2*B + 1), 5)
            u = self.__lshift((D * (2*D + 1)), 5)

            A = (self.__lshift(A ^ t, u) + self.round_keys[2 * i]) & 0xFFFFFFFF
            C = (self.__lshift(C ^ u, t) + self.round_keys[2*i + 1]) & 0xFFFFFFFF

            A, B, C, D = B, C, D, A

        A = (A + self.round_keys[2*self.R + 2]) & 0xFFFFFFFF
        C = (C + self.round_keys[2*self.R + 3]) & 0xFFFFFFFF

        return struct.pack('<4I', A, B, C, D)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Расшифровка блока данных."""
        if len(ciphertext) * 8 != 4*self.w:
            raise ValueError(f"Размер блока должен быть {self.bytes_count} байт (128 бит)")

        # Преобразование входных данных в 4 32-битных слова
        A, B, C, D = struct.unpack('<4I', ciphertext)

        C = (C - self.round_keys[2*self.R + 3]) & 0xFFFFFFFF
        A = (A - self.round_keys[2*self.R + 2]) & 0xFFFFFFFF

        # 20 раундов расшифрования
        for i in range(20, 0, -1):
            A, B, C, D = D, A, B, C

            u = self.__lshift((D * (2*D + 1)), 5)
            t = self.__lshift((B * (2*B + 1)), 5)

            C = self.__rshift((C - self.round_keys[2*i + 1]), t) ^ u
            A = self.__rshift((A - self.round_keys[2*i]), u) ^ t

        D = (D - self.round_keys[1]) & 0xFFFFFFFF
        B = (B - self.round_keys[0]) & 0xFFFFFFFF

        return struct.pack('<4I', A, B, C, D)



