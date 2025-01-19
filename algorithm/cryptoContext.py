from enum import Enum
from concurrent.futures import ThreadPoolExecutor

class PaddingScheme(Enum):
    PKCS7 = "PKCS7"
    ZERO = "ZERO"
    ISO7816 = "ISO7816"

class CryptoContext:
    def __init__(self, cipher, mode: str, padding: PaddingScheme = PaddingScheme.PKCS7, iv: bytes = None, nonce: bytes = None):
        """
        Инициализация криптоконтекста.
        :param cipher: Шифр (например, RC6, Seprent).
        :param mode: Режим шифрования ("ECB", "CBC", "CFB", "OFB", "CTR").
        :param padding: Схема набивки (PaddingScheme.PKCS7, PaddingScheme.ZERO, PaddingScheme.ISO7816).
        :param iv: Вектор инициализации (для CBC, CFB, OFB).
        :param nonce: Уникальное значение (для CTR).
        """
        self.cipher = cipher
        self.mode = mode
        self.padding = padding
        self.iv = iv
        self.nonce = nonce

        # Проверка наличия IV для режимов, которые его требуют
        if mode in ["CBC", "CFB", "OFB"] and iv is None:
            raise ValueError(f"IV должен быть предоставлен для режима {mode}.")
        if mode == "CTR" and nonce is None:
            raise ValueError("Nonce должен быть предоставлен для режима CTR.")

    def encrypt(self, plaintext: bytes) -> bytes:
        """Шифрование данных."""
        padded_data = self._apply_padding(plaintext)
        mode_to_encrypt_method = {
            "ECB": self._encrypt_ecb_parallel,
            "CBC": self._encrypt_cbc,
            "CFB": self._encrypt_cfb,
            "OFB": self._encrypt_ofb,
            "CTR": self._encrypt_ctr_parallel,
        }

        encrypt_method = mode_to_encrypt_method.get(self.mode)
        if encrypt_method is None:
            raise ValueError("Неподдерживаемый режим шифрования.")

        return encrypt_method(padded_data)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Расшифровка данных."""
        mode_to_decrypt_method = {
            "ECB": self._decrypt_ecb_parallel,
            "CBC": self._decrypt_cbc,
            "CFB": self._decrypt_cfb,
            "OFB": self._decrypt_ofb,
            "CTR": self._decrypt_ctr_parallel,
        }

        decrypt_method = mode_to_decrypt_method.get(self.mode)
        if decrypt_method is None:
            raise ValueError("Неподдерживаемый режим шифрования.")

        decrypted_data = decrypt_method(ciphertext)
        return self._remove_padding(decrypted_data)

    def encrypt_file(self, input_file: str, output_file: str) -> None:
        """
        Шифрование файла.
        :param input_file: Путь к исходному файлу.
        :param output_file: Путь к зашифрованному файлу.
        """
        with open(input_file, "rb") as f_in:
            plaintext = f_in.read()

        ciphertext = self.encrypt(plaintext)

        with open(output_file, "wb") as f_out:
            f_out.write(ciphertext)

    def decrypt_file(self, input_file: str, output_file: str) -> None:
        """
        Расшифровка файла.
        :param input_file: Путь к зашифрованному файлу.
        :param output_file: Путь к расшифрованному файлу.
        """
        with open(input_file, "rb") as f_in:
            ciphertext = f_in.read()

        plaintext = self.decrypt(ciphertext)

        with open(output_file, "wb") as f_out:
            f_out.write(plaintext)

    def encrypt_stream(self, input_stream, output_stream) -> None:
        """
        Шифрование потока данных.
        :param input_stream: Входной поток (например, файловый объект).
        :param output_stream: Выходной поток (например, файловый объект).
        """
        plaintext = input_stream.read()
        ciphertext = self.encrypt(plaintext)
        output_stream.write(ciphertext)

    def decrypt_stream(self, input_stream, output_stream) -> None:
        """
        Расшифровка потока данных.
        :param input_stream: Входной поток (например, файловый объект).
        :param output_stream: Выходной поток (например, файловый объект).
        """
        ciphertext = input_stream.read()
        plaintext = self.decrypt(ciphertext)
        output_stream.write(plaintext)

    def _apply_padding(self, data: bytes) -> bytes:
        """Применение набивки."""
        block_size = self.cipher.block_size
        padding_length = block_size - (len(data) % block_size)

        if self.padding == PaddingScheme.PKCS7:
            return data + bytes([padding_length] * padding_length)
        elif self.padding == PaddingScheme.ZERO:
            return data + bytes([0] * padding_length)
        elif self.padding == PaddingScheme.ISO7816:
            return data + b'\x80' + bytes([0] * (padding_length - 1))
        else:
            raise ValueError("Неподдерживаемая схема набивки.")

    def _remove_padding(self, data: bytes) -> bytes:
        """Удаление набивки."""
        if self.padding == PaddingScheme.PKCS7:
            padding_length = data[-1]
            return data[:-padding_length]
        elif self.padding == PaddingScheme.ZERO:
            return data.rstrip(b'\x00')
        elif self.padding == PaddingScheme.ISO7816:
            return data.rstrip(b'\x00').rstrip(b'\x80')
        else:
            raise ValueError("Неподдерживаемая схема набивки.")

    def _encrypt_ecb_parallel(self, data: bytes, chunk_size: int = 1024) -> bytes:
        """
        Параллельное шифрование в режиме ECB.
        :param data: Данные для шифрования.
        :param chunk_size: Размер блока данных для обработки.
        :return: Зашифрованные данные.
        """
        ciphertext = bytearray()

        def encrypt_chunk(chunk: bytes) -> bytes:
            encrypted_chunk = bytearray()
            for i in range(0, len(chunk), self.cipher.block_size):
                block = chunk[i:i + self.cipher.block_size]
                encrypted_chunk.extend(self.cipher.encrypt(block))
            return encrypted_chunk

        with ThreadPoolExecutor() as executor:
            futures = []
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                futures.append(executor.submit(encrypt_chunk, chunk))

            for future in futures:
                ciphertext.extend(future.result())

        return bytes(ciphertext)

    def _decrypt_ecb_parallel(self, ciphertext: bytes, chunk_size: int = 1024) -> bytes:
        """
        Параллельное расшифрование в режиме ECB.
        :param ciphertext: Зашифрованные данные.
        :param chunk_size: Размер блока данных для обработки.
        :return: Расшифрованные данные.
        """
        plaintext = bytearray()

        def decrypt_chunk(chunk: bytes) -> bytes:
            decrypted_chunk = bytearray()
            for i in range(0, len(chunk), self.cipher.block_size):
                block = chunk[i:i + self.cipher.block_size]
                decrypted_chunk.extend(self.cipher.decrypt(block))
            return decrypted_chunk

        with ThreadPoolExecutor() as executor:
            futures = []
            for i in range(0, len(ciphertext), chunk_size):
                chunk = ciphertext[i:i + chunk_size]
                futures.append(executor.submit(decrypt_chunk, chunk))

            for future in futures:
                plaintext.extend(future.result())

        return bytes(plaintext)

    def _encrypt_cbc(self, data: bytes) -> bytes:
        """Шифрование в режиме CBC."""
        ciphertext = b""
        previous_block = self.iv

        for i in range(0, len(data), self.cipher.block_size):
            block = data[i:i + self.cipher.block_size]
            block = bytes(a ^ b for a, b in zip(block, previous_block))
            encrypted_block = self.cipher.encrypt(block)
            ciphertext += encrypted_block
            previous_block = encrypted_block

        return ciphertext

    def _decrypt_cbc(self, ciphertext: bytes) -> bytes:
        """Расшифровка в режиме CBC."""
        plaintext = b""
        previous_block = self.iv

        for i in range(0, len(ciphertext), self.cipher.block_size):
            block = ciphertext[i:i + self.cipher.block_size]
            decrypted_block = self.cipher.decrypt(block)
            plaintext_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
            plaintext += plaintext_block
            previous_block = block

        return plaintext

    def _encrypt_cfb(self, data: bytes) -> bytes:
        """Шифрование в режиме CFB."""
        ciphertext = b""
        previous_block = self.iv

        for i in range(0, len(data), self.cipher.block_size):
            block = data[i:i + self.cipher.block_size]
            encrypted_block = self.cipher.encrypt(previous_block)
            ciphertext_block = bytes(a ^ b for a, b in zip(block, encrypted_block))
            ciphertext += ciphertext_block
            previous_block = ciphertext_block

        return ciphertext

    def _decrypt_cfb(self, ciphertext: bytes) -> bytes:
        """Расшифровка в режиме CFB."""
        plaintext = b""
        previous_block = self.iv

        for i in range(0, len(ciphertext), self.cipher.block_size):
            block = ciphertext[i:i + self.cipher.block_size]
            encrypted_block = self.cipher.encrypt(previous_block)
            plaintext_block = bytes(a ^ b for a, b in zip(block, encrypted_block))
            plaintext += plaintext_block
            previous_block = block

        return plaintext

    def _encrypt_ofb(self, data: bytes) -> bytes:
        """Шифрование в режиме OFB."""
        ciphertext = b""
        previous_block = self.iv

        for i in range(0, len(data), self.cipher.block_size):
            block = data[i:i + self.cipher.block_size]
            encrypted_block = self.cipher.encrypt(previous_block)
            ciphertext_block = bytes(a ^ b for a, b in zip(block, encrypted_block))
            ciphertext += ciphertext_block
            previous_block = encrypted_block

        return ciphertext

    def _decrypt_ofb(self, ciphertext: bytes) -> bytes:
        """Расшифровка в режиме OFB."""
        # В OFB режиме шифрование и расшифрование идентичны
        return self._encrypt_ofb(ciphertext)

    def _encrypt_ctr_parallel(self, data: bytes, chunk_size: int = 1024) -> bytes:
        """
        Параллельное шифрование в режиме CTR.
        :param data: Данные для шифрования.
        :param chunk_size: Размер блока данных для обработки.
        :return: Зашифрованные данные.
        """
        ciphertext = bytearray()
        counter = int.from_bytes(self.nonce, byteorder='big')

        def encrypt_chunk(chunk: bytes, start_counter: int) -> bytes:
            encrypted_chunk = bytearray()
            for i in range(0, len(chunk), self.cipher.block_size):
                block = chunk[i:i + self.cipher.block_size]
                counter_block = (start_counter + i // self.cipher.block_size).to_bytes(self.cipher.block_size,
                                                                                       byteorder='big')
                encrypted_block = self.cipher.encrypt(counter_block)
                encrypted_chunk.extend(bytes(a ^ b for a, b in zip(block, encrypted_block)))
            return encrypted_chunk

        with ThreadPoolExecutor() as executor:
            futures = []
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                futures.append(executor.submit(encrypt_chunk, chunk, counter + i // self.cipher.block_size))

            for future in futures:
                ciphertext.extend(future.result())

        return bytes(ciphertext)

    def _decrypt_ctr_parallel(self, ciphertext: bytes, chunk_size: int = 1024) -> bytes:
        """
        Параллельное расшифрование в режиме CTR.
        :param ciphertext: Зашифрованные данные.
        :param chunk_size: Размер блока данных для обработки.
        :return: Расшифрованные данные.
        """
        # В CTR режиме шифрование и расшифрование идентичны
        return self._encrypt_ctr_parallel(ciphertext, chunk_size)