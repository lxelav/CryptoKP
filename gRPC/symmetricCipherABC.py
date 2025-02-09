from abc import ABC, abstractmethod

class SymmetricCipher(ABC):
    """Интерфейс для симметричных алгоритмов шифрования."""

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        """Шифрование данных."""
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Расшифровка данных."""
        pass

    @abstractmethod
    def set_key(self, key: bytes) -> None:
        """Установка ключа."""
        pass
