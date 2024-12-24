import hashlib
import random
from sympy import nextprime

#TODO: Использовать мб библиотеку для генератора и большого простого числа, но пока и так пойдет

def generate_large_prime(bits=512):
    """
    Генерация большого простого числа для p
    :param bits:
    :return:
    """
    
    prime = nextprime(random.getrandbits(bits))
    return prime

def diffie_hellman(p: int, g: int):
    """
    Реализация обмена ключами по протоколу Диффи-Хеллмана.
    :param p: Простое число (модуль).
    :param g: Основание (генератор).
    : return: Приватный ключ, публичный ключ.
    """

    private_key = random.randint(1, p - 1)
    public_key = pow(g, private_key, p) #исопользуется алгоритм быстрого возведения в степень
    return private_key, public_key

def compute_shared_secret(their_public_key: int, private_key: int, p: int):
    """
    Вычисление общего секретного ключа.
    :param their_public_key: Публичный ключ другой стороны.
    :param private_key: Личный секретный ключ.
    :param p: Простое число (модуль).
    : return: Общий секретный ключ.
    """

    return pow(their_public_key, private_key, p)

def hash_shared_key(shared_key: int):
    """
    Хэширует общий секретный ключ
    :param shared_key:
    :return:
    """
    return  hashlib.sha256(str(shared_key).encode()).hexdigest()

#Это просто маленькое тестирование
if __name__ == "__main__":
    p = generate_large_prime()  # Простое число
    g = 5   # Генератор

    # Сторона A
    a_private, a_public = diffie_hellman(p, g)

    # Сторона B
    b_private, b_public = diffie_hellman(p, g)

    # Обмен ключами и вычисление общего секрета
    shared_secret_a = compute_shared_secret(b_public, a_private, p)
    shared_secret_b = compute_shared_secret(a_public, b_private, p)

    # Проверка совпадения секретов
    assert shared_secret_a == shared_secret_b, "Секреты не совпадают!"

    print(f"Общий секретный ключ: {shared_secret_a}")

    print("Hash public key A: ", hash_shared_key(shared_secret_a))
    print("Hash public key B: ", hash_shared_key(shared_secret_b))
