import base64
import string

import grpc
import chat_pb2
import chat_pb2_grpc
import sqlite3
import jwt
import bcrypt
import time
from concurrent import futures
import queue
import deffiehellman, rc6, serpent, cryptoContext as cc

#Dict by cryptoContext
algo_dict = {
    "rc6": rc6.RC6,
    "serpent": serpent.Serpent,
}

padding_dict = {
    "PKCS7": cc.PaddingScheme.PKCS7,
    "ZERO": cc.PaddingScheme.ZERO,
    "ISO7816": cc.PaddingScheme.ISO7816,
}

# Секретный ключ для JWT
SECRET_KEY = "supersecretkey"

# Создание базы данных пользователей
conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
""")
conn.commit()

class Room:
    def __init__(self, room_id, algorithm, mode, padding):
        self.room_id = room_id
        self.clients = {}
        self.subscribers = []

        self.algorithm = algorithm
        self.mode = mode
        self.padding = padding

        self.p = deffiehellman.generate_large_prime()
        self.g = 5

        # # Инициализация контекста шифрования
        # if self.mode in ["CBC", "CFB", "OFB"]:
        #     self.iv = b"1234567890abcdef"  # 16 байт
        #     self.crypto_context = cc.CryptoContext(
        #         algo_dict[self.algorithm.lower()],
        #         self.mode.upper(),
        #         padding_dict[self.padding.upper()],
        #         self.iv,
        #     )
        # elif self.mode == "CTR":
        #     self.nonce = None
        #     self.crypto_context = cc.CryptoContext(
        #         algo_dict[self.algorithm.lower()],
        #         self.mode.upper(),
        #         padding_dict[self.padding.upper()],
        #         nonce=self.nonce,
        #     )
        # else:
        #     self.crypto_context = cc.CryptoContext(
        #         algo_dict[self.algorithm.lower()],
        #         self.mode.upper(),
        #         padding_dict[self.padding.upper()],
        #     )

class AuthService(chat_pb2_grpc.AuthServiceServicer):
    def Register(self, request, context):
        hashed_password = bcrypt.hashpw(request.password.encode(), bcrypt.gensalt())
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (request.username, hashed_password))
            conn.commit()
            token = jwt.encode({"username": request.username, "exp": time.time() + 3600}, SECRET_KEY, algorithm="HS256")
            return chat_pb2.AuthResponse(token=token)
        except sqlite3.IntegrityError:
            context.set_code(grpc.StatusCode.ALREADY_EXISTS)
            context.set_details("Username already exists")
            return chat_pb2.AuthResponse()

    def Login(self, request, context):
        cursor.execute("SELECT password FROM users WHERE username = ?", (request.username,))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(request.password.encode(), user[0]):
            token = jwt.encode({"username": request.username, "exp": time.time() + 3600}, SECRET_KEY, algorithm="HS256")
            return chat_pb2.AuthResponse(token=token)
        else:
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details("Invalid credentials")
            return chat_pb2.AuthResponse()

class ChatService(chat_pb2_grpc.ChatServiceServicer):
    def __init__(self):
        self.rooms = {}  # Словарь для хранения комнат

    def CreateRoom(self, request, context):
        if request.room_id in self.rooms:
            context.set_code(grpc.StatusCode.ALREADY_EXISTS)
            context.set_details("Room already exists")
            return chat_pb2.RoomResponse()

        room = Room(request.room_id, request.algorithm, request.mode, request.padding)
        self.rooms[request.room_id] = room

        return chat_pb2.RoomResponse(message=f"Room '{request.room_id}' created with {request.algorithm} encryption, {request.mode} mode and {request.padding} padding.")

    def JoinRoom(self, request, context):
        if request.room_id not in self.rooms:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Комната не найдена")
            return chat_pb2.JoinRoomResponse()

        room = self.rooms[request.room_id]

        # Проверяем, есть ли уже два клиента в комнате
        if len(room.clients) >= 2:
            context.set_code(grpc.StatusCode.RESOURCE_EXHAUSTED)
            context.set_details("Комната уже заполнена")
            return chat_pb2.JoinRoomResponse()

        print(f"{len(self.rooms[request.room_id].clients)} JoinRoom .clients: {self.rooms[request.room_id].clients}")

        # Отправляем клиенту p и g
        response = chat_pb2.JoinRoomResponse(p=room.p.to_bytes((room.p.bit_length() + 7) // 8, byteorder="big"), g=room.g)
        return response

    def SendPublicKey(self, request, context):
        room_id = request.room_id
        if room_id not in self.rooms:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Комната не найдена")
            return chat_pb2.RoomResponse()

        leave_message = chat_pb2.MessageResponse(
            room_id=request.room_id,
            sender="System",
            encrypted_message=f"User '{request.username}' join chat.".encode()
        )

        room = self.rooms[room_id]

        # Добавляем сообщение в очередь для всех подписчиков
        for data in room.subscribers:
            data[-1].put(leave_message)

        room.clients[request.username] = request.public_key
        print(f"{len(self.rooms[request.room_id].clients)} JoinRoom .clients: {self.rooms[request.room_id].clients}")

        return chat_pb2.RoomResponse(message="Публичный ключ успешно принят", count_user=len(self.rooms[room_id].clients),
                                     algorithm=room.algorithm, mode=room.mode, padding=room.padding, room_id=room.room_id)

    def GenerateSessionKey(self, request, context):
        room_id = request.room_id
        if room_id not in self.rooms:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Комната не найдена")
            return chat_pb2.GenerateKeyResponse()

        room = self.rooms[room_id]

        if len(room.clients) != 2:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details("В комнате должно быть два клиента")
            return chat_pb2.GenerateKeyResponse()

        #тут буду писать в чат сообщение что ключ для пользователя username сгенерирован
        # Отправляем сообщение о выходе в чат
        leave_message = chat_pb2.MessageResponse(
            room_id=request.room_id,
            sender="System",
            encrypted_message=f"User '{request.username}' сгенерировал ключ для общения.".encode()
        )

        # Добавляем сообщение в очередь для всех подписчиков
        for data in room.subscribers:
            data[-1].put(leave_message)

        other_public_key = b''
        for username, public_key in room.clients.items():
            if (request.username != username):
                other_public_key = public_key
                break

        return chat_pb2.GenerateKeyResponse(other_public_key=other_public_key)

    def SendMessage(self, request_iterator, context):
        print("Ya in SendMessage, request_iterator - ", request_iterator)

        for message in request_iterator:
            print("message in sendMessage ", message)
            print("rooms in sendMessage: ", self.rooms)
            if message.room_id not in self.rooms:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Room not found")
                yield chat_pb2.MessageResponse()
                continue

            room = self.rooms[message.room_id]

            print("sendMEssage room_subc ", room.subscribers)

            if message.image_data:
                #Обрабатываем изображение
                message_response = chat_pb2.MessageResponse(
                        room_id=message.room_id,
                        sender=message.sender,
                        encrypted_message=message.encrypted_message,
                        image_data=message.image_data,
                        iv=message.iv,
                        nonce=message.nonce,
                    )
            else:
                #Текстовое сообщение
                message_response = chat_pb2.MessageResponse(
                    room_id=message.room_id,
                    sender=message.sender,
                    encrypted_message=message.encrypted_message,
                    iv=message.iv,
                    nonce=message.nonce,
                )

            for username, queue in room.subscribers:
                print("dobavil")
                queue.put(message_response)

    def ReceiveMessages(self, request, context):
        """Получение сообщений в режиме реального времени"""
        if request.room_id not in self.rooms:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Room not found")
            return

        room = self.rooms[request.room_id]

        q = queue.Queue(maxsize=100)
        room.subscribers.append([request.username, q])

        print(f"Room_id: {room.room_id}, room.subscribe: {room.subscribers}")

        try:
            while True:
                try:
                    message = q.get()
                    print(f'ya tyt - {message}')
                    yield message
                except queue.Empty:
                    print()
        except Exception as e:
            print(f"Error occurred: {str(e)}")
        finally:
            room.subscribers.remove([request.username, q])

    def LeaveRoom(self, request, context):
        if request.room_id not in self.rooms:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Room not found")
            return chat_pb2.RoomResponse()

        room = self.rooms[request.room_id]

        # Удаляем пользователя из комнаты
        if request.username in room.clients:
            del room.clients[request.username]

            for data in room.subscribers:
                if data[0] == request.username:
                    room.subscribers.remove(data)

            print(f"User '{request.username}' left room '{request.room_id}'.")
            print("leaveRoom room_subscribers: ", room.subscribers)

            # Отправляем сообщение о выходе в чат
            leave_message = chat_pb2.MessageResponse(
                room_id=request.room_id,
                sender="System",
                encrypted_message=f"User '{request.username}' has left the room.".encode()
            )

            # Добавляем сообщение в очередь для всех подписчиков
            for data in room.subscribers:
                data[-1].put(leave_message)

            # Если комната пуста, удаляем её
            if not room.clients:
                del self.rooms[request.room_id]
                print(f"Room '{request.room_id}' deleted as it is now empty.")

        return chat_pb2.RoomResponse(message=f"User '{request.username}' left room '{request.room_id}'.")

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    chat_pb2_grpc.add_AuthServiceServicer_to_server(AuthService(), server)
    chat_pb2_grpc.add_ChatServiceServicer_to_server(ChatService(), server)
    server.add_insecure_port("[::]:8080")
    server.start()
    print("Server started on port 8080")
    server.wait_for_termination()

if __name__ == "__main__":
    print(dir(chat_pb2))
    serve()
