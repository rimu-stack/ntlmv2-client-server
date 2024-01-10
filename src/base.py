import os
import time
import hmac
import hashlib
import asyncio
import struct

from typing import Tuple


class Base:
    def get_challenge(self) -> bytes:
        """
        Генерация случайного значения (challenge) из 8 байт
        """

        return os.urandom(8)

    def get_timestamp(self) -> bytes:
        """
        Получение текущей временной метки в формате, используемом в Windows
        """

        # Время в секундах с начала эпохи (01 января 1970 года)
        seconds_since_origin = int(time.time()) + 116444736000

        # Количество 100-наносекундных интервалов с начала эпохи (01 января 1601 года)
        return struct.pack('<q', seconds_since_origin * 10000000)
    
    def _ntowfv1(self, password: bytes) -> bytes:
        """
        Преобразование пароля в NTLMv1-хэш, используя алгоритм MD5

        @param password: Байтовая строка, представляющая пароль
        """

        return hashlib.new('md5', password).digest()
    
    def _ntowfv2(self, user_name: bytes, password: bytes, domain_name: bytes) -> bytes:
        """
        Преобразование пароля, имени пользователя и имени домена в NTLMv2-хэш, используя алгоритм HMAC-MD5

        @param user_name: Байтовая строка, представляющая имя пользователя
        @param password: Байтовая строка, представляющая пароль
        @param domain_name: Байтовая строка, представляющая имя домена
        """

        return hmac.new(
            password,
            user_name + domain_name, 
            digestmod=hashlib.md5
        ).digest()
    
    def _get_lm_response(
        self, 
        login: bytes, 
        password: bytes, 
        domain_name: bytes, 
        client_challenge: bytes, 
        server_challenge: bytes, 
    ) -> bytes:
        """
        Генерация LM Response

        @param login: Байтовая строка, представляющая имя пользователя
        @param password: Байтовая строка, представляющая пароль пользователя
        @param domain_name: Байтовая строка, представляющая имя домена
        @param client_challenge: Байтовая строка, представляющая вызов (challenge) клиента
        @param server_challenge: Байтовая строка, представляющая вызов (challenge) сервера
        """

        nt_hash = self._ntowfv2(
            login,
            password,
            domain_name
        )
        challenge = server_challenge + client_challenge
 
        lm_hash = hmac.new(
            nt_hash, 
            challenge, 
            digestmod=hashlib.md5
        ).digest()
        
        return lm_hash + client_challenge
    
    def _get_nt_response(
        self, 
        login: bytes, 
        password: bytes, 
        domain_name: bytes, 
        client_challenge: bytes, 
        server_challenge: bytes, 
        timestamp: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Генерация NT Response

        @param login: Байтовая строка, представляющая имя пользователя
        @param password: Байтовая строка, представляющая пароль пользователя
        @param domain_name: Байтовая строка, представляющая имя домена
        @param client_challenge: Байтовая строка, представляющая вызов (challenge) клиента
        @param server_challenge: Байтовая строка, представляющая вызов (challenge) сервера
        @param server_challenge: Байтовая строка, представляющая время от сервера
        """

        nt_hash = self._ntowfv2(
            login,
            password,
            domain_name
        )

        # temp_bytes = (
        #     timestamp + client_challenge \
        #     target_info как в сообщении type_2 от сервера + другие байты
        # )
        temp_bytes = timestamp + client_challenge
        nt_proof_str = hmac.new(
            nt_hash,
            (server_challenge + temp_bytes),
            digestmod=hashlib.md5
        ).digest()

        response = nt_proof_str + temp_bytes
 
        session_base_key = hmac.new(
            nt_hash, 
            nt_proof_str,
            digestmod=hashlib.md5
        ).digest()

        return response, session_base_key
    
    async def run(self, server_queue: asyncio.Queue) -> None:
        """
        Запуск обмена данными
        
        @param server_queue: Очередь для взаимодействия с сервером

        :raises InvalidNTLMSignatureError: Если сигнатура NTLM не является корректной
        :raises InvalidNTLMMessageTypeError: Если тип сообщения NTLM не является корректным
        """

        raise NotImplementedError
