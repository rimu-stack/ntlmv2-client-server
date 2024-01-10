import struct
import asyncio
import base64

from typing import Dict, Tuple, NoReturn

from base import Base
from constants import NTLM_SIGNATURE, MessageTypes, NegotiateFlags, AvId, AvFlags
from exceptions import (
    UnknownDomainError, UnknownWorkstationError, UnknownUserError,
    InvalidNTLMMessageTypeError, InvalidNTLMSignatureError
)


class Server(Base):
    _credentions: Dict[str, Dict[str, Dict[str, bytes]]] = {}
    """
    {
        domain: {
            workstation: {
                login: password
            }
        }
    }
    """

    _sessions: Dict[asyncio.Queue, bytes] = {}
    """Сессии клиентов на основе очередей и server_challenge"""

    ttl_in_seconds: int
    """Таймаут для ответного сообщения, замена MaxLifetime"""

    def __init__(
        self, 
        credentions: Dict[str, Dict[str, Dict[str, str]]], 
        ttl_in_seconds: int=10
    ) -> None:
        for domain in credentions.keys():
            if domain not in self._credentions.keys():
                self._credentions[domain] = {}

            for workstation in credentions[domain]:
                if workstation not in self._credentions[domain].keys():
                    self._credentions[domain][workstation] = {}

                for login, password in credentions[domain][workstation].items():
                    self._credentions[domain][workstation][login.upper()] = self._ntowfv1(password.encode('utf-16-le'))

        self.ttl_in_seconds = ttl_in_seconds * 10000000

    def parse_negotiate_message(self, message: bytes) -> Tuple[str, str]:
        """
        Парсинг NTLM_NEGOTIATE

        @param message: Байтовая строка, представляющая сообщение NTLM_NEGOTIATE

        :return: Кортеж из строк, представляющих домен и рабочую станцию

        :raises InvalidNTLMSignatureError: Если сигнатура NTLM не является корректной
        :raises InvalidNTLMMessageTypeError: Если тип сообщения NTLM не является корректным
        """

        (
            signature, message_type, negotiate_flags,
            domain_name_len, _, domain_name_buffer_offset,
            workstation_len, _, workstation_buffer_offset,
            _
        ) = struct.unpack('<8sLIHHIHHI8s', message[:40])

        if signature != NTLM_SIGNATURE:
            raise InvalidNTLMSignatureError

        if message_type != MessageTypes.NTLM_NEGOTIATE:
            raise InvalidNTLMMessageTypeError

        domain_name = message[domain_name_buffer_offset:domain_name_buffer_offset+domain_name_len]
        workstation = message[workstation_buffer_offset:workstation_buffer_offset+workstation_len]

        return domain_name.decode('utf-16-le'), workstation.decode('utf-16-le')
    
    def parse_auth_message(self, message: bytes) -> Tuple[str, str, str, bytes]:
        """
        Парсинг NTLM_AUTHENTICATE

        @param message: Байтовая строка, представляющая сообщение NTLM_AUTHENTICATE

        :return: Кортеж из строк (домен, рабочая станция, логин) и байтов (NT-ответ)

        :raises InvalidNTLMSignatureError: Если сигнатура NTLM не является корректной
        :raises InvalidNTLMMessageTypeError: Если тип сообщения NTLM не является корректным
        """

        (
            signature, message_type,
            domain_name_len, _, domain_name_buffer_offset,
            login_len, _, login_buffer_offset,
            workstation_len, _, workstation_buffer_offset,
            nt_response_len, _, nt_response_buffer_offset,
        ) = struct.unpack('<8sLHHIHHIHHIHHI', message[:44])

        if signature != NTLM_SIGNATURE:
            raise InvalidNTLMSignatureError

        if message_type != MessageTypes.NTLM_AUTHENTICATE:
            raise InvalidNTLMMessageTypeError

        domain_name = message[domain_name_buffer_offset:domain_name_buffer_offset+domain_name_len]
        workstation = message[workstation_buffer_offset:workstation_buffer_offset+workstation_len]
        login = message[login_buffer_offset: login_buffer_offset + login_len]

        nt_response = message[nt_response_buffer_offset:nt_response_buffer_offset+nt_response_len]

        return (
            domain_name.decode('utf-16-le'), 
            workstation.decode('utf-16-le'), 
            login.decode('utf-16-le'), 
            nt_response
        )
    
    def generate_target_info(self, domain_name: str, workstation: str) -> bytes:
        """
        Генерация поля TargetInfo

        @param domain_name: Строка с именем домена
        @param workstation: Строка с именем рабочей станции
        """
        
        target_info = b""

        dns_value = f"{workstation}.{domain_name}".encode('utf-16le')
        timestamp_value = self.get_timestamp()

        target_info += struct.pack("<HH", AvId.MSV_AV_DNS_COMPUTER_NAME, len(dns_value))
        target_info += dns_value

        target_info += struct.pack("<HH", AvId.MSV_AV_TIMESTAMP, len(timestamp_value))
        target_info += timestamp_value


        target_info += struct.pack("<HH", AvId.MSV_AV_FLAGS, len(struct.pack("<L", AvFlags.MIC_PROVIDED)))
        target_info += struct.pack("<L", AvFlags.MIC_PROVIDED)

        target_info += struct.pack('<HH', AvId.MSV_AV_EOL, 0)

        return target_info

    def create_challenge_message(self, domain_name: str, workstation: str, nonce: bytes) -> bytes:
        """
        Генерация сообщения NTLM_CHALLENGE

        @param domain_name: Строка с именем домена
        @param workstation: Строка с именем рабочей станции
        @param nonce: Байтовая строка, представляющая вызов (challenge) сервера
        """

        target_info_value = self.generate_target_info(domain_name, workstation)
        target_info_len = struct.pack('<H', len(target_info_value))
        target_info_max_len = struct.pack('<H', len(target_info_value))

        message = b'NTLMSSP\x00'
        message += struct.pack('<I', MessageTypes.NTLM_CHALLENGE)
        message += b'\x00' * 8 # NTLMSSP_REQUEST_TARGET
        message += struct.pack('<I', NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO)
        message += nonce
        message += b'\x00' * 8 # reserved

        message += target_info_len
        message += target_info_max_len
        message += struct.pack('<I', 56)
    
        message += b'\x00' * 8 # version
        message += target_info_value

        return message
    
    async def process_negotiate_message(self, message: bytes, queue: asyncio.Queue) -> None:
        """
        Обработка NTLM_NEGOTIATE, проверка домена и рабочей станции,
        генерация сообщение NTLM_CHALLENGE и отправка клиенту

        @param message: Байтовая строка, представляющая сообщение NTLM_NEGOTIATE
        @param queue: Очередь для взаимодействия с клиентом

        :raises UnknownDomainError: Если указанный домен не зарегистрирован
        :raises UnknownWorkstationError: Если указанная рабочая станция не зарегистрирована
        """

        domain_name, workstation = self.parse_negotiate_message(message)

        if domain_name not in self._credentions.keys():
            raise UnknownDomainError
        
        if workstation not in self._credentions[domain_name].keys():
            raise UnknownWorkstationError
        
        server_challenge = self.get_challenge()
        challenge_message = self.create_challenge_message(
            domain_name, 
            workstation, 
            server_challenge
        )
        challenge_message = base64.b64encode(challenge_message)

        self._sessions[queue] = server_challenge

        await queue.put(challenge_message)
    
    async def process_auth_message(self, message: bytes, queue: asyncio.Queue) -> None:
        """
        Обработка NTLM_AUTHENTICATE, проверка аутентификации пользователя
        и отправка клиенту

        @param message: Байтовая строка, представляющая сообщение NTLM_NEGOTIATE
        @param queue: Очередь для взаимодействия с клиентом

        :raises UnknownDomainError: Если указанный домен не зарегистрирован
        :raises UnknownWorkstationError: Если указанная рабочая станция не зарегистрирована
        :raises UnknownUserError: Если указанный пользователь не зарегистрирован
        """

        # допустим
        auth_failed_message = b''
        auth_successful_message = b'1'
        
        domain_name, workstation, login, client_nt_response = self.parse_auth_message(message)

        # сравнение mic обязательно, если не совпадает, то отказ
        # из-за этого нет обработки исключения в удалени server_challenge из self._sessions

        _, temp_bytes = client_nt_response[:16], client_nt_response[16:]
        timestamp, client_challenge = temp_bytes[:8], temp_bytes[8:]

        timestamp_from_challenge_message = struct.unpack("<Q", timestamp)[0]
        timestamp_now = struct.unpack("<Q", self.get_timestamp())[0]

        if timestamp_now > timestamp_from_challenge_message + self.ttl_in_seconds:
            await queue.put(auth_failed_message)
            return
        
        if domain_name not in self._credentions.keys():
            raise UnknownDomainError
        
        if workstation not in self._credentions[domain_name].keys():
            raise UnknownWorkstationError
        
        if login not in self._credentions[domain_name][workstation].keys():
            raise UnknownUserError
        
        server_challenge = self._sessions.pop(queue)

        server_nt_response, _ = self._get_nt_response(
            login.encode('utf-16-le'),
            self._credentions[domain_name][workstation][login],
            domain_name.encode('utf-16-le'),
            client_challenge,
            server_challenge,
            timestamp
        )

        if server_nt_response == client_nt_response:
            await queue.put(auth_successful_message)
        else:
            await queue.put(auth_failed_message)
    
    async def run(self, server_queue: asyncio.Queue) -> NoReturn: # pragma: no cover
        while True:
            message, client_queue = await server_queue.get()
            message = base64.b64decode(message)

            signature, message_type = struct.unpack('<8sL', message[:12])

            if signature != NTLM_SIGNATURE:
                raise InvalidNTLMSignatureError

            if message_type == MessageTypes.NTLM_NEGOTIATE:
                asyncio.create_task(self.process_negotiate_message(message, client_queue))

            elif message_type == MessageTypes.NTLM_AUTHENTICATE:
                asyncio.create_task(self.process_auth_message(message, client_queue))

            else:
                raise InvalidNTLMMessageTypeError
