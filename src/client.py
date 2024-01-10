import struct
import asyncio
import base64

from typing import Dict, Tuple

from base import Base
from constants import NTLM_SIGNATURE, MessageTypes, NegotiateFlags, AvId
from exceptions import InvalidNTLMMessageTypeError, InvalidNTLMSignatureError


class Client(Base):
    login: bytes
    password: bytes
    workstation: bytes
    domain_name: bytes

    server_challenge: bytes
    target_info: Dict[int, bytes] = {}

    def __init__(
        self, 
        login: str, 
        password: str, 
        workstation: str, 
        domain_name: str
    ) -> None:
        self.login = login.upper().encode('utf-16-le')
        self.password = self._ntowfv1(password.encode('utf-16-le'))
        self.workstation = workstation.encode('utf-16-le')
        self.domain_name = domain_name.encode('utf-16-le')

    def add_fields(
        self, 
        message: bytes, 
        offset: int, 
        field_name: str
    ) -> Tuple[bytes, int]:
        """
        Добавление информации о поле в сообщение NTLM

        @param message: Байтовая строка, представляющая текущее сообщение NTLM
        @param offset: Смещение для текущего поля в сообщении
        @param field_name: Название поля, информацию о котором нужно добавить

        :return: Кортеж из обновленного сообщения и обновленного смещения
        """

        field = getattr(self, field_name)
        
        message += struct.pack('<H', len(field)) # len
        message += struct.pack('<H', len(field)) # max_len
        message += struct.pack('<I', offset) # buffer_offset

        offset += len(field)

        return message, offset

    def create_negotiate_message(self) -> bytes:
        """Генерация сообщения NTLM_NEGOTIATE"""

        payload_offset = 40

        message = NTLM_SIGNATURE
        message += struct.pack('<L', MessageTypes.NTLM_NEGOTIATE)
        message += struct.pack('<I', NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE)

        message, payload_offset = self.add_fields(message, payload_offset, 'domain_name')
        message, payload_offset = self.add_fields(message, payload_offset, 'workstation')

        message += b'\x00' * 8 # version

        payload = self.domain_name + self.workstation

        message += payload

        return message

    def create_auth_message(self) -> bytes:
        """Генерация сообщения NTLM_AUTHENTICATE"""

        # payload_offset = 72 # без MIC
        # payload_offset = 88 # с MIC

        # упрощенная моя версия
        payload_offset = 44

        client_challenge = self.get_challenge()

        # исходя их документации не должна отсылаться если был отправлен
        # сервером target_info
        # If NTLM v2 authentication is used and the CHALLENGE_MESSAGE contains 
        # a TargetInfo field, the client SHOULD NOT send the LmChallengeResponse and etc
        # self.lm_response = self._get_lm_response(
        #     self.login,
        #     self.password,
        #     self.domain_name,
        #     self.server_challenge,
        #     client_challenge,
        # )
        self.nt_response, _ = self._get_nt_response(
            self.login,
            self.password,
            self.domain_name,
            client_challenge,
            self.server_challenge,
            self.target_info[AvId.MSV_AV_TIMESTAMP]
        )

        message = NTLM_SIGNATURE
        message += struct.pack('<L', MessageTypes.NTLM_AUTHENTICATE)

        message, payload_offset = self.add_fields(message, payload_offset, 'domain_name')
        message, payload_offset = self.add_fields(message, payload_offset, 'login')
        message, payload_offset = self.add_fields(message, payload_offset, 'workstation')

        # message, payload_offset = self.add_fields(message, payload_offset, 'lm_response')
        message, payload_offset = self.add_fields(message, payload_offset, 'nt_response')
        
        # message, payload_offset = self.add_fields(message, payload_offset, 'encrypted_random_session_key')

        # message += self.negotiate_flags
        # message += self.version
        # message += mic

        payload = self.domain_name 
        payload += self.login 
        payload += self.workstation 
        payload += self.nt_response

        message += payload
        
        return message
    
    def parse_challenge_message(self, message: bytes) -> None:
        """
        Обрабатывает сообщение NTLM_CHALLENGE.

        @param message: Байтовая строка, представляющая сообщение NTLM_CHALLENGE

        :raises InvalidNTLMSignatureError: Если сигнатура NTLM не является корректной
        :raises InvalidNTLMMessageTypeError: Если тип сообщения NTLM не является корректным
        """

        (
            signature, message_type, target_info,
            negotiate_flags, server_challenge,
            reserved, target_info_len, target_info_max_len,
            target_info_offset_min, version
        ) = struct.unpack('<8sI8sI8s8sHHI8s', message[:56])

        if signature != NTLM_SIGNATURE:
            raise InvalidNTLMSignatureError

        if message_type != MessageTypes.NTLM_CHALLENGE:
            raise InvalidNTLMMessageTypeError

        target_info = message[56:target_info_offset_min+target_info_len]
        self.server_challenge = server_challenge

        attribute_type = None

        while attribute_type != AvId.MSV_AV_EOL:
            attribute_type = struct.unpack("<H", target_info[:2])[0]
            attribute_length = struct.unpack("<H", target_info[2:4])[0]
            self.target_info[attribute_type] = target_info[4:attribute_length+4]
            target_info = target_info[4+attribute_length:]
    
    async def run(self, server_queue: asyncio.Queue) -> None: # pragma: no cover
        queue = asyncio.Queue()

        negotiate_message = self.create_negotiate_message()
        negotiate_message = base64.b64encode(negotiate_message)

        await server_queue.put((negotiate_message, queue))

        challenge_message = await queue.get()
        challenge_message = base64.b64decode(challenge_message)

        self.parse_challenge_message(challenge_message)

        auth_message = self.create_auth_message()
        auth_message = base64.b64encode(auth_message)

        await server_queue.put((auth_message, queue))

        result = await queue.get()

        if result:
            print('Успешная аутентификация')
        else:
            print('Неуспешная аутентификация')
