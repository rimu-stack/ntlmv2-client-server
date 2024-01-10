import asyncio

from typing import TYPE_CHECKING

import pytest

from exceptions import (
    UnknownDomainError, UnknownWorkstationError,
    InvalidNTLMMessageTypeError, InvalidNTLMSignatureError
)

if TYPE_CHECKING:
    from server import Server
    from client import Client


@pytest.mark.asyncio
async def test_correct_parse_message(client_auth: "Client", server: "Server"):
    message_type_1 = client_auth.create_negotiate_message()
    
    domain_name, workstation = server.parse_negotiate_message(message_type_1)
    nonce = server.get_challenge()
    challenge_message = server.create_challenge_message(domain_name, workstation, nonce)
    
    client_auth.parse_challenge_message(challenge_message)
    auth_message = client_auth.create_auth_message()
    
    server.parse_auth_message(auth_message)


@pytest.mark.asyncio
async def test_incorrect_signature_message(client_auth: "Client", server: "Server"):
    incorrect_message_signature = b'NOT_NTLMSSP\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0e\x00\x0e\x00(\x00\x00\x00\x16\x00\x16\x006\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x00o\x00m\x00a\x00i\x00n\x003\x00w\x00o\x00r\x00k\x00s\x00t\x00a\x00t\x00i\x00o\x00n\x00'

    with pytest.raises(InvalidNTLMSignatureError):
        server.parse_negotiate_message(incorrect_message_signature)
    
    with pytest.raises(InvalidNTLMSignatureError):
        server.parse_auth_message(incorrect_message_signature)
    
    with pytest.raises(InvalidNTLMSignatureError):
        client_auth.parse_challenge_message(incorrect_message_signature)


@pytest.mark.asyncio
async def test_incorrect_type_message(client_auth: "Client", server: "Server"):
    negotiate_message = b'NTLMSSP\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0e\x00\x0e\x00(\x00\x00\x00\x16\x00\x16\x006\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x00o\x00m\x00a\x00i\x00n\x003\x00w\x00o\x00r\x00k\x00s\x00t\x00a\x00t\x00i\x00o\x00n\x00'
    challenge_message = b'NTLMSSP\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00A\x15\x9e\x02\x8a\xb0c\xea\x00\x00\x00\x00\x00\x00\x00\x00B\x00B\x008\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00&\x00w\x00o\x00r\x00k\x00s\x00t\x00a\x00t\x00i\x00o\x00n\x00.\x00d\x00o\x00m\x00a\x00i\x00n\x003\x00\x07\x00\x08\x00\x80\x83\xd8\x11w\x84e\x10\x06\x00\x04\x00\x02\x00\x00\x00\x00\x00\x00\x00'
    auth_message = b'NTLMSSP\x00\x03\x00\x00\x00\x0e\x00\x0e\x00,\x00\x00\x00\n\x00\n\x00:\x00\x00\x00\x16\x00\x16\x00D\x00\x00\x00 \x00 \x00Z\x00\x00\x00d\x00o\x00m\x00a\x00i\x00n\x003\x00L\x00O\x00G\x00I\x00N\x00w\x00o\x00r\x00k\x00s\x00t\x00a\x00t\x00i\x00o\x00n\x00w)!\xf2\x81r\xb43\xa6\x1af6(\xab62\x80\x83\xd8\x11w\x84e\x10\x1d"\x03{\xf5%\xe8@'

    with pytest.raises(InvalidNTLMMessageTypeError):
        server.parse_negotiate_message(challenge_message)
    
    with pytest.raises(InvalidNTLMMessageTypeError):
        server.parse_auth_message(negotiate_message)
    
    with pytest.raises(InvalidNTLMMessageTypeError):
        client_auth.parse_challenge_message(auth_message)


@pytest.mark.asyncio
async def test_old_auth_message(server_with_negative_ttl: "Server"):
    auth_message = b'NTLMSSP\x00\x03\x00\x00\x00\x0e\x00\x0e\x00,\x00\x00\x00\n\x00\n\x00:\x00\x00\x00\x16\x00\x16\x00D\x00\x00\x00 \x00 \x00Z\x00\x00\x00d\x00o\x00m\x00a\x00i\x00n\x003\x00L\x00O\x00G\x00I\x00N\x00w\x00o\x00r\x00k\x00s\x00t\x00a\x00t\x00i\x00o\x00n\x00w)!\xf2\x81r\xb43\xa6\x1af6(\xab62\x80\x83\xd8\x11w\x84e\x10\x1d"\x03{\xf5%\xe8@'
    queue = asyncio.Queue()

    await server_with_negative_ttl.process_auth_message(auth_message, queue)
    result = await queue.get()

    assert result == b""


@pytest.mark.asyncio
async def test_unknonw(
    client_unknow_domain: "Client",
    client_unknow_workstation: "Client",
    server: "Server"
):
    queue = asyncio.Queue()
    negotiate_message = client_unknow_domain.create_negotiate_message()

    with pytest.raises(UnknownDomainError):
        await server.process_negotiate_message(negotiate_message, queue)
    
    negotiate_message = client_unknow_workstation.create_negotiate_message()
    
    with pytest.raises(UnknownWorkstationError):
        await server.process_negotiate_message(negotiate_message, queue)