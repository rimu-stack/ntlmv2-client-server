import asyncio

from client import Client
from server import Server


async def main():
    server_queue = asyncio.Queue()

    domain = 'domain'
    workstation = 'workstation'

    credentionals = {
        domain: {
            workstation: {
                'login': 'password'
            }
        }
    }
    client_1 = Client('login', 'password', workstation, domain)
    server = Server(credentionals, 1)

    await asyncio.gather(
        server.run(server_queue), 
        client_1.run(server_queue)
    )


if __name__ == '__main__':
    asyncio.run(main())