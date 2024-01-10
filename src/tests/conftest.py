import pytest

from client import Client
from server import Server


@pytest.fixture
def client_auth():
    return Client('login', 'password', "workstation", "domain")

@pytest.fixture
def client_unknow_domain():
    return Client('login', 'password', "workstation", "unknow_domain")

@pytest.fixture
def client_unknow_workstation():
    return Client('login', 'password', "unknow_workstation", "domain")

@pytest.fixture
def server():
    return Server(
        {
            'domain': {
                'workstation': {
                    'login': 'password'
                }
            }
        },
        ttl_in_seconds=10
    )

@pytest.fixture
def server_with_negative_ttl():
    return Server(
        {
            'domain': {
                'workstation': {
                    'login': 'password'
                }
            }
        },
        ttl_in_seconds=-1
    )
