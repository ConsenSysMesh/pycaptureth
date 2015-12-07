import pyethapp.app as Pyethapp
from pyethapp.accounts import AccountsService
from pyethapp.db_service import DBService
from pyethapp.jsonrpc import JSONRPCServer
from pyethapp.pow_service import PoWService
from devp2p.app import BaseApp
from devp2p.discovery import NodeDiscovery
from devp2p.peermanager import PeerManager

from capture_service import ChainService
ChainService.start_blocks = {}

__version__ = '0.0.1'
Pyethapp.services = [
    DBService,
    NodeDiscovery,
    PeerManager,
    ChainService,
    AccountsService,
    JSONRPCServer
]

if __name__ == '__main__':
    Pyethapp.app()
