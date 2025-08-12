"""
Oracle implementations for detecting database bugs.
"""

from .base_oracle import BaseOracle
from .base_oracle import BaseOracle
from .tlp_oracle import TLOracle
from .qpg_oracle import QPGOracle
from .pqs_oracle import PQSOracle
from .norec_oracle import NoRECOracle
from .cert_oracle import CERTOracle
from .dqp_oracle import DQPOracle
from .coddtest_oracle import CODDTestOracle

__all__ = [
    'BaseOracle',
    'TLOracle',
    'QPGOracle', 
    'PQSOracle',
    'NoRECOracle',
    'CERTOracle',
    'DQPOracle',
    'CODDTestOracle'
]

# Oracle registry for easy instantiation
ORACLE_REGISTRY = {
    'TLOracle': TLOracle,
    'QPGOracle': QPGOracle,
    'PQSOracle': PQSOracle,
    'NoRECOracle': NoRECOracle,
    'CERTOracle': CERTOracle,
    'DQPOracle': DQPOracle,
    'CODDTestOracle': CODDTestOracle
}
