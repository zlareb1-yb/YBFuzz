"""
Oracle implementations for detecting database bugs.
"""

from .base_oracle import BaseOracle
from .tlp_oracle import TLPOracle
from .qpg_oracle import QPGOracle
from .pqs_oracle import PQSOracle
from .norec_oracle import NoRECOracle
from .cert_oracle import CERTOracle
from .dqp_oracle import DQPOracle
from .coddtest_oracle import CODDTestOracle

__all__ = [
    'BaseOracle',
    'TLPOracle',
    'QPGOracle', 
    'PQSOracle',
    'NoRECOracle',
    'CERTOracle',
    'DQPOracle',
    'CODDTestOracle'
]

# Oracle registry for easy access
ORACLE_REGISTRY = {
    'TLPOracle': TLPOracle,
    'QPGOracle': QPGOracle,
    'PQSOracle': PQSOracle,
    'NoRECOracle': NoRECOracle,
    'CERTOracle': CERTOracle,
    'DQPOracle': DQPOracle,
    'CODDTestOracle': CODDTestOracle
}
