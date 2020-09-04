from .consts import DEFAULT_HP_LPORT
from .simple_commands.app import Hypercorn

setattr(Hypercorn, 'DEFAULT_PORT', DEFAULT_HP_LPORT)