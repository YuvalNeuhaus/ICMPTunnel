import iptc
from utils import TunnelSide
from consts import *

class IPTablesRule():
	"""
	IPTables rule interface class
	"""
	def __init__(self):
		self.chain = self._get_chain()
		self.rule = self._create_rule()

	def _get_chain(self):
		raise NotImplementedError

	def _create_rule(self):
		raise NotImplementedError

	def insert_to_chain(self):
		"""
		Inserts the rule to the chain
		"""
		self.chain.insert_rule(self.rule)

	def delete_from_chain(self):
		"""
		Deletes the rule from the chain
		"""
		self.chain.delete_rule(self.rule)	


class IPTablesLoopbackRule(IPTablesRule):
	"""
	IPTables rule that drops TCP packets on the loopback interface
	"""
	def __init__(self, port, tunnel_side):
		"""
		Initializes the rule.
		:param port: TCP port to drop on INPUT chain (int)
		:param tunnel_side: The tunnel side (server/client) (TunnelSide)
		"""
		self.port = port
		self._tunnel_side = tunnel_side
		super().__init__()

	def _get_chain(self):
		"""
		Returns an 'INPUT' chain object
		"""
		return iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")

	def _create_rule(self):
		"""
		Creates the loopback TCP packets dropping rule
		"""
		rule = iptc.Rule()
		rule.in_interface = LOOPBACK_DEVICE
		rule.dst = LOOPBACK_IP_ADDR
		rule.src = LOOPBACK_IP_ADDR
		rule.create_target("DROP")
		rule.protocol = 'tcp'
		match = rule.create_match('tcp')
		if self._tunnel_side == TunnelSide.server:
			match.sport = str(self.port)
		else:
			match.dport = str(self.port)
		return rule


class IPTablesICMPRule(IPTablesRule):
	"""
	IPTables rule ICMP packets dropping
	"""
	def __init__(self, ip):
		"""
		Initializes the rule.
		:param IP: IP address to drop on OUTPUT chain (str)
		"""
		self._ip = ip
		self.rule = self._create_rule()
		super().__init__()

	def _get_chain(self):
		"""
		Returns an 'OUTPUT' chain object
		"""
		return iptc.Chain(iptc.Table(iptc.Table.FILTER), 'OUTPUT')

	def _create_rule(self):
		"""
		Creates the ICMP packets dropping rule
		"""
		rule = iptc.Rule()
		rule.protocol = 'icmp'
		rule.dst = self._ip
		rule.create_target('DROP')
		return rule
