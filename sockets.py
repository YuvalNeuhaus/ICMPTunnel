from scapy.arch import attach_filter, raw
from scapy.supersocket import L3RawSocket
from scapy.layers.inet import TCP, IP, ICMP
from scapy.sendrecv import send
import socket
from iptables import IPTablesICMPRule, IPTablesLoopbackRule
from consts import *
from utils import TunnelSide

class Socket():
	"""
	Class for socket.
	"""
	def __init__(self):
		"""
		Initialize socket.
		"""
		self.iptables_rule = None

	def cleanup(self):
		"""
		Cleans the iptables rule of the socket if exists
		"""
		if self.iptables_rule:
			self.iptables_rule.delete_from_chain()

class ICMPTunnelSocket(Socket):
	"""
	Class for tunnel socket in ICMP mode.
	This socket receives ICMP packets from remote server or client and forwards payload to the LoopbackSocket.
	"""
	def __init__(self, icmp_id, remote_addr, type, mtu=DEFAULT_MTU):
		"""
		Initialize socket.
		:param icmp_id: Magic ID of the tunnel (int)
		:param remote_addr: Server IP address (str)
		:param type: icmp type ('echo-reply' or 'echo-request') (str)
		:param mtu: Maximum transmission unit to use for socket recieve (int)
		"""
		super().__init__()
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		self.id = icmp_id
		self._mtu=mtu
		self.type = type
		self.remote = remote_addr

	def prepare_incoming_packet(self):
		"""
		Receives a packet and validates it's an ICMP packet with the expected ICMP id
		"""
		buff = self.sock.recv(self._mtu)
		icmp_packet = IP(buff)
		if not icmp_packet[ICMP].id == self.id:
			print("Unexpected ICMP id received")
			return
		print('ICMP socket received %d bytes' % len(buff))
		return icmp_packet
		
	@classmethod
	def transit_incoming_packet_to_loopback(cls, loopback_sock, incoming_icmp_packet):
		"""
		Transits an incoming packet from the ICMP tunnel socket to the loopback interface wrapped within a TCP packet
		"""
		tcp_data = raw(incoming_icmp_packet[ICMP].payload)
		loopback_sock.send_packet_to_loopback(tcp_data)

	def send_packet_to_tunnel(self, data):
		"""
		Build ICMP packet with input data as payload and send to remote server
		"""
		packet = IP(dst=self.remote) / ICMP(id=self.id, type=self.type) / data
		send(packet)


class ICMPTunnelServerSocket(ICMPTunnelSocket):
	"""
	Class for server side tunnel socket in ICMP mode.
	This socket receives ICMP packets from remote server or client and forwards payload to the LoopbackSocket.
	"""
	def __init__(self, icmp_id, mtu=DEFAULT_MTU):
		"""
		Initialize socket.
		:param icmp_id: Magic ID of the tunnel (int)
		:param mtu: Maximum transmission unit to use for socket recieve (int)
		"""
		super().__init__(icmp_id, None, 'echo-reply', mtu)

	def transit_incoming_packet_to_loopback(self, loopback_sock):
		"""
		Receives a from the UDP tunnel socket and transits it to the loopback interface wrapped within a TCP packet
		"""
		incoming_icmp_packet = super().prepare_incoming_packet()
		if not self.remote:
			self.remote = incoming_icmp_packet.src
			self.iptables_rule = IPTablesICMPRule(self.remote)
			self.iptables_rule.insert_to_chain()
		super().transit_incoming_packet_to_loopback(loopback_sock, incoming_icmp_packet)

class ICMPTunnelClientSocket(ICMPTunnelSocket):
	"""
	Class for client side tunnel socket in ICMP mode.
	This socket receives ICMP packets from remote server or client and forwards payload to the LoopbackSocket.
	"""
	def __init__(self, icmp_id, server_addr, mtu=DEFAULT_MTU):
		"""
		Initialize socket.
		:param icmp_id: Magic ID of the tunnel (int)
		:param mtu: Maximum transmission unit to use for socket recieve (int)
		"""
		super().__init__(icmp_id, server_addr, 'echo-request', mtu)

	def transit_incoming_packet_to_loopback(self, loopback_sock):
		"""
		Receives a from the ICMP tunnel socket and transits it to the loopback interface wrapped within a TCP packet
		"""
		incoming_icmp_packet = super().prepare_incoming_packet()
		super().transit_incoming_packet_to_loopback(loopback_sock, incoming_icmp_packet)


class UDPTunnelSocket(Socket):
	"""
	Class for tunnel socket in UDP mode.
	This socket receives UDP packets from remote server or client and forwards payload to the LoopbackSocket.
	"""
	def __init__(self, server_addr, mtu=DEFAULT_MTU):
		"""
		Initialize socket.
		:param server_addr: Server IP address ((str, int) tuple)
		:param mtu: Maximum transmission unit to use for socket recieve (int)
		"""
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self._mtu=mtu
		self.iptables_rule = None
		self.remote = server_addr

	def transit_incoming_packet_to_loopback(self, loopback_sock):
		"""
		Get data buffer from UDP socket and send data to loopback sock
		:param loopback_sock: (ServerLoopbackSocket/ClientLoopbackSocket)
		"""
		buff, self.remote = self.sock.recvfrom(self._mtu)
		loopback_sock.send_packet_to_loopback(buff)
		print('UDP socket received %d bytes' % len(buff))

	def send_packet_to_tunnel(self, data):
		"""
		Send data to remote server with UDP socket
		:param data: The packet data to send (str)
		"""
		self.sock.sendto(data, self.remote)


class UDPTunnelServerSocket(UDPTunnelSocket):
	"""
	Class for server side tunnel socket in UDP mode.
	This socket receives UDP packets from remote server or client and forwards payload to the LoopbackSocket.
	"""
	def __init__(self, tunnel_port, mtu=DEFAULT_MTU):
		"""
		Initialize socket.
		:param tunnel_port: Server IP address (int)
		:param mtu: Maximum transmission unit to use for socket recieve (int)
		"""
		super().__init__(None, mtu)
		self.sock.bind((LOCAL_IP_ADDR, tunnel_port)) 

class UDPTunnelClientSocket(UDPTunnelSocket):
	"""
	Class for client side tunnel socket in UDP mode.
	This socket receives UDP packets from remote server or client and forwards payload to the LoopbackSocket.
	"""
	def __init__(self, server_addr, mtu=DEFAULT_MTU):
		"""
		Initialize socket.
		:param server_addr: Server IP address ((str, int) tuple))
		:param mtu: Maximum transmission unit to use for socket recieve (int)
		"""
		super().__init__(server_addr, mtu)


class LoopbackSocket(Socket):
	"""
	Class for Loopback raw socket.
	This socket receives and sends TCP packets on Loopback device.
	"""
	def __init__(self, port, filter, ip_tables_rule, mtu=DEFAULT_MTU):
		"""
		Initialize socket.
		:param port: TCP port to forward in the tunnel (int)
		:param filter: The BPF filter for the socket (str)
		:param ip_tables_rule: IPTables rule to drop the loopback TCP communication (IPTablesLoopbackRule)
		:param mtu: Maximum transmission unit to use for socket recieve (int)
		"""
		self.sock = L3RawSocket(iface=LOOPBACK_DEVICE)
		self.port = port
		self._filter = filter
		attach_filter(self.sock.ins, self._filter.format(port=self.port), LOOPBACK_DEVICE)
		self.iptables_rule = ip_tables_rule
		self.iptables_rule.insert_to_chain()
		self._mtu = mtu

	def transit_incoming_packet_to_tunnel(self, tunnel_sock):
		"""
		Parse incoming packet and send TCP data to tunnel sock
		:param tunnel_sock: TCP port to forward in the tunnel (UDPTunnelServerSocket/ICMPTunnelServerSocket/UDPTunnelClientSocket/ICMPTunnelClientSocket)
		"""
		buff = self.sock.recv(self._mtu)
		tunnel_sock.send_packet_to_tunnel(raw(buff[TCP]))
		print('Loopback socket received %d bytes' % len(raw(buff)))

	def send_packet_to_loopback(self, data):
		"""
		Build raw IP packet with TCP data from input and send to loopback
		:param data: The packet data to send (str)
		"""
		packet = IP(dst=LOOPBACK_IP_ADDR) / TCP(data)
		del packet[TCP].chksum
		self.sock.send(packet)


class ServerLoopbackSocket(LoopbackSocket):
	"""
	Class for Loopback raw socket on the server side.
	This socket receives and sends TCP packets on Loopback device.
	"""
	def __init__(self, port, mtu=DEFAULT_MTU):
		"""
		Initialize socket.
		:param port: TCP port to forward in the tunnel (int)
		:param mtu: Maximum transmission unit to use for socket recieve (int)
		"""
		super().__init__(port, SERVER_BPF, IPTablesLoopbackRule(port=port, tunnel_side=TunnelSide.server), mtu)
		

class ClientLoopbackSocket(LoopbackSocket):
	"""
	Class for Loopback raw socket on the client side.
	This socket receives and sends TCP packets on Loopback device.
	"""
	def __init__(self, port, mtu=DEFAULT_MTU):
		"""
		Initialize socket.
		:param port: TCP port to forward in the tunnel (int)
		:param mtu: Maximum transmission unit to use for socket recieve (int)
		"""
		super().__init__(port, CLIENT_BPF, IPTablesLoopbackRule(port=port, tunnel_side=TunnelSide.client), mtu)
