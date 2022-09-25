import select
import argparse
from sockets import ICMPTunnelClientSocket, UDPTunnelClientSocket, ClientLoopbackSocket
from consts import *
from utils import *

def client_main_loop(loopback_sock, tunnel_sock):
	"""
	Main loop. Waits for incoming packets from both sockets forever.
	"""
	while True:
		socks, _, _ = select.select([loopback_sock.sock, tunnel_sock.sock],[],[])
		for s in socks:
			if s == loopback_sock.sock:
				loopback_sock.transit_incoming_packet_to_tunnel(tunnel_sock)
			else:
				tunnel_sock.transit_incoming_packet_to_loopback(loopback_sock)	

def create_sockets(args):
	"""
	Parse user arguments and create LoopbackSocket and TunnelSocket
	"""
	if args.udp:
		tunnel_sock = UDPTunnelClientSocket(server_addr=(args.server_ip, args.udp_port), mtu=args.mtu)
	elif args.icmp:
		tunnel_sock = ICMPTunnelClientSocket(icmp_id=args.icmp_id, server_addr=args.server_ip, mtu=args.mtu)

	loopback_sock = ClientLoopbackSocket(port=args.server_port, mtu=args.mtu)
	
	return (loopback_sock, tunnel_sock)

def main(args):
	loopback_sock, tunnel_sock = create_sockets(args)
	try:
		client_main_loop(loopback_sock, tunnel_sock)
	finally:
		loopback_sock.cleanup()
		tunnel_sock.cleanup()

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-s', '--server-ip', help='Server IP', type=str, required=True)
	parser.add_argument('-t', '--server-port', help='Server TCP port', type=int, required=True)
	parser.add_argument('-u', '--udp', help='Use UDP tunnel', action='store_true')
	parser.add_argument('-p', '--udp-port', help='Tunnel UDP port', type=int)
	parser.add_argument('-i', '--icmp', help='Use ICMP tunnel', action='store_true')
	parser.add_argument('-d', '--icmp-id', help='Tunnel ICMP ID', type=int)
	parser.add_argument('--mtu', help='Maximal size for loopback packets', type=int, default=DEFAULT_MTU)
	args = parser.parse_args()
	validate_args(args)
	main(args)
