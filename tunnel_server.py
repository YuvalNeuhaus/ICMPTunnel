import select
import argparse
from sockets import ICMPTunnelServerSocket, UDPTunnelServerSocket, ServerLoopbackSocket
from consts import *
from utils import *

def server_main_loop(loopback_sock, tunnel_sock):
	"""
	Infinite Main loop. Waits for incoming packets from both sockets.
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
	Parse user arguments and create LOServerSocket and TunnelServerSocket
	"""
	if args.udp_port:
		tunnel_sock = UDPTunnelServerSocket(mtu=args.mtu)
	elif args.icmp_id:
		tunnel_sock = ICMPTunnelServerSocket(icmp_id=args.icmp_id, mtu=args.mtu)

	loopback_sock = ServerLoopbackSocket(port=args.server_port, mtu=args.mtu)
	
	return (loopback_sock, tunnel_sock)

def main(args):
	loopback_sock, tunnel_sock = create_sockets(args)
	try:
		server_main_loop(loopback_sock, tunnel_sock)
	finally:
		loopback_sock.cleanup()
		tunnel_sock.cleanup()

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--server-port', help='Server TCP port', type=int, required=True)
	parser.add_argument('-u', '--udp', help='Use UDP tunnel', action='store_true')
	parser.add_argument('-p', '--udp-port', help='Tunnel UDP port', type=int)
	parser.add_argument('-i', '--icmp', help='Use ICMP tunnel', action='store_true')
	parser.add_argument('-d', '--icmp-id', help='Tunnel ICMP ID', type=int)
	parser.add_argument('--mtu', help='Maximal size for loopback packets', type=int, default=DEFAULT_MTU)
	args = parser.parse_args()
	validate_args(args)
	main(args)
