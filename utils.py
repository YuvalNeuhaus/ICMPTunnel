from enum import Enum


class TunnelSide(Enum):
	client = 1
	server = 2

def validate_args(args):
	if args.udp and args.icmp:
		raise Exception("Only one of UDP/ICMP can be used")
	if not args.udp and not args.icmp:
		raise Exception("You must use UDP or ICMP")
	if args.udp and not args.udp_port:
		raise Exception("UDP must be used together with udp-port")
	if args.icmp and not args.icmp_id:
		raise Exception("ICMP must be used together with icmp-id")
