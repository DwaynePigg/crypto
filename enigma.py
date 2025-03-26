import sys
import argparse

parser = argparse.ArgumentParser(
	prog='enigma',
	description='Encrypts a message using the Enigma Machine.')
input_group = parser.add_mutually_exclusive_group(required=True)
input_group.add_argument('message', nargs='?', type=str, help='the text of the message')
input_group.add_argument('-in', metavar='FILE', dest='in_file', type=str, help='a file containing the message')
input_group.add_argument('-a', '--alpha', action='store_true', help='compute the full alphabet')
parser.add_argument('-order', type=str, required=True, help='the rotor orders')
parser.add_argument('-pos', type=str, required=True, help='the starting positions of the rotors')
parser.add_argument('-plug', type=str, help='the plugboard in the format AB,CD...')
parser.add_argument('-rotors', nargs='+', type=str)

args = parser.parse_args()

print(args)

order = [int(p) for p in args.order]
positions = args.pos

plugboard = {}
if args.plug:
	for a, b in args.plug.split(','):
		plugboard[a] = b
		plugboard[b] = a


