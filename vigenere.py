from itertools import cycle

from crypto import OFFSET_LOWER, OFFSET_UPPER, collect_to_str, to_code


@collect_to_str
def vigenere(message: str, key: str, sign: int, offset: int):
	for c, k in zip(message, cycle(sign * to_code(k) for k in key)):
		yield chr((to_code(c) + k) % 26 + offset)


def encrypt(message: str, key: str):
	return vigenere(message, key, +1, OFFSET_UPPER)


def decrypt(message: str, key: str):
	return vigenere(message, key, -1, OFFSET_LOWER)


if __name__ == '__main__':
	import argparse
	from functools import partial

	import cryptoshell

	parser = argparse.ArgumentParser(
		prog='vigenere',
		description=f"Applies the Vigenère Cipher to a message. {cryptoshell.MODE_HELP}")
	cryptoshell.input_args(parser)
	cryptoshell.output_args(parser)
	key_group = parser.add_mutually_exclusive_group(required=True)
	key_group.add_argument('-k', '--key', type=str, 
		help='the cipher key')
	key_group.add_argument('-p', '--pad', metavar='FILE', type=str,
		help='a file containing the cipher key (ideal for one-time pads)')
	cryptoshell.mode_args(parser)
	args = parser.parse_args()

	key = cryptoshell.str_or_file(args.key, args.pad)
	cryptoshell.run_cipher(args, 
		partial(encrypt, key=key),
		partial(decrypt, key=key))
