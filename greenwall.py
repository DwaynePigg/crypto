from itertools import product
from string import ascii_lowercase, ascii_uppercase

from crypto import batched_lenient, collect_to_str, make_filter

MULT_INV = [None] + [pow(i, -1, 29) for i in range(1, 29)]
PUNCT = ' ,.'
ALPHA_UPPER = ascii_uppercase + PUNCT
ALPHA_LOWER = ascii_lowercase + PUNCT
TO_CODE = {c: i for i, c in enumerate(ALPHA_UPPER)}


def _to_code(c):
	return TO_CODE[c.upper()]

def _enc(x, h, v, b):
	return ((b * x + h) * v) % 29

def _dec(x, h, v, b):
	return ((MULT_INV[v] * x - h) * MULT_INV[b]) % 29


@collect_to_str
def _greenwall(message, key_horiz, key_vert, mode, code_to_letter):
	horiz = [_to_code(h) for h in key_horiz]
	vert = [_to_code(v) + 1 for v in key_vert]	
	def iter_params():
		block_num = 0
		while True:
			b = (block_num % 28) + 1
			for v in vert:
				for h in horiz:
					yield h, v, b
			block_num += 1

	for c, (h, v, b) in zip(message, iter_params()):
		yield code_to_letter[mode(_to_code(c), h, v, b)]


def encrypt(message, key_horiz, key_vert):
	return _greenwall(message, key_horiz, key_vert, _enc, ALPHA_UPPER)

def decrypt(message, key_horiz, key_vert):
	return _greenwall(message, key_horiz, key_vert, _dec, ALPHA_LOWER)


if __name__ == '__main__':
	import argparse
	import functools

	import cryptoshell

	parser = argparse.ArgumentParser(prog='greenwall',
		description=f"Applies the world-famous Greenwall Cipher to a message. {cryptoshell.MODE_HELP}",
		epilog='Algorithm by Max Koren and Oliver Hammond.')
	cryptoshell.input_args(parser)
	cryptoshell.output_args(parser)
	parser.add_argument('-z', '--horizontal', type=str, required=True, metavar='HORIZ', 
		help='the horizontal (additive) keyword')
	parser.add_argument('-v', '--vertical', type=str, required=True, metavar='VERT', 
		help='the vertical (multiplicative) keyword')
	cryptoshell.mode_args(parser)	
	args = parser.parse_args()

	keys = dict(key_horiz=args.horizontal, key_vert=args.vertical)
	cryptoshell.run_cipher(args,
		functools.partial(encrypt, **keys),
		functools.partial(decrypt, **keys),
		make_filter(PUNCT))
