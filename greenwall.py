from itertools import product
from string import ascii_lowercase, ascii_uppercase

from crypto import collect_to_str, AsciiTranslationTable

MULT_INV = [None] + [pow(i, -1, 29) for i in range(1, 29)]
PUNCT = ' ,.'
ALPHA_UPPER = ascii_uppercase + PUNCT
ALPHA_LOWER = ascii_lowercase + PUNCT
TO_CODE = {c: i for i, c in enumerate(ALPHA_UPPER)}


def _to_code(c):
	return TO_CODE[c.upper()]

def _enc(x, horiz_value, vert_value, block_value):
	return ((block_value * x + horiz_value) * vert_value) % 29

def _dec(x, horiz_value, vert_value, block_value):
	return ((MULT_INV[vert_value] * x - horiz_value) * MULT_INV[block_value]) % 29


class Greenwall:
	
	def __init__(self, horizontal, vertical):
		self.horiz_values = [_to_code(h) for h in horizontal]
		self.vert_values = [_to_code(v) + 1 for v in vertical]
		
	def _iter_values(self):
		block_num = 0
		while True:
			b = (block_num % 28) + 1
			for v in self.vert_values:
				for h in self.horiz_values:
					yield h, v, b
			block_num += 1
	
	@collect_to_str
	def _cipher(self, message, mode, alphabet):
		for c, (h, v, b) in zip(message, self._iter_values()):
			yield alphabet[mode(_to_code(c), h, v, b)]


	def encrypt(self, message):
		return self._cipher(message, _enc, ALPHA_UPPER)

	def decrypt(self, message):
		return self._cipher(message, _dec, ALPHA_LOWER)


if __name__ == '__main__':
	import argparse
	import functools
	from string import ascii_letters

	import cryptoshell

	parser = argparse.ArgumentParser(
		description=f"Applies the Greenwall Cipher to a message. {cryptoshell.MODE_HELP}",
		epilog='Invented by Max Koren and Oliver Hammond in 2006.')
	cryptoshell.input_args(parser)
	parser.add_argument('-z', '--horizontal', type=str, required=True, metavar='HORIZ', 
		help='the horizontal (additive) keyword')
	parser.add_argument('-v', '--vertical', type=str, required=True, metavar='VERT', 
		help='the vertical (multiplicative) keyword')
	cryptoshell.mode_args(parser)	
	args = parser.parse_args()
	
	table = AsciiTranslationTable.with_letters(PUNCT)
	table.replace('\n', ' ')

	greenwall = Greenwall(args.horizontal, args.vertical)
	cryptoshell.run_cipher(args, greenwall.encrypt, greenwall.decrypt, table)
