from itertools import chain, cycle

from crypto import OFFSET_LOWER, OFFSET_DIGIT, add_unique, batched, collect_to_str, AsciiTranslationTable


def _to_code(a):
	c = ord(a)
	if c >= OFFSET_UPPER:
		return (c - OFFSET_UPPER) & 0x1F
	return c - OFFSET_DIGIT


class Adfgvx:

	def __init__(self, grid, keyword, coord='ADFGVX'):
		# TODO: make this numeric and avoid dicts?
		coord = coord.upper()
		subs = {}
		inv_subs = {}
		unique = set()
		for i, row in enumerate(grid):
			for j, c in enumerate(row):
				if not add_unique(unique, c):
					raise ValueError(f"duplicate grid char: {c}")
				s = (coord[i], coord[j])
				subs[c.lower()] = s
				inv_subs[s] = c.upper()
		self.subs = subs
		self.inv_subs = inv_subs
		self.keyword = keyword
		self.inv_keyword = get_inv_keyword(keyword)

	@collect_to_str
	def encrypt(self, message, pad_char='X'):
		subs = chain.from_iterable(self.subs[c.lower()] for c in message)
		pad = cycle(self.subs[pad_char.lower()])
		rows = batched(subs, len(self.keyword), pad)
		columns = zip(*rows)
		scrambled = scramble(columns, self.keyword)
		for column in scrambled:
			yield from column

	@collect_to_str
	def decrypt(self, message):
		col_len = len(message) // len(self.keyword)
		columns = batched(message, col_len)
		unscrambled = scramble(columns, self.inv_keyword)
		rows = zip(*unscrambled)
		subs = chain.from_iterable(rows)
		inv_subs = self.inv_subs
		for c1, c2 in batched(subs, 2, drop=True):
			yield inv_subs[(c1.upper(), c2.upper())].lower()


def scramble(columns, keyword):
	for _, column in sorted(zip(keyword, columns)):
		yield column


def get_inv_keyword(keyword):
	indexed = sorted((c, i) for i, c in enumerate(keyword))
	return [i for _, i in indexed]


if __name__ == '__main__':
	import argparse
	import math
	import string

	import cryptoshell

	parser = argparse.ArgumentParser(prog='adfgvx',
		description=f"Applies the ADFGVX Cipher to a message. {cryptoshell.MODE_HELP}")
	cryptoshell.input_args(parser)
	parser.add_argument('-g', '--grid', type=str, required=True,
		help='The full text of the substitution grid. Row separators (such as commas) may be included, as all invalid characters are ignored.')
	parser.add_argument('-k', '--keyword', type=str, required=True,
		help='the transposition keyword')
	parser.add_argument('-c', '--coordinates', metavar='COORD', type=str,
		help='The letters to use for the grid coordinates. Defaults to ADFGVX for a 6x6 grid and ADFGX for 5x5.')
	parser.add_argument('-p', '--pad', type=str,
		help='the pad character to fill out an incomplete row. Defaults to X.')
	cryptoshell.mode_args(parser)
	args = parser.parse_args()
	text_filter = AsciiTranslationTable.with_letters(string.digits)

	grid = args.grid.translate(text_filter)

	side_len = math.isqrt(len(grid))
	if side_len ** 2 != len(grid):
		raise ValueError(f"Grid must be a square but had length {len(grid)}")

	coord = args.coordinates
	if not coord:
		if side_len == 6:
			coord = 'ADFGVX'
		elif side_len == 5:
			coord = 'ADFGX'
		else:
			raise ValueError(f"Coordinates must be specified for grid of length {side_len}x{side_len}")
	elif len(coord) != side_len:
		raise ValueError(f"Coordinates have length {side_len} to match size of grid")

	cipher = Adfgvx(batched(grid, side_len), args.keyword, coord)
	cryptoshell.run_cipher(args, cipher.encrypt, cipher.decrypt, text_filter)
