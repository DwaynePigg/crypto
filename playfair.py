from collections.abc import Iterable, Sequence
from itertools import chain
from string import ascii_uppercase

from crypto import add_unique, to_code, batched, collect_to_str

Grid = Sequence[Sequence[str]]


def make_key(keyword: str, combine='IJ'):
	share, replace = combine
	letters = chain(keyword.upper(), ascii_uppercase)
	seen = set()
	while len(seen) < 25:
		a = next(letters)
		if a == replace:
			a = share
		if add_unique(seen, a):
			yield a


def _create_lookup(grid: Grid, combine='IJ'):
	lookup: list[tuple[int, int]] = [None] * 26
	for i, row in enumerate(grid):
		for j, a in enumerate(row):
			lookup[to_code(a)] = i, j
	if combine:
		share, replace = combine
		lookup[to_code(replace)] = lookup[to_code(share)]
	return lookup


def _ensure_ciphertext(message: str):
	for a1, a2 in batched(message, 2):
		c1 = to_code(a1)
		c2 = to_code(a2)
		if c1 == c2:
			raise ValueError(f"ciphertext has double {c1}")
		yield c1, c2


class Playfair:

	def __init__(self, grid: Grid, separator='X', alt_separator='Q', combine='IJ'):
		self.grid = grid
		self.separator = to_code(separator)
		self.alt_separator = to_code(alt_separator)
		self.lookup = _create_lookup(grid, combine)

	@classmethod
	def from_keyword(cls, keyword, separator='X', alt_separator='Q', combine='IJ'):
		grid = list(batched(make_key(keyword, combine), 5))
		return cls(grid, separator, alt_separator, combine)
	
	def _separator_for(self, c: int):
		return self.separator if c != self.separator else self.alt_separator

	def _separate_doubles(self, message: str):
		i = 0
		msg_len = len(message)
		while True:
			rem = msg_len - i
			if rem == 0:
				return

			c1 = to_code(message[i])
			if rem == 1:
				yield c1, self._separator_for(c1)
				return	

			c2 = to_code(message[i + 1])
			if c1 == c2:
				c2 = self._separator_for(c1)
				i += 1
			else:
				i += 2
			yield c1, c2

	def encode_pair(self, c1: int, c2: int, shift: int = 1):
		row1, col1 = self.lookup[c1]
		row2, col2 = self.lookup[c2]
		if row1 == row2:
			return (
				self.grid[row1][(col1 + shift) % 5], 
				self.grid[row1][(col2 + shift) % 5])
		if col1 == col2:
			return (
				self.grid[(row1 + shift) % 5][col1], 
				self.grid[(row2 + shift) % 5][col1])
		return (
			self.grid[row1][col2],
			self.grid[row2][col1])

	@collect_to_str
	def _process(self, message: Iterable[tuple[str, str]], shift: int):
		for c1, c2 in message:
			yield from self.encode_pair(c1, c2, shift)


	def encrypt(self, message: str):
		return self._process(self._separate_doubles(message), 1).upper()


	def decrypt(self, message: str):
		return self._process(_ensure_ciphertext(message), -1).lower()


if __name__ == '__main__':
	import argparse
	import sys

	import cryptoshell

	parser = argparse.ArgumentParser(
		description=f"Applies the Playfair Cipher to a message. {cryptoshell.MODE_HELP}",
		epilog='Invented by Sir Charles Wheatstone in 1854, popularized by Lord Playfair.')
	cryptoshell.input_args(parser)
	parser.add_argument('-k', '--key', type=str, required=True,
		help='The cipher key, which may be the full grid or a keyword. Row separators (such as commas) may be included, as all invalid characters are ignored.')
	parser.add_argument('-s', '--separator', type=str, default='XQ',
		help='The letter for separating double letters and padding an odd-length message. If two letters are given, the second is used to separate doubles of the first letter if they occur. (default: XQ)')
	parser.add_argument('-c', '--combine', type=str, default='IJ',
		help='The letter pair that must be combined when using a 5x5 grid. The first letter stands in for the second. (default: IJ)')
	cryptoshell.mode_args(parser)
	args = parser.parse_args()

	separators = args.separator.upper()
	separator = separators[0]
	if len(separators) >= 2:
		alt_separator = separators[1]
		if separator == alt_separator:
			raise ValueError('Separators must be different')
	else:
		alt_separator = 'Q' if separator != 'Q' else 'X'

	cipher = Playfair.from_keyword(args.key, separator, alt_separator, args.combine)
	cryptoshell.run_cipher(args, cipher.encrypt, cipher.decrypt)
