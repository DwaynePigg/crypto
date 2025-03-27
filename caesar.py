import itertools
from crypto import OFFSET_LOWER, OFFSET_UPPER, to_code


def iter_shift(message: str, key: int, offset: int | None = None):
	if offset is None:
		offset = OFFSET_UPPER if key > 0 else OFFSET_LOWER
	for c in message:
		x = to_code(c)
		if 0 <= x < 26:
			yield chr(((x + key) % 26) + offset)
		else:
			yield c


def analyze(message: str, max_len: int | None = None, sign: int = -1, offset=OFFSET_LOWER):
	for e in range(1, 26):
		yield ''.join(itertools.islice(iter_shift(
			message, sign * e, offset), max_len))


if __name__ == '__main__':
	import argparse
	import cryptoshell

	parser = argparse.ArgumentParser(
		description="Tests all possible Caesar shifts of an encrypted message. Looking to actually *use* the Caesar cipher? Just run vigenere with a one-letter key.")
	cryptoshell.input_args(parser)
	cryptoshell.mode_args(parser)
	parser.add_argument('-a', '--analyze', type=int, default=75, help='The maximum length of each shift. Defaults to 75. Use 0 for no limit.')
	args = parser.parse_args()
	message = cryptoshell.get_message(args)
	sign, offset = (1, OFFSET_UPPER) if args.encrypt else (-1, OFFSET_LOWER)
	max_len = args.analyze or None
	cryptoshell.write_output('\n'.join(
		f"{chr(i + OFFSET_UPPER)}:{shift}" for i, shift in 
		enumerate(analyze(message, max_len, sign, offset), start=1)), args)
