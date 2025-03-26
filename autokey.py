from collections import deque
from itertools import chain

from crypto import OFFSET_LOWER, OFFSET_UPPER, collect_to_str, to_code


@collect_to_str
def encrypt(message: str, key: str):
	message_code = [to_code(c) for c in message]
	key_code = (to_code(k) for k in key)
	for c, k in zip(message_code, chain(key_code, message_code)):
		yield chr(((c + k) % 26) + OFFSET_UPPER)


@collect_to_str
def decrypt(message: str, key: str):
	queue = deque(to_code(k) for k in key)
	for c in message:
		x = (to_code(c) - queue.popleft()) % 26
		queue.append(x)
		yield chr(x + OFFSET_LOWER)


if __name__ == '__main__':
	import argparse
	from functools import partial

	import cryptoshell

	parser = argparse.ArgumentParser(prog='autokey',
		description=f"Applies the Autokey Cipher to a message. {cryptoshell.MODE_HELP}")
	cryptoshell.input_args(parser)
	cryptoshell.output_args(parser)
	parser.add_argument('-k', '--key', type=str, help='the cipher key')
	cryptoshell.mode_args(parser)	
	args = parser.parse_args()

	cryptoshell.run_cipher(args,
		partial(encrypt, key=args.key), 
		partial(decrypt, key=args.key))
