import sys

from argparse import ArgumentParser, Namespace
from collections.abc import Callable

from crypto import BASIC_TABLE, FileType, AsciiTranslationTable

MODE_HELP = 'A message starting with a lower-case letter is assumed plaintext to be encrypted (with upper-case output), and the inverse is also true. Encrypt/decrypt can be forced with optional flags.'


def input_args(parser: ArgumentParser):
	parser.add_argument('message', nargs='?', type=str,
		help='The text of the message. May be passed with stdin instead.')


def mode_args(parser: ArgumentParser):
	mode_group = parser.add_mutually_exclusive_group()
	mode_group.add_argument('-e', '--encrypt', action='store_true', help='encrypt mode')
	mode_group.add_argument('-d', '--decrypt', action='store_true', help='decrypt mode')


def get_message(args: Namespace):
	has_stdin = not sys.stdin.isatty()	
	if args.message is not None:
		if has_stdin:
			raise ValueError('Messaged passed through both stdin and args.')
		return args.message
	if has_stdin:
		return sys.stdin.read()
	raise ValueError('No message passed through stdin or args.')


def probe_text(s: str):
	for c in s:
		if c.isalpha():
			return c.islower()
	return True


def run_cipher(
	args: Namespace,
	encrypt: Callable[[str], str],
	decrypt: Callable[[str], str],
	text_filter: AsciiTranslationTable = BASIC_TABLE,
	probe_func: Callable[[str], bool] = probe_text):

	message = get_message(args).translate(text_filter)

	if args.encrypt:
		mode = encrypt
	elif args.decrypt:
		mode = decrypt
	else:
		mode = encrypt if probe_func(message) else decrypt

	print(mode(message), end='')
