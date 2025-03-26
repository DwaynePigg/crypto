from argparse import ArgumentParser, Namespace
from collections.abc import Callable

from crypto import ALPHA_FILTER, FileType, TranslateTable

MODE_HELP = "A message starting with a lower-case letter is assumed plaintext to be encrypted (with upper-case output), and the inverse is also true. Encrypt/decrypt can be forced with optional flags."


def input_args(parser: ArgumentParser):
	input_group = parser.add_mutually_exclusive_group(required=True)
	input_group.add_argument('message', nargs='?', type=str, 
		help='the text of the message')
	input_group.add_argument('-i', '--input', metavar='FILE', dest='in_file', type=str,
		help='a file containing the message')


def mode_args(parser: ArgumentParser):
	mode_group = parser.add_mutually_exclusive_group()
	mode_group.add_argument('-e', '--encrypt', action='store_true', help='encrypt mode')
	mode_group.add_argument('-d', '--decrypt', action='store_true', help='decrypt mode')


def output_args(parser: ArgumentParser):
	parser.add_argument('-o', '--output', metavar='FILE', dest='out_file', type=str,
			help='destination for output; print to STDOUT by default')


def str_or_file(s: str, file: FileType):
	if s is not None:
		return s
	else:
		with open(file) as f:
			return f.read()


def get_message(args: Namespace):
	return str_or_file(args.message, args.in_file)


def write_output(text: str, args: Namespace):
	file = args.out_file
	if file is not None:
		with open(file, 'w') as f:
			f.write(text)
	else:
		print(text, end='')


def probe_text(s: str):
	for c in s:
		if c.isalpha():
			return c.islower()
	return True


def run_cipher(
	args: Namespace,
	encrypt: Callable[[str], str],
	decrypt: Callable[[str], str],
	text_filter: TranslateTable = ALPHA_FILTER,
	probe_func: Callable[[str], bool] = probe_text):

	message = get_message(args).translate(text_filter)

	if args.encrypt:
		mode = encrypt
	elif args.decrypt:
		mode = decrypt
	else:
		mode = encrypt if probe_func(message) else decrypt

	write_output(mode(message), args)
