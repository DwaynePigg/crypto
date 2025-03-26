import sys
import secrets
import string
from string import ascii_uppercase as ALPHA

def exclude(letter):
	i = ALPHA.index(letter)
	return ALPHA[:i] + ALPHA[i + 1:]

ALPHABETS = {
	'25': exclude('J'),
	'26': ALPHA,
	'29': ALPHA + ' ,.',
	'36': ALPHA + string.digits,
}

def generate(alphabet, length):
	for _ in range(length):
		yield secrets.choice(alphabet)


if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(prog='random',
		description='Generates random keys for classical ciphers.')
	parser.add_argument('-alpha', metavar='ALPHABET', type=str, default=ALPHA, help='the alphabet of the key')
	parser.add_argument('length', type=int, help='the length of the key')
	parser.add_argument('out_file', type=str, nargs='?', metavar='out_file', help='destination for output')
	args = parser.parse_args()

	length = args.length
	if len(args.alpha) < 4:
		alphabet = ALPHABETS.get(args.alpha)
		if alphabet is None:
			sys.exit(f"Special alphabet {args.alpha} not found.")
	else:
		alphabet = args.alpha

	result = ''.join(generate(alphabet, length))
	
	if args.out_file is not None:
		with open(args.out_file, 'w') as f:
			f.write(result)
	else:
		print(result)
