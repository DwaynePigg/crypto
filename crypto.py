import string
from collections.abc import Callable, Iterable
from itertools import chain, islice
from os import PathLike
from string import ascii_letters
from types import SimpleNamespace
from typing import Mapping, ParamSpec, Sequence

OFFSET_DIGIT = ord('0')
OFFSET_UPPER = ord('A')
OFFSET_LOWER = ord('a')
FileType = str | bytes | PathLike


def batched(iterable: Iterable, size: int, pad=None, drop=False):
	if size < 1:
		raise ValueError(f"{size=}")
	it = iter(iterable)
	while batch := tuple(islice(it, size)):
		if len(batch) < size:
			if drop:
				return
			if pad is None:
				raise ValueError(f"iterable had {len(batch)} items left over")
			batch += tuple(islice(pad, size - len(batch)))
		yield batch


class AsciiTranslationTable:
	__slots__ = ('chars',)
		
	def __init__(self, chars=None):
		self.chars = [None] * 127 if chars is None else chars
	
	@classmethod
	def with_letters(cls, extra=''):
		table = cls()
		table.allow(ascii_letters)
		table.allow(extra)
		return table
	
	def allow(self, letters):
		for c in letters:
			self.chars[ord(c)] = c

	def replace(self, letters, replace):
		for c, d in zip(letters, replace):
			self.chars[ord(c)] = d
	
	def __getitem__(self, x):
		return self.chars[x] if x < 127 else None
		
	def __repr__(self):
		allow = []
		replace = []
		for c, d in enumerate(self.chars):
			if d is not None:
				if c == ord(d):
					allow.append(d)
				else:
					replace.append(f"{chr(c).replace('\n', '\\n').replace('\t', '\\t')}:{d}")
		return f'(allow="{''.join(allow)}", replace={{{','.join(replace)}}}'


BASIC_TABLE = AsciiTranslationTable.with_letters()


def to_code(c: str):
	return (ord(c) - OFFSET_UPPER) & 0x1F


P = ParamSpec('P')

def collect_to_str(func: Callable[P, Iterable[str]]) -> Callable[P, str]:
	def joiner(*args: P.args, **kwargs: P.kwargs) -> str:
		it = func(*args, **kwargs)
		return ''.join(it)
	return joiner


def add_unique(s: set, item):
	old_len = len(s)
	s.add(item)
	return old_len != len(s)


class CodeTable:
	__slots__ = 'table', 'offset'
	
	def __init__(self, table: list[str], offset: int):
		self.table = table
		self.offset = offset
	
	@classmethod
	def from_alphabet_ignore_case(cls, alphabet: str):
		alphabet_both_cases = alphabet.lower() + alphabet.upper()
		offset = ord(min(alphabet_both_cases))
		table = [None] * (ord(max(alphabet_both_cases)) - offset + 1)
		for i, a in enumerate(alphabet):
			table[ord(a.upper()) - offset] = i
			table[ord(a.lower()) - offset] = i
		return cls(table, offset)

	@classmethod
	def from_alphabet(cls, alphabet: str):
		offset = ord(min(alphabet))
		table = [None] * (ord(max(alphabet)) - offset + 1)
		for i, a in enumerate(alphabet):
			table[ord(a) - offset] = i
		return cls(table, offset)

	def __getitem__(self, c: str):
		return self.table[ord(c) - self.offset]

	def __repr__(self):
		return f'<CodeTable with {len(self.table)} slots ({chr(self.offset)}..{chr(self.offset + len(self.table) - 1)})>'
