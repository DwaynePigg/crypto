import string
from collections.abc import Callable, Iterable
from itertools import chain, islice
from os import PathLike
from typing import Mapping, ParamSpec, Sequence

OFFSET_UPPER = ord('A')
OFFSET_LOWER = ord('a')
FileType = str | bytes | PathLike
TranslateTable = Sequence[str | int | None] | Mapping[int, str | int | None]
PAD_STRICT = object()

def batched(iterable: Iterable, size: int, pad=PAD_STRICT, drop=False):
	if size < 1:
		raise ValueError(f"{size=}")
	it = iter(iterable)
	while batch := tuple(islice(it, size)):
		if len(batch) < size:
			if drop:
				return
			if pad is PAD_STRICT:
				raise ValueError(f"iterable had {len(batch)} items left over")
			batch += tuple(islice(pad, size - len(batch)))
		yield batch


def batched_lenient(iterable: Iterable, size: int):
	return batched(iterable, size, iter(()))


def make_filter(allow: str = ''):
	chars: list[str | None] = [None] * 127
	for c in chain(string.ascii_letters, allow):
		chars[ord(c)] = c
	return chars


ALPHA_FILTER = make_filter()


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


class CharTable:
	__slots__ = 'table', 'offset'
	
	def __init__(self, min: int | str = 0, max: int | str = 0xFF):
		if isinstance(min, str):
			min = ord(min)
		if isinstance(max, str):
			max = ord(max)
		self.table = [None] * (max - min + 1)
		self.offset = min

	@classmethod
	def for_printable(cls):
		return cls(0x20, 0xFF)

	@classmethod
	def for_upper(cls):
		return cls('A', 'Z')

	@classmethod
	def for_lower(cls):
		return cls('a', 'z')

	def _get_index(self, key: str):
		index = ord(key) - self.offset
		if not (0 <= index < len(self.table)):
			raise IndexError(f"'{key}' not in '{chr(self.offset)}'..'{chr(len(self) + self.offset - 1)}'")
		return index

	def __getitem__(self, key: str):
		return self.table[self._get_index(key)]

	def __setitem__(self, key: str, value):
		self.table[self._get_index(key)] = value

	def __len__(self):
		return len(self.table)

	def items(self):
		for i, value in enumerate(self.table):
			yield chr(i + self.offset), value
	
	def update(self, mapping):
		try:
			items = mapping.items()
		except AttributeError:
			items = mapping
		for key, value in items:
			self[key] = value

	def __repr__(self):
		return '; '.join(f"{key}: {value}" for key, value in self.items())
