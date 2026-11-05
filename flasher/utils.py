from ctypes import Union, LittleEndianStructure, c_uint16
from contextlib import contextmanager
from alive_progress import alive_bar

def log(message, log_callback=None):
    """Print a CLI message or send it through the GUI's log signal."""
    if log_callback is None:
        print(message)
    else:
        log_callback.emit(message)


def strip_identifier(value):
    return ''.join(character for character in value if character.isalnum())


@contextmanager
def byte_progress(total, title, progress_callback=None):
    """Use a byte callback supplied by a frontend, or the CLI progress bar."""
    if progress_callback is not None:
        yield progress_callback
    else:
        with alive_bar(total, unit='B', title=title, enrich_print=False) as bar:
            yield bar

class WordBitfield(Union):
	_anonymous_ = ('bits',)

	class bits(LittleEndianStructure):
		_fields_ = [
		]

	_fields_ = [
		('value', c_uint16),
		('bits', bits),
	]

	def _to_dict (self) -> dict:
		fields = getattr(type(self).bits, '_fields_', ())
		if not fields:
			return {}
		bits = type(self).bits.from_buffer(self)
		return {field: getattr(bits, field) for field, _, _ in fields}

	def __str__ (self) -> str:
		return '{}(\n{}\n)'.format(
			type(self).__name__,
			', \n'.join([f'  {k}={v}' for k,v in self._to_dict().items()])
		)
