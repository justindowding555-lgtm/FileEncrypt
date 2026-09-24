"""Create a small valid ZIP seed for the FileEncrypt ZIP parser fuzz target."""
from pathlib import Path
from zipfile import ZipFile, ZIP_STORED

path = Path(__file__).parent / "corpus" / "zip_reader" / "one-entry.zip"
path.parent.mkdir(parents=True, exist_ok=True)
with ZipFile(path, "w", compression=ZIP_STORED) as archive:
    archive.writestr("0123456789abcdef0123456789abcdef.fenc", b"FENC\x03")
print(path)
