# py-clamav

LibClamAV ctypes binding

## Install

- install or [download](https://www.clamav.net/downloads) libclamv
- `pip install py-clamav`

## Using

```python
import os

from py_clamav import ClamAvScanner

with ClamAvScanner() as scanner:
    # scan file by path
    path_file = 'path/to/file'
    infected, virname = scanner.scan_file(path_file)
    
    # scan file by fileno
    fileno = os.memfd_create('testfile')
    try:
        os.write(fileno, b'data')
        os.lseek(fileno, 0, 0)
        infected, virname = scanner.scan_fileno(fileno)
    finally:
        os.close(fileno)
```
