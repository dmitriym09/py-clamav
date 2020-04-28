# py-clamav

LibClamAV ctypes binding

## Docker

Check file by [docker container](https://hub.docker.com/r/dmitriym09/py-clamav)

```bash
docker run --rm -it -v{path_to_file}:{path_to_file} dmitriym09/py-clamav python -m py_clamav {path_to_file}
```

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
