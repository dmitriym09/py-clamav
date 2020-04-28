"""

"""

import sys

from .scanner import Scanner


def main(file_path: str) -> None:
    with Scanner() as scanner:
        infected, virname = scanner.scan_file(file_path)
        if not infected:
            print('File not infecfed')
        else:
            print(f'File infecfed: {virname}')
            sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise RuntimeError('Not set file')
    if len(sys.argv) > 2:
        raise RuntimeError('Supported only one file')

    main(sys.argv[1])
