"""
LibClamAV ctypes binding
"""

import setuptools

__verison__ = "1.0.1"

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="py-clamav",
    version=__verison__,
    license='MIT',
    author="dmitriym09",
    author_email='dmitriym.09.12.1989@gmail.com',
    description="LibClamAV ctypes binding",
    keywords=['antivirus', 'ClamAv', 'LibClamAV'],
    url="https://github.com/dmitriym09/py-clamav",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(where="src", exclude=["tests", "tests.*"]),
    package_dir={"": "src"},
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Operating System :: POSIX :: Linux'
    ],
)
