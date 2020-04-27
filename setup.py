"""
LibClamAV ctypes binding
"""

import setuptools

__verison__ = "1.0.0"

with open('README.md', 'r') as readme_file:
    long_description = readme_file.read()

setuptools.setup(
    name="py-clamav",
    version=__verison__,
    author="dmitriym09",
    description="LibClamAV ctypes binding",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/dmitriym09/py-clamav",
    packages=setuptools.find_packages(exclude="test"),
    python_requires='>=3.8'
)
