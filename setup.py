"""
LibClamAV ctypes binding
"""

import setuptools

__verison__ = "1.0.0"

setuptools.setup(
    name="py-clamav",
    version=__verison__,
    license='MIT',
    author="dmitriym09",
    author_email='dmitriym.09.12.1989@gmail.com',
    description="LibClamAV ctypes binding",
    keywords=['antivirus', 'ClamAv', 'LibClamAV'],
    url="https://github.com/dmitriym09/py-clamav",
    packages=setuptools.find_packages(exclude="test"),
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
    ],
)
