#!/usr/bin/env python
import os
from distutils.core import setup, Extension
sources = [
    'src/python/core.c',
    'src/libetchash/io.c',
    'src/libetchash/internal.c',
    'src/libetchash/sha3.c']
if os.name == 'nt':
    sources += [
        'src/libetchash/util_win32.c',
        'src/libetchash/io_win32.c',
        'src/libetchash/mmap_win32.c',
    ]
else:
    sources += [
        'src/libetchash/io_posix.c'
    ]
depends = [
    'src/libetchash/etchash.h',
    'src/libetchash/compiler.h',
    'src/libetchash/data_sizes.h',
    'src/libetchash/endian.h',
    'src/libetchash/etchash.h',
    'src/libetchash/io.h',
    'src/libetchash/fnv.h',
    'src/libetchash/internal.h',
    'src/libetchash/sha3.h',
    'src/libetchash/util.h',
]
pyetchash = Extension('pyetchash',
                     sources=sources,
                     depends=depends,
                     extra_compile_args=["-Isrc/", "-std=gnu99", "-Wall"])

setup(
    name='pyetchash',
    author="Matthew Wampler-Doty",
    author_email="matthew.wampler.doty@gmail.com",
    license='GPL',
    version='0.1.23',
    url='https://github.com/etclabscore/etchash',
    download_url='https://github.com/etclabscore/etchash/tarball/v23',
    description=('Python wrappers for etchash, the ethereum proof of work'
                 'hashing function'),
    ext_modules=[pyetchash],
)
