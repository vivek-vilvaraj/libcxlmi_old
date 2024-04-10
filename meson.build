# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libcxlmi.
#
project(
    'libcxlmi', ['c'],
    meson_version: '>= 0.50.0',
    version: '1.8',
    license: 'LGPL-2.1-or-later',
    default_options: [
        'c_std=gnu99',
        'warning_level=1',
        'buildtype=debugoptimized',
        'prefix=/usr/local',
        'sysconfdir=etc',
        'wrap_mode=nofallback'
    ]
)

cc = meson.get_compiler('c')
cxx_available = add_languages('cpp', required: false)
inc = include_directories(['ccan', 'src'])

subdir('ccan')
subdir('src')
subdir('examples')
install_headers('src/libcxlmi.h')
