# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libcxlmi.
#
project(
    'libcxlmi', ['c'],
    meson_version: '>= 0.50.0',
    version: '0.0.1',
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

conf = configuration_data()

conf.set10(
    'HAVE_TYPEOF',
    cc.compiles(
        '''int main(void) {
                int a = 1;
                typeof(a) b;
                b = a;
           }
        ''',
        name: 'typeof'
    ),
    description: 'Is typeof available?'
)
conf.set10(
    'HAVE_BYTESWAP_H',
    cc.compiles(
        '''#include <byteswap.h>''',
        name: 'byteswap.h'
    ),
    description: 'Is byteswap.h include-able?'
)
conf.set10(
    'HAVE_BSWAP_64',
    cc.links(
        '''#include <byteswap.h>
            int main(void) {
                return bswap_64(0);
            }
        ''',
        name: 'bswap64'
    ),
    description: 'Is bswap_64 available?'
)
conf.set10(
    'HAVE_LITTLE_ENDIAN',
    host_machine.endian() == 'little',
    description: 'Building for little-endian'
)
conf.set10(
    'HAVE_BIG_ENDIAN',
    host_machine.endian() == 'big',
    description: 'Building for big-endian'
)

conf.set10(
    'HAVE_LINUX_MCTP_H',
    cc.compiles(
	'''#include <linux/mctp.h>''',
	name: 'linux/mctp.h'
    ),
    description: 'Is linux/mctp.h include-able?'
)

conf.set(
    'HAVE_GLIBC_IOCTL',
    cc.compiles(
        '''#include <sys/ioctl.h>
        int ioctl(int fd, unsigned long request, ...);
        ''',
        name: 'ioctl has glibc-style prototype'
    ),
    description: 'Is ioctl the glibc interface (rather than POSIX)'
)

add_project_arguments(
    [
	'-fomit-frame-pointer',
	'-D_GNU_SOURCE',
    ],
    language : 'c',
)
inc = include_directories(['ccan', 'src'])

subdir('ccan')
subdir('src')
subdir('examples')

mode = ['rw-r--r--', 0, 0]
install_headers('src/libcxlmi.h', install_mode: mode)
