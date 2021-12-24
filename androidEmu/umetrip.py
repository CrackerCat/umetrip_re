from unicorn import *
from androidemu.emulator import Emulator
from UnicornTraceDebugger import udbg
from unicorn.arm_const import *
from androidemu.java.helpers.native_method import native_method
from androidemu.utils import memory_helpers
import binascii, re

import logging
import sys
import zipfile, os, re, shutil

# Configure logging
logging.basicConfig(stream=sys.stdout,
                    level=logging.DEBUG,
                    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s")
logger = logging.getLogger(__name__)


@native_method
def __aeabi_memclr(mu, addr, size):
    print('__aeabi_memclr(%x,%d)' % (addr, size))
    mu.mem_write(addr, bytes(size))


emulator = Emulator()
emulator.modules.add_symbol_hook('__aeabi_memclr4', emulator.hooker.write_function(__aeabi_memclr) + 1)
emulator.modules.add_symbol_hook('__aeabi_memclr', emulator.hooker.write_function(__aeabi_memclr) + 1)
libmod = emulator.load_library('lib/libc.so', do_init=False)
libmod = emulator.load_library('lib/libdl.so', do_init=False)
libmod = emulator.load_library('lib/libumejni.so', do_init=False)
print(libmod.base)

image1 = 0xf200000
image_size1 = 0x10000 * 3
emulator.mu.mem_map(image1, image_size1)
emulator.mu.mem_write(image1, 'h[+_{qDGiXoYjiRHfjo_lU'.encode('utf-8'))

image2 = 0xf300000
image_size2 = 0x10000 * 3
emulator.mu.mem_map(image2, image_size2)

try:

    dbg = udbg.UnicornDebugger(emulator.mu, mode=1)
    # dbg.add_bpt(0xcbc73f24)
    emulator.call_native(0xCBC6C000 + 0x9328 + 1, image1, image2)

    print(emulator.mu.mem_read(image2, 32))
    # emulator.call_symbol('sub_7f24',image1, image2)
except UcError as e:
    list_tracks = dbg.get_tracks()
    for addr in list_tracks[-100:-1]:
        print(hex(addr - 0xcbc6c000))
    print(e)
