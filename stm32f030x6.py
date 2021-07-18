import struct

from unicorn import *
from unicorn.arm_const import *
from unicorn.unicorn_const import *

from unicornetto import Unicornetto

FLASH_ADDRESS = 0x08000000
FLASH_SIZE = 0x8000 # 32 Kbytes
SRAM_ADDRESS = 0x20000000
SRAM_SIZE = 0x1000 # 4 Kbytes

GPIOA_ADDRESS = 0x48000000
GPIOA_SIZE = 0x400

class STM32F030x6(Unicornetto):
    def __init__(self, firmware_file) -> None:
        self.arch = UC_ARCH_ARM
        self.mode = UC_MODE_THUMB | UC_MODE_MCLASS
        super().__init__(firmware_file)
    
    def _map_memory(self):
        self._print_debug("Mapping STM32F030x6 memory")
        self.uc.mem_map(FLASH_ADDRESS, FLASH_SIZE, perms=UC_PROT_READ|UC_PROT_EXEC)
        self.uc.mem_map(SRAM_ADDRESS, SRAM_SIZE, perms=UC_PROT_READ|UC_PROT_WRITE)

        # Peripherals
        self.uc.mem_map(GPIOA_ADDRESS, GPIOA_SIZE, perms=UC_PROT_READ|UC_PROT_WRITE) # GPIOA
    
    def _add_hooks(self):
        super()._add_hooks()
        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.hook_gpioa, begin=GPIOA_ADDRESS, end=(GPIOA_ADDRESS+GPIOA_SIZE-1))
    
    def _set_initial_state(self):
        initial_sp = self.uc.mem_read(FLASH_ADDRESS, 0x4)
        self.initial_sp = struct.unpack("<I", initial_sp)[0]
        print(f"Initial SP: {self.initial_sp:08x}")

        entrypoint = self.uc.mem_read(FLASH_ADDRESS+0x4, 0x4)
        self.entrypoint = struct.unpack("<I", entrypoint)[0]
        print(f"Entrypoint: {self.entrypoint:08x}")

        # Initialize registers
        self.uc.reg_write(UC_ARM_REG_SP, self.initial_sp)

    def hook_gpioa(self, uc, access, address, size, value, data):
        print(f"Accessing GPIOA (type 0x{access:x}) at 0x{address:08x} (size {size:x}), value 0x{value:x}")