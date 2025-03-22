import struct

import capstone as cs
from unicorn import *
from unicorn.arm_const import *
from unicorn.unicorn_const import *

from firmware import Firmware

arm_cortexm_registers = {
    'sp': UC_ARM_REG_SP,
    'pc': UC_ARM_REG_PC,
    'lr': UC_ARM_REG_LR,
    'r0': UC_ARM_REG_R0,
    'r1': UC_ARM_REG_R1,
    'r2': UC_ARM_REG_R2,
    'r3': UC_ARM_REG_R3,
    'r4': UC_ARM_REG_R4,
    'r5': UC_ARM_REG_R5,
    'r6': UC_ARM_REG_R6,
    'r7': UC_ARM_REG_R7,
    'r8': UC_ARM_REG_R8,
    'r9': UC_ARM_REG_R9,
    'r10': UC_ARM_REG_R10,
    'r11': UC_ARM_REG_R11,
    'r12': UC_ARM_REG_R12,
    'cpsr': UC_ARM_REG_CPSR
}

class Unicornetto:
    def __init__(self, firmware_file, verbose = False, tracing = False) -> None:
        if self.arch != UC_ARCH_ARM or self.mode != UC_MODE_THUMB | UC_MODE_MCLASS:
            raise RuntimeError(f"Unsupported architecture {self.arch}, mode {self.mode}")

        self.firmware = Firmware(firmware_file)
        self.uc = Uc(self.arch, self.mode)

        self.capstone = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB | cs.CS_MODE_MCLASS)
        self.capstone.detail = True

        self.verbose = verbose

        self.last_address = 0x0
        self.last_instruction_size = 0x0

        self.tracing = tracing
        self.traces = [] # List of tuples

        self.instruction_count = 0
        self.cycle_count = 0

        self.glitch_armed = False
        self.glitch_delay = 0
        self.glitch_cycle_count = 0

        self.function_hooks = {}
        
        self._map_memory()
        self._map_sections()
        self._add_hooks()
        self._set_initial_state()
    
    def _print_debug(self, val):
        if self.verbose:
            print(val)
    
    def _map_memory(self):
        pass

    def _map_sections(self):
        for (addr, data) in self.firmware.iter_sections():
            self.uc.mem_write(addr, data)

    def _add_hooks(self):
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self._hook_mem_unmapped)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        self.uc.hook_add(UC_HOOK_BLOCK, self._hook_block)

    def _set_initial_state(self):
        pass
    
    def _return_to_last(self):
        data = self.uc.mem_read(self.last_address, self.last_instruction_size*2)
        disasm = next(self.capstone.disasm(data, self.last_address, 1))
        if disasm.mnemonic in ['bl', 'blx']:
            lr = self.uc.reg_read(UC_ARM_REG_LR)
            self.uc.reg_write(UC_ARM_REG_PC, lr)
        else:
            raise RuntimeError("Unsupported jump")

    def _hook_code(self, uc, address, size, user_data):
        data = uc.mem_read(address, size*2)
        disasm = next(self.capstone.disasm(data, address, 1))
        disasm_str = f"0x{disasm.address:08x}:\t{disasm.mnemonic:<8} {disasm.op_str:<32}"
        self._print_debug(disasm_str)
        if self.last_address == address and disasm.mnemonic == 'b':
            print("Infinite loop detected. Stopping.")
            uc.emu_stop()

        self.last_address = address
        self.last_instruction_size = size

        if self.glitch_armed and self.glitch_cycle_count >= self.glitch_delay:
            print("Fault injected! Skipping instruction.")
            self.glitch_armed = False
            self.glitch_cycle_count = 0
            # Skip instruction
            self.uc.reg_write(UC_ARM_REG_PC, (address + size) | 1)
            # TODO: More glitch types
            return

        self.instruction_count += 1
        cycles = self._cycles_for_ins(disasm)
        self.cycle_count += cycles
        if self.glitch_armed:
            self.glitch_cycle_count += cycles

        # Instruction tracing
        if self.tracing:
            funcname = self.firmware.get_dwarf_funcname(address)
            source_line = self.firmware.get_dwarf_source(address)
            trace = (address, disasm_str, cycles, self.cycle_count, funcname, source_line)
            self.traces.append(trace)

    def _hook_block(self, uc, address, size, user_data):
        self._print_debug(f"Entering basic block at 0x{address:08x}, block size = 0x{size}")
        if self.is_thumb_mode():
            address = address | 1
        if address in self.firmware.symbol_table:
            self._print_debug(f"{self.firmware.symbol_table[address]}")
        if address in self.function_hooks:
            func = self.function_hooks[address]
            if func != None:
                self._print_debug("Function hooked. Calling hook and returning.")
                self.function_hooks[address](self)
            else:
                self._print_debug("Function stubbed out. Returning.")
            self._return_to_last()

    def _hook_mem_unmapped(self, uc, access, address, size, value, data):
        print(f"Invalid memory access (type 0x{access:x}) at 0x{address:08x} (size {size:x}), value 0x{value:x}")
        self.print_state()
    
    def stub_function(self, symbol_or_addr):
        if isinstance(symbol_or_addr, str):
            symbol_or_addr = self.firmware.get_symbol(symbol_or_addr)
        self._print_debug(f"Stubbing out {symbol_or_addr:08x}")
        self.function_hooks[symbol_or_addr] = None
    
    def hook_function(self, symbol_or_addr, func):
        if isinstance(symbol_or_addr, str):
            symbol_or_addr = self.firmware.get_symbol(symbol_or_addr)
        self._print_debug(f"Hooking {symbol_or_addr:08x}")
        self.function_hooks[symbol_or_addr] = func

    def map_memory(self, address, size, perms=UC_PROT_ALL):
        self.uc.mem_map(address, size, perms=perms)

    def write_memory(self, address, value):
        self.uc.mem_write(address, value)

    def write_register(self, address, value):
        self.uc.reg_write(address, value)

    def print_state(self):
        for (name, code) in arm_cortexm_registers.items():
            value = self.uc.reg_read(code)
            print(f"{name}: 0x{value:08x}")
    
    def is_thumb_mode(self):
        cpsr = self.uc.reg_read(UC_ARM_REG_CPSR)
        return ((cpsr >> 5) & 1) == 1

    def glitch(self, delay=0):
        self.glitch_armed = True
        self.glitch_delay = delay
        self.glitch_cycle_count = 0

    def set_tracing(self, tracing):
        self.tracing = tracing

    def get_traces(self):
        return self.traces

    def set_verbose(self, verbose):
        self.verbose = verbose

    def get_symbol(self, symbol):
        return self.firmware.get_symbol(symbol)

    def run(self, start = -1, end = 0x0, timeout = 30):
        if start == -1:
            start = self.entrypoint
        if isinstance(start, str):
            start = self.firmware.get_symbol(start)
        if isinstance(end, str):
            end = self.firmware.get_symbol(end)
        # Always start in thumb mode
        start = start | 1
        # This should _not_ be a thumb mode address,
        # no matter what mode the emulation is running in
        end = end ^ (end & 0x1)
        self.uc.emu_start(start, end, timeout=timeout*UC_SECOND_SCALE)
