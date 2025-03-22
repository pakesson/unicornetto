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
    def __init__(self, firmware_file, tracing = False) -> None:
        self.arch = UC_ARCH_ARM
        self.mode = UC_MODE_THUMB | UC_MODE_MCLASS
        super().__init__(firmware_file, tracing)
    
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

    def _cycles_for_ins(self, ins):
        # Based on https://developer.arm.com/documentation/ddi0432/c/CHDCICDF

        regs_read, regs_write = ins.regs_access()
        regs_read = [ins.reg_name(reg_id) for reg_id in regs_read]
        regs_write = [ins.reg_name(reg_id) for reg_id in regs_write]

        # We need the current state to be able to determine the cycles needed for
        # some instructions
        cpsr = self.uc.reg_read(UC_ARM_REG_CPSR)
        negative = (cpsr >> 31 & 0x1) == 0x1 # N
        zero = (cpsr >> 30 & 0x1) == 0x1     # Z
        carry = (cpsr >> 29 & 0x1) == 0x1    # C
        overflow = (cpsr >> 28 & 0x1) == 0x1 # V

        cycles = 1 # Default number of clock cycles per instruction

        if ins.mnemonic == 'movs':
            pass # Always 1 cycle
        elif ins.mnemonic == 'mov':
            if 'pc' in regs_write:
                cycles = 3
        elif ins.mnemonic == 'adds':
            pass # Always 1 cycle
        elif ins.mnemonic == 'add':
            if 'pc' in regs_write:
                cycles = 3
        elif ins.mnemonic == 'adcs':
            pass # Always 1 cycle
        elif ins.mnemonic == 'adr':
            pass # Always 1 cycle
        elif ins.mnemonic == 'subs':
            pass # Always 1 cycle
        elif ins.mnemonic == 'sbcs':
            pass # Always 1 cycle
        elif ins.mnemonic == 'sub':
            pass # Always 1 cycle
        elif ins.mnemonic == 'rsbs':
            pass # Always 1 cycle
        elif ins.mnemonic == 'muls':
            pass # 1 or 32. Depends on multiplier implementation.
        elif ins.mnemonic == 'cmp':
            pass # Always 1 cycle
        elif ins.mnemonic == 'cmn':
            pass # Always 1 cycle
        elif ins.mnemonic == 'ands':
            pass # Always 1 cycle
        elif ins.mnemonic == 'eors':
            pass # Always 1 cycle
        elif ins.mnemonic == 'orrs':
            pass # Always 1 cycle
        elif ins.mnemonic == 'bics':
            pass # Always 1 cycle
        elif ins.mnemonic == 'mvns':
            pass # Always 1 cycle
        elif ins.mnemonic == 'tst':
            pass # Always 1 cycle
        elif ins.mnemonic == 'lsls':
            pass # Always 1 cycle
        elif ins.mnemonic == 'lsrs':
            pass # Always 1 cycle
        elif ins.mnemonic == 'asrs':
            pass # Always 1 cycle
        elif ins.mnemonic == 'rors':
            pass # Always 1 cycle
        elif ins.mnemonic == 'ldr':
            cycles = 2
        elif ins.mnemonic == 'ldrh':
            cycles = 2
        elif ins.mnemonic == 'ldrb':
            cycles = 2
        elif ins.mnemonic == 'ldrsh':
            cycles = 2
        elif ins.mnemonic == 'ldrsb':
            cycles = 2
        elif ins.mnemonic == 'ldm':
            cycles = 1 + len(regs_read) # 1+N
        elif ins.mnemonic == 'str':
            cycles = 2
        elif ins.mnemonic == 'strh':
            cycles = 2
        elif ins.mnemonic == 'strb':
            cycles = 2
        elif ins.mnemonic == 'stm':
            cycles = 1 + len(regs_read) # 1+N
        elif ins.mnemonic == 'push':
            N = len(regs_read) - 1 # Don't count 'sp'
            cycles = 1 + N
        elif ins.mnemonic == 'pop':
            N = len(regs_write) - 1 # Don't count 'sp'
            if 'pc' in regs_write:
                cycles = 4 + N
            else:
                cycles = 1 + N
        elif ins.mnemonic == 'beq':
            if zero:
                cycles = 3
            # else cycles = 1
        elif ins.mnemonic == 'bne':
            if not zero:
                cycles = 3
            # else cycles = 1
        elif ins.mnemonic == 'blt':
            if negative != overflow:
                cycles = 3
            # else cycles = 1
        elif ins.mnemonic == 'ble':
            if zero or (negative != overflow):
                cycles = 3
            # else cycles = 1
        elif ins.mnemonic == 'bhi':
            if carry and not zero:
                cycles = 3
            # else cycles = 1
        elif ins.mnemonic == 'blo':
            if not carry:
                cycles = 3
            # else cycles = 1
        elif ins.mnemonic == 'bls':
            if not carry or zero:
                cycles = 3
            # else cycles = 1
        # TODO: More conditional branches missing here
        elif ins.mnemonic == 'b':
            cycles = 3
        elif ins.mnemonic == 'bl':
            cycles = 4
        elif ins.mnemonic == 'bx':
            cycles = 3
        elif ins.mnemonic == 'blx':
            cycles = 3
        elif ins.mnemonic == 'sxth':
            pass # Always 1 cycle
        elif ins.mnemonic == 'sxtb':
            pass # Always 1 cycle
        elif ins.mnemonic == 'uxth':
            pass # Always 1 cycle
        elif ins.mnemonic == 'uxtb':
            pass # Always 1 cycle
        elif ins.mnemonic == 'rev':
            pass # Always 1 cycle
        elif ins.mnemonic == 'rev16':
            pass # Always 1 cycle
        elif ins.mnemonic == 'revsh':
            pass # Always 1 cycle
        elif ins.mnemonic == 'nop':
            pass # Always 1 cycle
        # TODO: svc, cpsid, cpsie, mrs, msr, bkpt, sev, wfe, wfi, yield, isb, dmb, dsb, ...
        else:
            print("Unhandled instruction!")
            print(f"Instruction name: {ins.insn_name()}")
            print(f"Mnemonic: {ins.mnemonic}")
            print(f"Regs read: {regs_read}")
            print(f"Regs write: {regs_write}")
            print(f"N: {negative}, Z: {zero}, C: {carry}, O: {overflow}")

        return cycles

    def hook_gpioa(self, uc, access, address, size, value, data):
        print(f"Accessing GPIOA (type 0x{access:x}) at 0x{address:08x} (size {size:x}), value 0x{value:x}")