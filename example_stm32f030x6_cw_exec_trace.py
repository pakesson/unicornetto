#!/usr/bin/env python3
import sys
import pickle

import unicorn
from unicorn.arm_const import *
from stm32f030x6 import STM32F030x6

KEY_ADDRESS = 0x20201000
PT_ADDRESS  = 0x20202000

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <firmware file> <trace file>")
        sys.exit(1)

    target_file = sys.argv[1]
    trace_file = sys.argv[2]

    unicornetto = STM32F030x6(target_file)

    # Add a couple of extra memory segments so that we don't have to
    # figure out where to put these in the normal SRAM
    print("Mapping memory for key and plaintext")
    unicornetto.map_memory(KEY_ADDRESS, 0x400)
    unicornetto.map_memory(PT_ADDRESS, 0x400)

    # Set key
    print("Setting key")
    unicornetto.write_memory(KEY_ADDRESS, b'\xaa' * 16)

    # Run the key expansion function
    print("Running key expansion function")
    unicornetto.write_register(UC_ARM_REG_R0, KEY_ADDRESS)
    unicornetto.write_register(UC_ARM_REG_R1, 0x10) # Length
    get_key = unicornetto.get_symbol("get_key")
    unicornetto.run(get_key, end=get_key+0x8)

    # Set plaintext
    print("Setting plaintext")
    unicornetto.write_memory(PT_ADDRESS, b'\xcc' * 16)

    # Enable instruction tracing
    print("Enabling trigger")
    unicornetto.hook_function('trigger_high', lambda x: print("Trigger: Tracing enabled!") or x.set_tracing(True))

    # Run main encryption
    print("Running encryption function")
    print("This may take a while...")
    unicornetto.write_register(UC_ARM_REG_R0, PT_ADDRESS)
    unicornetto.write_register(UC_ARM_REG_R1, 0x10) # Length
    unicornetto.run("get_pt", end="trigger_low", timeout=10)

    traces = unicornetto.get_traces()
    print(f"Got trace of length {len(traces)}")
    print(f"Saving execution trace to {trace_file}")
    with open(trace_file, "wb") as f:
        pickle.dump(traces, f)