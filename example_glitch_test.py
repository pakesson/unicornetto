#!/usr/bin/env python3
import sys
from unicorn.arm_const import *
from stm32f030x6 import STM32F030x6

delay = 128

def trigger_fault(unicornetto: STM32F030x6):
    print(f"Triggering fault in {delay} cycles")
    unicornetto.glitch(delay)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <firmware file>")
        sys.exit(1)

    target_file = sys.argv[1]

    unicornetto = STM32F030x6(target_file)

    unicornetto.stub_function('HAL_RCC_OscConfig')
    unicornetto.stub_function('HAL_RCC_ClockConfig')
    unicornetto.stub_function('HAL_GPIO_Init')
    unicornetto.stub_function('init_uart')

    unicornetto.hook_function('putch', lambda x: print(chr(x.uc.reg_read(UC_ARM_REG_R0)),end=''))

    unicornetto.hook_function('fault_arm', trigger_fault)

    unicornetto.set_tracing(False)

    unicornetto.run(end = 'fault_disarm')

    print(f"Total cycle count: {unicornetto.cycle_count}")
    print(f"Total instruction count: {unicornetto.instruction_count}")