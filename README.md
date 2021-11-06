# Features

Firmware emulation based on Unicorn. Only STM32F030 (Arm Cortex-M0) is currently implemented.

* Function hooking
* Function stubbing
* Execution tracing
* Accurate(ish) cycle count
* Basic fault injection (glitching) support
* Horrible performance

# Examples

## AES execution trace (`example_stm32f030x6_cw_exec_trace.py`)

This example shows how to record an execution trace for the [ChipWhisperer
SimpleSerial AES firmware](https://github.com/newaetech/chipwhisperer/tree/develop/hardware/victims/firmware/simpleserial-aes).
Each trace entry will include the address, clock cycles, total clock cycles,
human-readable disassembly, source code function, file and line number.
The result is saved as a pickled list of tuples.

```
$ ./example_stm32f030x6_cw_exec_trace.py simpleserial-aes-CWNANO.elf ./execution_trace.pkl
Initial SP: 20001000
Entrypoint: 08001579
Mapping memory for key and plaintext
Setting key
Running key expansion function
Setting plaintext
Enabling trigger
Running encryption function
This may take a while...
Trigger: Tracing enabled!
Got trace of length 169
Saving execution trace to ./execution_trace.pkl
```