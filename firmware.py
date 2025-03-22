from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS
from elftools.elf.sections import SymbolTableSection
from elftools.dwarf.descriptions import describe_form_class

class Firmware:
    def __init__(self, filename) -> None:
        self.elfstream = open(filename, 'rb')
        self.elffile = ELFFile(self.elfstream)
        self.symbol_table = {}

        self.symtab_section = self.elffile.get_section_by_name('.symtab')

        self.dwarfinfo = self.elffile.get_dwarf_info()
        self.dwarf_funcname_cache = {}
        self.dwarf_source_cache = {}

        self._build_symbol_table()

    def __del__(self):
        if hasattr(self, 'elfstream') and self.elfstream:
            self.elfstream.close()

    def close(self):
        if hasattr(self, 'elfstream') and self.elfstream:
            self.elfstream.close()
            self.elfstream = None
    
    def print_symbols(self):
        num_symbols = self.symtab_section.num_symbols()
        print(f"Number of symbols: {num_symbols}")
        for symbol in self.symtab_section.iter_symbols():
            print(f"{symbol.name} {symbol['st_value']:x} {symbol['st_size']:x}")
    
    def _build_symbol_table(self):
        for symbol in self.symtab_section.iter_symbols():
            name = symbol.name
            value = symbol['st_value']
            #size = symbol['st_size']
            if name not in ['', '$t', '$d'] and value > 0:
                self.symbol_table[value] = name
    
    def get_symbol(self, symbol_name):
        symbol = self.symtab_section.get_symbol_by_name(symbol_name)
        if not symbol:
            raise RuntimeError("Symbol not found")
        symbol = symbol[0]
        return symbol['st_value']
    
    def get_symbol_by_addr(self, addr):
        return self.symbol_table[addr]

    def iter_sections(self):
        for section in self.elffile.iter_sections():
            flags = section['sh_flags']
            if not flags & SH_FLAGS.SHF_ALLOC:
                continue
            #print(f"Section name: {section.name}, type: {section['sh_type']}")
            addr = section['sh_addr']
            size = section['sh_size']
            data = section.data()
            if len(data) != size:
                print(f"Data length does not match sh_size")
                continue
            yield (addr, data)

    def has_dwarf_info(self):
        return self.elffile.has_dwarf_info()

    # Based on public domain code from
    #   https://github.com/eliben/pyelftools/blob/9db67b19b237f0d75f119633b3f23f4b67a60b3d/examples/dwarf_decode_address.py
    def get_dwarf_funcname(self, address):
        if not self.has_dwarf_info():
            raise RuntimeError("No DWARF info available")
        if address in self.dwarf_funcname_cache:
            return self.dwarf_funcname_cache[address]

        # Go over all DIEs in the DWARF information, looking for a subprogram
        # entry with an address range that includes the given address. Note that
        # this simplifies things by disregarding subprograms that may have
        # split address ranges.
        for CU in self.dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                try:
                    if DIE.tag == 'DW_TAG_subprogram':
                        lowpc = DIE.attributes['DW_AT_low_pc'].value

                        # DWARF v4 in section 2.17 describes how to interpret the
                        # DW_AT_high_pc attribute based on the class of its form.
                        # For class 'address' it's taken as an absolute address
                        # (similarly to DW_AT_low_pc); for class 'constant', it's
                        # an offset from DW_AT_low_pc.
                        highpc_attr = DIE.attributes['DW_AT_high_pc']
                        highpc_attr_class = describe_form_class(highpc_attr.form)
                        if highpc_attr_class == 'address':
                            highpc = highpc_attr.value
                        elif highpc_attr_class == 'constant':
                            highpc = lowpc + highpc_attr.value
                        else:
                            print('Error: invalid DW_AT_high_pc class:',
                                highpc_attr_class)
                            continue

                        if lowpc <= address < highpc:
                            self.dwarf_funcname_cache[address] = DIE.attributes['DW_AT_name'].value
                            return self.dwarf_funcname_cache[address]
                except KeyError:
                    continue
        return None

    # Based on public domain code from
    #   https://github.com/eliben/pyelftools/blob/9db67b19b237f0d75f119633b3f23f4b67a60b3d/examples/dwarf_decode_address.py
    def get_dwarf_source(self, address):
        if not self.has_dwarf_info():
            raise RuntimeError("No DWARF info available")
        if address in self.dwarf_source_cache:
            return self.dwarf_source_cache[address]

        # Go over all the line programs in the DWARF information, looking for
        # one that describes the given address.
        for CU in self.dwarfinfo.iter_CUs():
            # First, look at line programs to find the file/line for the address
            lineprog = self.dwarfinfo.line_program_for_CU(CU)
            prevstate = None
            for entry in lineprog.get_entries():
                # We're interested in those entries where a new state is assigned
                if entry.state is None:
                    continue
                # Looking for a range of addresses in two consecutive states that
                # contain the required address.
                if prevstate and prevstate.address <= address < entry.state.address:
                    filename = lineprog['file_entry'][prevstate.file - 1].name
                    line = prevstate.line
                    return filename, line
                if entry.state.end_sequence:
                    # For the state with `end_sequence`, `address` means the address
                    # of the first byte after the target machine instruction
                    # sequence and other information is meaningless. We clear
                    # prevstate so that it's not used in the next iteration. Address
                    # info is used in the above comparison to see if we need to use
                    # the line information for the prevstate.
                    prevstate = None
                else:
                    prevstate = entry.state
        return None, None