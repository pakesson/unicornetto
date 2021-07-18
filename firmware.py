from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS
from elftools.elf.sections import SymbolTableSection

class Firmware:
    def __init__(self, filename) -> None:
        self.elfstream = open(filename, 'rb')
        self.elffile = ELFFile(self.elfstream)
        self.symbol_table = {}

        self._build_symbol_table()
    
    def print_symbols(self):
        section = self.elffile.get_section_by_name('.symtab')
        num_symbols = section.num_symbols()
        print(f"Number of symbols: {num_symbols}")
        for symbol in section.iter_symbols():
            print(f"{symbol.name} {symbol['st_value']:x} {symbol['st_size']:x}")
    
    def _build_symbol_table(self):
        section = self.elffile.get_section_by_name('.symtab')
        for symbol in section.iter_symbols():
            name = symbol.name
            value = symbol['st_value']
            #size = symbol['st_size']
            if name not in ['', '$t', '$d'] and value > 0:
                self.symbol_table[value] = name
    
    def get_symbol(self, symbol_name):
        section = self.elffile.get_section_by_name('.symtab')
        symbol = section.get_symbol_by_name(symbol_name)
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