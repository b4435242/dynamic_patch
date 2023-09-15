import lief
import capstone



def find_symbol(binary_path, symbol_name):
    # Load the binary
    binary = lief.parse(binary_path)
    base_address = binary.optional_header.imagebase
    print(base_address)

    


    
    # Iterate through the binary's symbols and find the one you're looking for
    symbol_address = None
    for symbol in binary.symbols:
        print(symbol)
        if symbol.name == symbol_name:
            symbol_address = symbol.value
            break

    if symbol_address is not None:
        print(f"The address of symbol '{symbol_name}' is 0x{symbol_address:016X}")
        return base_address + 0x1000 + symbol_address
    else:
        print(f"Symbol '{symbol_name}' not found in the binary.")
