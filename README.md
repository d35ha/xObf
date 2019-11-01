# xObf
Simple x86/x86_64 instruction level obfuscator based on a basic SBI engine

# How it works 
This is straight forward:
* Create new section to hold the de-obfuscation blocks
* Recursively disassemble all of the possible branches
* Replace long instruction with a `call` to the appropriate block
* Each block will decode/write/execute/clear the instruction at runtime

# Impact
This really gonna mess up with the static code analysis making it almost impossible, consider using this code snippet:
```c++
#include <stdio.h>

int main(int argc, char** argv){
    if (argc < 2){
        puts("Wrong number of arguments");
    } else {
        printf("Hello %s\n", argv[1]);
    };
};
```
After compiling and using the obfuscator upon it, this is the difference between the main subroutine instructions before and after obfuscation

![Impact](https://github.com/d35ha/xObf/raw/master/Images/Impact.png)

This will mislead any disassembler/decompiler to preview wrong output

# Thoughts
* Invalid out PE
    * The tool is basically a static binary instrumentation engine
    * The PE should be disassembled right if not, any changes made by the engine may break the binary
    * Any type of self modifying binaries will make the tool generate executables with undefined behavior
    * It may generate binaries with unexpected behavior but for now all of the tests shows it's very stable
* Not fully disassembled
    * The engine uses recursive traversal disassembling starting from the entry point so a lot of branches won't be disassembled, like the branches accessed as statically undefined destination
    * To get over this problem, the tool will manipulate any of tls table, COFF symbol table, debug table (pdb file), exception table and export table if exists; to collect all of the possible subroutine entries
    * To have all of the branches obfuscated, make sure the binary is built with debug symbols not stripped
    * By default the tool will strip any of the debug symbols (COFF and debug tables)
* Out binary properties
    * When fully obfuscated its size may reach 500% of the original size, the performance may reach 10% of the original performance and the obfuscated instruction will be 50-60% at x64 binaries and 20-30% at x86 binaries of the total number of the disassembled instructions
    * Obfuscation is hugely increased if the original binary is statically linked
    * Because the obfuscated instructions are built on the fly, trying to use x-referencing (an import or a string) will be useless even at runtime because the instruction will be removed once executed
* Multi Threading
    * The problem with multi threaded executable is that two or more threads may have race condition over write/clear of the same instruction
    * The tool can efficiently handle this by using `xchg` instruction that has `lock` prefix by default to make sure this won't happen
* De-obfuscation
    * Of course the generated PE can be de-obfuscated, but it requires a lot of work regarding decoding the instructions because every instruction decoding depends on the executing of the previous block so it can be decoded at runtime only
* Development
    * The SBI engine uses the trampoline approach, so not all of the instructions are disassembled (only the long instructions)
    * To obfuscate 100% of the instructions, it should use int3 approach, so I'm going to work on this implementation
* Other binaries types
    * For now it handles only PEs, but the same core and techniques can be applied for any other type

# Additional
* Download source with `git clone --recursive https://github.com/d35ha/xObf`
* Download the binaries from the [release section](https://github.com/d35ha/xObf/releases)
