# zelf

Zig's ELF parsing utility - a replacement (maybe someday) utility for `readelf` and `objdump` written in Zig.

## Usage

```
Usage: zelf [options] file

General Options:
-a, --all                Equivalent of having all flags on
-h, --file-header        Display ELF file header
-l, --program-headers    Display program headers (if any)
-S, --section-headers    Display section headers
-s, --symbols            Display symbol table
-r, --relocs             Display relocations (if any)
--help                   Display this help and exit
```

Currently supported flags. More to come.

Typical output will look something like this.

```
> zelf -a main.o
ELF Header:
  Endianness: Endian.Little
  Machine: AMD x86-64 architecture
  Class: ELF64
  Entry point address: 0x0
  Start of program headers: 0 (bytes into file)
  Start of section headers: 592 (bytes into file)
  Size of program headers: 0 (bytes)
  Number of program headers: 0
  Size of section headers: 64 (bytes)
  Number of section headers: 10
  Section header string table index: 8

There are 10 section headers, starting at offset 0x250:

Section Headers:
  [Nr]  Name              Type              Address           Offset
        Size              EntSize           Flags  Link  Info  Align
  [ 0]                    NULL              0000000000000000  0000000000000000
        0000000000000000  0000000000000000            0     0     0
  [ 1]  .text             PROGBITS          0000000000000000  0000000000000040
        0000000000000025  0000000000000000  AX        0     0    16
  [ 2]  .rela.text        RELA              0000000000000000  0000000000000078
        0000000000000048  0000000000000018  I         7     1     8
  [ 3]  .rodata.str1.1    PROGBITS          0000000000000000  0000000000000065
        000000000000000f  0000000000000001  AMS       0     0     1
  [ 4]  .comment          PROGBITS          0000000000000000  00000000000000c0
        0000000000000016  0000000000000001  MS        0     0     1
  [ 5]  .llvm_addrsig     LOOS+0xfff4c03    0000000000000000  00000000000000d6
        0000000000000000  0000000000000000  E         0     0     1
  [ 6]  .note.GNU-stack   PROGBITS          0000000000000000  00000000000000d6
        0000000000000000  0000000000000000            0     0     1
  [ 7]  .symtab           SYMTAB            0000000000000000  00000000000000d8
        00000000000000f0  0000000000000018            9     7     8
  [ 8]  .shstrtab         STRTAB            0000000000000000  00000000000001c8
        0000000000000062  0000000000000000            0     0     1
  [ 9]  .strtab           STRTAB            0000000000000000  000000000000022a
        0000000000000022  0000000000000000            0     0     1

Relocation section '.rela.text' at offset 0x78 contains 3 entries:
  Offset        Info            Type                    Sym. Value  Sym. Name + Addend
000000000004 00090000002a R_X86_64_REX_GOTPCRELX   0000000000000000 stderr -4
00000000000e 000200000002 R_X86_64_PC32            0000000000000000 .L.str -4
00000000001d 000700000004 R_X86_64_PLT32           0000000000000000 fwrite -4

Symbol table '.symtab' contains 10 entries:
  Num:            Value  Size Type    Bind   Vis      Ndx   Name
    0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND   
    1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS   main.c
    2: 0000000000000000    15 OBJECT  LOCAL  DEFAULT  3     .L.str
    3: 0000000000000000     0 SECTION LOCAL  DEFAULT  1     
    4: 0000000000000000     0 SECTION LOCAL  DEFAULT  5     
    5: 0000000000000000     0 SECTION LOCAL  DEFAULT  3     
    6: 0000000000000000     0 SECTION LOCAL  DEFAULT  4     
    7: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND   fwrite
    8: 0000000000000000    37 FUNC    GLOBAL DEFAULT  1     main
    9: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND   stderr

```

