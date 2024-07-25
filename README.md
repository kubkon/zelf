# zelf

Zig's ELF parsing utility - a replacement (maybe someday) utility for `readelf` written in Zig.

## Usage

```
Usage: zelf [options] file

General Options:
-a, --all                        Equivalent of having all flags on
-g, --section-groups             Display the section groups
-h, --file-header                Display ELF file header
-l, --program-headers            Display program headers (if present)
-S, --section-headers            Display section headers
-s, --symbols                    Display symbol table
    --dyn-syms                   Display the dynamic symbol table
-r, --relocs                     Display relocations (if present)
-d, --dynamic                    Display the dynamic section (if present)
--initializers                   Display table(s) of initializers/finalizers (if present)
-p, --string-dump=<number|name>  Dump the contents of section <number|name> as strings
-V, --version-info               Display the version sections (if present)
-W, --wide                       Do not shorten the names if too wide
-x, --hex-dump=<number|name>     Dump the contents of section <number|name> as bytes
--help                           Display this help and exit
```

Currently supported flags. More to come.

Typical output will look something like this.

```
> zelf -a main.o
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          28208 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           64 (bytes)
  Number of section headers:         23
  Section header string table index: 22

There are 23 section headers, starting at offset 0x6e30:

Section Headers:
  [Nr]  Name              Type              Address           Offset
        Size              EntSize           Flags  Link  Info  Align
  [ 0]                    NULL              0000000000000000  0000000000000000
        0000000000000000  0000000000000000            0     0     0
  [ 1]  .note.gnu.pr[..]  NOTE              0000000000000000  0000000000000040
        0000000000000040  0000000000000000  A         0     0     8
  [ 2]  .note.ABI-tag     NOTE              0000000000000000  0000000000000080
        0000000000000020  0000000000000000  A         0     0     4
  [ 3]  .text             PROGBITS          0000000000000000  00000000000000a0
        0000000000000031  0000000000000000  AX        0     0    16
  [ 4]  .rela.text        RELA              0000000000000000  0000000000000480
        0000000000000030  0000000000000018  I        20     3     8
  [ 5]  .rodata.cst4      PROGBITS          0000000000000000  00000000000000d4
        0000000000000004  0000000000000004  AM        0     0     4
  [ 6]  .eh_frame         PROGBITS          0000000000000000  00000000000000d8
        000000000000005c  0000000000000000  A         0     0     8
  [ 7]  .rela.eh_frame    RELA              0000000000000000  00000000000004b0
        0000000000000030  0000000000000018  I        20     6     8
  [ 8]  .data             PROGBITS          0000000000000000  0000000000000134
        0000000000000004  0000000000000000  WA        0     0     1
  [ 9]  .bss              NOBITS            0000000000000000  0000000000000138
        0000000000000000  0000000000000000  WA        0     0     1
  [10]  .comment          PROGBITS          0000000000000000  0000000000000138
        0000000000000036  0000000000000001  MS        0     0     1
  [11]  .note.GNU-stack   PROGBITS          0000000000000000  000000000000016e
        0000000000000000  0000000000000000            0     0     1
  [12]  .debug_aranges    PROGBITS          0000000000000000  00000000000004e0
        000000000000003b  0000000000000000  C         0     0     8
  [13]  .rela.debug_[..]  RELA              0000000000000000  0000000000000520
        0000000000000090  0000000000000018  I        20    12     8
  [14]  .debug_info       PROGBITS          0000000000000000  00000000000005b0
        00000000000013c4  0000000000000000  C         0     0     8
  [15]  .rela.debug_info  RELA              0000000000000000  0000000000001978
        00000000000041d0  0000000000000018  I        20    14     8
  [16]  .debug_abbrev     PROGBITS          0000000000000000  0000000000005b48
        00000000000001ac  0000000000000000  C         0     0     8
  [17]  .debug_line       PROGBITS          0000000000000000  0000000000005cf8
        0000000000000313  0000000000000000  C         0     0     8
  [18]  .rela.debug_line  RELA              0000000000000000  0000000000006010
        0000000000000030  0000000000000018  I        20    17     8
  [19]  .debug_str        PROGBITS          0000000000000000  0000000000006040
        0000000000000d1a  0000000000000001  MSC       0     0     8
  [20]  .symtab           SYMTAB            0000000000000000  0000000000000170
        0000000000000288  0000000000000018           21    19     8
  [21]  .strtab           STRTAB            0000000000000000  00000000000003f8
        0000000000000088  0000000000000000            0     0     1
  [22]  .shstrtab         STRTAB            0000000000000000  0000000000006d5a
        00000000000000d6  0000000000000000            0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)

There are no program headers in this file.

Relocation section '.rela.text' at offset 0x480 contains 2 entries:
  Offset        Info            Type                    Sym. Value  Sym. Name + Addend
000000000017 00150000002a R_X86_64_REX_GOTPCRELX   0000000000000000 main - 4
00000000001d 001900000029 R_X86_64_GOTPCRELX       0000000000000000 __libc_start_main - 4

Relocation section '.rela.eh_frame' at offset 0x4b0 contains 2 entries:
  Offset        Info            Type                    Sym. Value  Sym. Name + Addend
000000000020 000300000002 R_X86_64_PC32            0000000000000000 .text + 0
000000000050 000300000002 R_X86_64_PC32            0000000000000000 .text + 30

Relocation section '.rela.debug_aranges' at offset 0x520 contains 6 entries:
  Offset        Info            Type                    Sym. Value  Sym. Name + Addend
000000000006 000b0000000a R_X86_64_32              0000000000000000 .debug_info + 0
000000000010 000300000001 R_X86_64_64              0000000000000000 .text + 0
000000000036 000b0000000a R_X86_64_32              0000000000000000 .debug_info + 2e
000000000056 000b0000000a R_X86_64_32              0000000000000000 .debug_info + af4
000000000076 000b0000000a R_X86_64_32              0000000000000000 .debug_info + b34
000000000080 000300000001 R_X86_64_64              0000000000000000 .text + 30

Symbol table '.symtab' contains 27 entries:
  Num:            Value  Size Type    Bind   Vis      Ndx   Name
    0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND   
    1: 0000000000000000     0 SECTION LOCAL  DEFAULT  1     
    2: 0000000000000000     0 SECTION LOCAL  DEFAULT  2     
    3: 0000000000000000     0 SECTION LOCAL  DEFAULT  3     
    4: 0000000000000000     0 SECTION LOCAL  DEFAULT  5     
    5: 0000000000000000     0 SECTION LOCAL  DEFAULT  6     
    6: 0000000000000000     0 SECTION LOCAL  DEFAULT  8     
    7: 0000000000000000     0 SECTION LOCAL  DEFAULT  9     
    8: 0000000000000000     0 SECTION LOCAL  DEFAULT  10    
    9: 0000000000000000     0 SECTION LOCAL  DEFAULT  11    
   10: 0000000000000000     0 SECTION LOCAL  DEFAULT  12    
   11: 0000000000000000     0 SECTION LOCAL  DEFAULT  14    
   12: 0000000000000000     0 SECTION LOCAL  DEFAULT  16    
   13: 0000000000000000     0 SECTION LOCAL  DEFAULT  17    
   14: 0000000000000000     0 SECTION LOCAL  DEFAULT  19    
   15: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS   abi-note.c
   16: 0000000000000000    32 OBJECT  LOCAL  DEFAULT  2     __abi_tag
   17: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS   init.c
   18: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS   static-reloc.c
   19: 0000000000000030     1 FUNC    GLOBAL UNKNOWN  3     _dl_relocate_static_pie
   20: 0000000000000000    34 FUNC    GLOBAL DEFAULT  3     _start
   21: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND   main
   22: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  8     data_start
   23: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND   _GLOBAL_OFFSET_TABLE_
   24: 0000000000000000     4 OBJECT  GLOBAL DEFAULT  5     _IO_stdin_used
   25: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND   __libc_start_main
   26: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  8     __data_start

```

