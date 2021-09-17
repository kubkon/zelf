# zelf

Zig's ELF parsing utility - a replacement (maybe someday) utility for `readelf` and `objdump` written in Zig.

## Usage

```
zelf [-hS] [--help] <FILE>
            --help              Display this help and exit
        -a, --all               Equivalent to having all flags on
        -h, --file-header       Display the ELF file header
        -S, --section-headers   Display the sections' header
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
```

## Building from source

You will need Zig 0.8.x in your PATH.

```
> git clone --recurse-submodules https://github.com/kubkon/zelf
> cd zelf
> zig build -Drelease-fast
```

