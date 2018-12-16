Delinker
========

Overview
--------
This program does the opposite of a linker - it takes a fully linked binary executable file as input, and outputs a set of relocatable .o files. These .o files can be linked again to create a working binary executable. The set of .o files can also be modified before being relinked, either by simply replacing one more more .o files with alternate versions, or by more intrusive methods that modify the contents of the file.

How does it work?
-----------------
After reading in the binary executable file, the delinker performs 'function detection' to restore the function symbols, and then delinks each function by replacing absolute memory references with relocations. The resulting code, data, symbols and relocations are then output to object files.

External libraries
------------------
The unlinker is dependent on the udis86 library, which by default is installed to /usr/local/lib. Unfortunately,
that path is not searched by default which means the unlinker program fails to load every time, unless we
tell the computer where to look, by adding it to the library search path:
```
  export LD_LIBRARY_PATH=/usr/local/lib
```
