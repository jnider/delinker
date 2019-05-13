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
The udis86 library has been replaced with the capstone library. Capstone supports multiple platforms, but otherwise
works with a similar API to udis86. It is included as a git submodule in this project. You can get the code with:
```
git submodule update --init
```

The advantage of having it as a submodule is that we know its location. That way, we can point to its headers and
libraries with a feeling of certainty during building/linking/execution. They have a comprehensive help file (in
capstone/COMPILE.TXT) but basically to build it, you need to:
```
cd capstone
./make.sh
```
