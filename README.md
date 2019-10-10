Delinker
========

Overview
--------
This program does the opposite of a linker - it takes a fully linked binary executable file as input, and outputs a set of relocatable .o files. These .o files can be linked again to create a working binary executable. The set of .o files can also be modified before being relinked, either by simply replacing one more more .o files with alternate versions, or by more intrusive methods that modify the contents of the file.

How does it work?
-----------------
After reading in the binary executable file, the delinker performs 'function detection' to restore the function symbols, and then delinks each function by replacing absolute memory references with relocations. The resulting code, data, symbols and relocations are then output to object files.

How to clone & build
--------------------
This project uses git submodules. Therefore, you should clone the project like this:
```
git clone --recurse-submodules https://github.com/jnider/delinker.git
```

External libraries
------------------
All external dependencies are included as git submodules. The advantage of having them as submodules is that we know their location at build-time. That way, we can point to its headers and libraries with a feeling of certainty during building/linking/execution. See 'How to clone & build' above for instructions on cloning with submodules.

Capstone
========
For disassembly, the udis86 library has been replaced with the capstone library. Capstone supports multiple platforms, but otherwise works with a similar API to udis86. The main Makefile for the delinker will automatically build capstone. However, if the need arises to do any tweaking, they have a comprehensive help file (in capstone/COMPILE.TXT) but basically to build it, you need to:
```
cd capstone
./make.sh
```

Nucleus
=======
Nucleus was selected to replace the built-in function detector. They claim to have very good accuracy, andfairly high speed. Since delinker was originally written in C, it is now being migrated to C++ in order to use nucleus objects directly. The nucleus C++ implementation is a bit primitive, and lacking in places. Because major changes are expected, it has been forked into a separate repository for convenience. It is not expected that all of these changes will be accepted back into the main repository. The integration has not yet been fully tested.
