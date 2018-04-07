External libraries

The unlinker is dependent on the udis86 library, which by default is installed to /usr/local/lib. This is stupid,
because that path is not searched by default which means the unlinker program fails to load every time, unless we
tell the computer where to look, by adding it to the library search path:

export LD_LIBRARY_PATH=/usr/local/lib
