rule zlib: info feature library
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects usage of zlib deflate by copyright string"

        strings:
                $zlib_00 = " deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly and Mark Adler "
                $zlib_01 = "deflate_copyright"

        condition:
                //ELF magic
                uint32be(0) == 0x7f454c46 and

                //Contains any of the strings
                1 of ($zlib_*)
}

