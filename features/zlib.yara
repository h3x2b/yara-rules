rule zlib: info feature library
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects usage of zlib deflate by copyright string"

        strings:
                $zlib_00 = "Copyright 1995-2017 Jean-loup Gailly and Mark Adler"

        condition:
                //ELF magic
                uint32(0) == 0x464c457f and

                //Contains all of the strings
                1 of ($zlib_*)
}

