// https://github.com/frizb/FirmwareReverseEngineering/blob/master/IdentifyingCompressionAlgorithms.md
rule xz_magic: info compress
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects XZ stream magics in ELF executable"

        strings:
		// .7zXZ header magic - .7zXZ
                $xz_00 = { fd 37 7a 58 }

		// footer magic YZB - lzma_stream_footer_decode
                $xz_01 = "YZB"

        condition:
                //ELF magic
                uint32be(0) == 0x7f454c46 and

                //Contains the strings
                2 of ($xz_*)
}

