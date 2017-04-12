rule executable_pe : info executable windows
{
	meta:
		//author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect PE executable based on MZ and PE magic"

	strings:
		$pe = "PE"

	condition:
                //MZ on the beginning of file
                uint16(0) == 0x5a4d and
		//PE at offset given by 0x3c
		($pe at (uint32(0x3c)))
}



rule executable_elf32 : info executable linux
{
	meta:
		//author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect ELF 32 bit executable based on ELF magic"

	condition:
                //ELF magic
                uint32(0) == 0x464c457f and
		uint8(4) == 0x01
}


rule executable_elf64 : info executable linux
{
	meta:
		//author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect ELF 64 bit executable based on ELF magic"

	condition:
                //ELF magic
                uint32(0) == 0x464c457f and
		uint8(4) == 0x02
}
