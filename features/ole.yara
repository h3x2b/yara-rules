rule ole_object : info ole windows
{
	meta:
		//author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect OLE (Object Linking and Embedding)"

	condition:
                //d0cf11e0a1b11ae1 on the beginning of file
                uint32be(0) == 0xd0cf11e0 and
                uint32be(4) == 0xa1b11ae1
}

rule embedded_ole_object : info embedded ole windows
{
	meta:
		//author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect embedded OLE (Object Linking and Embedding)"

	strings:
		$msdocfile_hexstring = { D0 CF 11 E0 A1 B1 1A E1 }

	condition:
                //DOCFILEALBILAE string anywhere within file
		$msdocfile_hexstring
}


