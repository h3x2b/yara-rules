rule crypto_vertical_transposition : info crypto {
	meta:
	        description = "Alphabet plaintext writtent in transposition cipher"
		/* Vertical transposition with 4 rows such as
			AEIMQU DHLPTX UQMIEA XTPLHD
			BFJNRV CGKOSW VRNJFB WSOKGC
			CGKOSW BFJNRV WSOKGC VRNJFB
			DHLPTX AEIMQU XTPLHD UQMIEA
		*/

	strings:
		$s_topleft_01  = "AEIMQU"
		$s_topleft_02  = "BFJNRV"
		$s_topleft_03  = "CGKOSW"
		$s_topleft_04  = "DHLPTX"
		$s_topright_01 = "UQMIEA"
		$s_topright_02 = "VRNJFB"
		$s_topright_03 = "WSOKGC"
		$s_topright_04 = "XTPLHD"

		$sl_topleft_01  = "aeimqu"
		$sl_topleft_02  = "bfjnrv"
		$sl_topleft_03  = "cgkosw"
		$sl_topleft_04  = "dhlptx"
		$sl_topright_01 = "umqmiea"
		$sl_topright_02 = "vrnjfb"
		$sl_topright_03 = "wsokgc"
		$sl_topright_04 = "xtplhd"

	condition:
                4 of ($s_*) or 4 of ($sl_*)
}


rule crypto_vertical_transposition_wide : info crypto {
	meta:
	        description = "Alphabet plaintext writtent in transposition cipher"
		/* Vertical transposition with 4 rows such as
			AEIMQU DHLPTX UQMIEA XTPLHD
			BFJNRV CGKOSW VRNJFB WSOKGC
			CGKOSW BFJNRV WSOKGC VRNJFB
			DHLPTX AEIMQU XTPLHD UQMIEA
		*/

	strings:
		$s_topleft_01   = { 41 ?? 45 ?? 49 ?? 4d ?? 51 ?? 55 }
		$s_topleft_02   = { 42 ?? 46 ?? 4a ?? 4e ?? 52 ?? 56 }
		$s_topleft_03   = { 43 ?? 47 ?? 4b ?? 4f ?? 53 ?? 57 }
		$s_topleft_04   = { 44 ?? 48 ?? 4c ?? 50 ?? 54 ?? 58 }
		$s_topright_01  = { 55 ?? 51 ?? 4d ?? 49 ?? 45 ?? 41 }
		$s_topright_02  = { 56 ?? 52 ?? 4e ?? 4a ?? 46 ?? 42 }
		$s_topright_03  = { 57 ?? 53 ?? 4f ?? 4b ?? 47 ?? 43 }
		$s_topright_04  = { 58 ?? 54 ?? 50 ?? 4c ?? 48 ?? 44 }

		$sl_topleft_01  = { 61 ?? 65 ?? 69 ?? 6d ?? 71 ?? 75 }
		$sl_topleft_02  = { 62 ?? 66 ?? 6a ?? 6e ?? 72 ?? 76 }
		$sl_topleft_03  = { 63 ?? 67 ?? 6b ?? 6f ?? 73 ?? 77 }
		$sl_topleft_04  = { 64 ?? 68 ?? 6c ?? 70 ?? 74 ?? 78 }
		$sl_topright_01 = { 75 ?? 71 ?? 6d ?? 69 ?? 65 ?? 61 }
		$sl_topright_02 = { 76 ?? 72 ?? 6e ?? 6a ?? 66 ?? 62 }
		$sl_topright_03 = { 77 ?? 73 ?? 6f ?? 6b ?? 67 ?? 63 }
		$sl_topright_04 = { 58 ?? 54 ?? 50 ?? 4c ?? 48 ?? 44 }
	condition:
                4 of ($s_*) or 4 of ($sl_*)
}

rule crypto_LM_DES: info crypto {
        meta:
                description = "String constant 'KGS!@#$%' used in LM DES"

        strings:
                $lm_des = "KGS!@#$%"

        condition:
                all of them
}
