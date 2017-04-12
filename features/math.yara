/* Check the entropy of the files being checked */

import "math"

rule math_entropy_close_8 : info statistics {
	meta:
	        description = "Very high entropy - random stream, packed data or encryption"

	condition:
		math.entropy(0, filesize) >= 7.5
}

rule math_entropy_7 : info statistics {
	meta:
	        description = "High entropy - probably random stream, packed data or encryption"

	condition:
		math.entropy(0, filesize) >= 7 and
		math.entropy(0, filesize) < 7.5
}

rule math_entropy_6 : info statistics {
	meta:
	        description = "High entropy - like binary code or base64 encoded random stream"

	condition:
		math.entropy(0, filesize) >= 6 and
		math.entropy(0, filesize) < 7
}

rule math_entropy_5 : info statistics {
	meta:
	        description = "Medium entropy - like binary data"

	condition:
		math.entropy(0, filesize) >= 5 and
		math.entropy(0, filesize) < 6
}

rule math_entropy_4 : info statistics {
	meta:
	        description = "Low entropy - like plaintext or HTML or sparse data"

	condition:
		math.entropy(0, filesize) >= 4 and
		math.entropy(0, filesize) < 5
}

rule math_entropy_3 : info statistics {
	meta:
	        description = "Low entropy - very sparse data or repeating plaintext"

	condition:
		math.entropy(0, filesize) >= 3 and
		math.entropy(0, filesize) < 4
}

rule math_entropy_2 : info statistics {
	meta:
	        description = "Very low entropy - repeating sequence of couple of bytes"

	condition:
		math.entropy(0, filesize) >= 2 and
		math.entropy(0, filesize) < 3
}

rule math_entropy_1 : info statistics {
	meta:
	        description = "Very low entropy - repeating 2 bytes"

	condition:
		math.entropy(0, filesize) >= 1 and
		math.entropy(0, filesize) < 2
}

rule math_entropy_0 : info statistics {
	meta:
	        description = "Very low entropy - all zeroes or same bytes"

	condition:
		math.entropy(0, filesize) >= 0 and
		math.entropy(0, filesize) < 1
}

