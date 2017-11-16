all: *.yara
	find ./ -name '*.yara' -exec echo "include \"{}\"" ";" | sort | grep -v 00_all.yara > 00_all.yara
	yarac 00_all.yara 00_all.yc

