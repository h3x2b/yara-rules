all: *.yara
	find ./ -name '*.yara' -exec echo "include \"{}\"" ";" | grep -v 00_all.yara > 00_all.yara
	yarac 00_all.yara 00_all.yc
	cd ../ && ./yaracompile_safe.sh

