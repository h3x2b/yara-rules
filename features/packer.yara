rule upx_sections : info packer upx
{
    meta:
        // author = "@h3x2b <tracker _AT h3x.eu>"
        description = "Contains UPX sections"

    strings:
        $str_upx_01 = "UPX0"
        $str_upx_02 = "UPX1"

    condition:
        uint16be(0) == 0x4d5a and
        all of ( $str_upx_* )
}


