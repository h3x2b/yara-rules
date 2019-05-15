rule turkish_downloader : vb_win32api
{
    meta:
        hash1  = "50715a07883c6564c68a43f56d93cb83dd68da6258d5d491a8dc51e25b4836ef"
 
    strings:
        $flag_01 = "TESTER"

    condition:
        //DOC file magic
        uint32be(0) == 0xD0CF11E0 and
        all of ($flag_*) 
}
