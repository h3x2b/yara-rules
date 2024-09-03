rule linux_kernel_module: info linux lkm
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects LKM - Linux kernel module"

        strings:
                $lkm_00 = "addressable_init_module"
                $lkm_01 = "addressable_cleanup_module"
                $lkm_02 = "vermagic="
                $lkm_03 = "retpoline="
                $lkm_04 = "depends="
                $lkm_05 = "name="
                $lkm_06 = "license="
                $lkm_07 = "author="
                $lkm_08 = "description="

        condition:
                //ELF magic
                uint32(0) == 0x464c457f and

                //Contains all of the strings
                5 of ($lkm_*)
}

