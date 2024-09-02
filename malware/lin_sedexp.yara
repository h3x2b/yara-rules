rule sedexp: malware linux
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects sedexp samples - 202408"
                // Check also: https://www.aon.com/en/insights/cyber-labs/unveiling-sedexp
                // Samples:
		// 43f72f4cdab8ed40b2f913be4a55b17e7fd8a7946a636adb4452f685c1ffea02
		// 94ef35124a5ce923818d01b2d47b872abd5840c4f4f2178f50f918855e0e5ca2
		// b981948d51e344972d920722385f2370caf1e4fac0781d508bc1f088f477b648

        strings:
                $sedexp_00 = "sedexp"
                $sedexp_01 = "HOME=/proc"
                $sedexp_02 = "kdevtmpfs"
                $sedexp_03 = "/lib/udev/%s"
                $sedexp_04 = "/proc/self/exe"
                $sedexp_05 = "pkill"
                $sedexp_06 = "/lib/modules/%s"

        condition:
                //ELF magic
                uint32(0) == 0x464c457f and

                //Contains all of the strings
                5 of ($sedexp_*)
}

