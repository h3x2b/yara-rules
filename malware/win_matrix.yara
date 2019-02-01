rule matrix__mutex: malware ransomware windows
{
  meta:
	author = "@h3x2b <tracker@h3x.eu>"
    	description = "Match matrix ransomware by mutex"
	
  strings:
    	$dll01 = "OurMainMutex999"
    	$dll02 = "OurMainMutex999net"

  condition:
    	any of them 
        and filesize < 1000000
        
}

