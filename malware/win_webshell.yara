rule iis_dot_net : webshell
{
    meta:
        description = "Identify .Net webshell"
        author = "tracker [_at] h3x.eu"
        // Error.cshtml

    strings:
        $shell_1 = "using System.Diagnostics"
        $shell_2 = "new Process()"
        $shell_3 = "StartInfo.FileName = "
        $shell_4 = "StartInfo.Arguments = "
	$shell_5 = "StartInfo.UseShellExecute = "
        $shell_6 = "StartInfo.CreateNoWindow = true"

    condition:
        all of ( $shell_* )
}
