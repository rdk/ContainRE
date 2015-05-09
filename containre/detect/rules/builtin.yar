/* ContainRE built-in YARA rules - deliberately specific so they don't fire on
 * benign code/heap/stack. Users add their own via policy.detect.yara_rules. */

rule embedded_pe
{
    meta:
        description = "Windows PE executable (MZ header at offset 0)"
        severity = "high"
        attack = "T1027, T1105"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}

rule base64_pe
{
    meta:
        description = "Base64-encoded PE header (TVqQAA...)"
        severity = "medium"
        attack = "T1027, T1140"
    strings:
        $b64 = "TVqQAA"
    condition:
        $b64
}

rule upx_packed
{
    meta:
        description = "UPX-packed binary marker"
        severity = "medium"
        attack = "T1027.002"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX!"
    condition:
        all of them
}

rule linux_reverse_shell
{
    meta:
        description = "Shell spawned on a socket file descriptor (reverse shell)"
        severity = "high"
        attack = "T1059.004"
    strings:
        $sh = "/bin/sh"
        $dup = "dup2"
        $sock = "socket"
    condition:
        $sh and $dup and $sock
}
