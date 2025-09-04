
rule Sample_UPX_Packer
{
    meta:
        description = "Detect UPX packer string"
        family = "UPX-packed"
    strings:
        $a = "UPX!"
    condition:
        $a
}
