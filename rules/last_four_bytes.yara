import "console"

rule last_four_bytes
{
    meta:
        Description = "print out the uint32 of the last four bytes of file"


    condition:
        console.log("last four bytes of file: ", uint32(filesize -4))

}
