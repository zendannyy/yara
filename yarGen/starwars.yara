rule sample_star_wars
{
	meta:
		author = "zendannyy"
		description = "Simple YARA rule for Cyberwox lab POC"
		md5hash = "f1bc52b1c4da8b1d9dbe44bf41697d9d"
	strings:
		$s1 = "Hello there!"
		$s2 = "star{warz}"

	condition:
		($s1 or $s2) and filesize < 20KB
}
