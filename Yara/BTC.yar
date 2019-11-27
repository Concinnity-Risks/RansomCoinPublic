rule
bitcoin	{
	strings:
	$key	=	/5[HJK][1-9A-Za-z][^OIl]{48}}/
	$addr	=	/[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
	condition:
	any	of them
}
