use strict;

my $Win32_FormatMessage   = undef;
my %Win32API = ();
my %ToLoad = ('iphlpapi' => {'GetAdaptersInfo' => [['P','P'],             'N'],
                             'GetIpAddrTable'  => [['P','P','I'],         'N'],
                             'GetIfTable'      => [['P','P','I'],         'N'],
                             'AddIPAddress'    => [['N','N','N','P','P'], 'N'],
                             'DeleteIPAddress' => [['N'],                 'N'],
                            },
             );

if ( "\L$^O" =~ m/win32/ )
	{
	eval {
	     use Win32::API;
	     use Win32::WinError;
	     $Win32_FormatMessage = sub { return Win32::FormatMessage(@_); };
	     foreach my $DLib (keys(%ToLoad))
	     	{
	     	foreach my $Func (keys(%{$ToLoad{$DLib}}))
	     		{
	     		$Win32API{$DLib}->{$Func} = Win32::API->new($DLib, $Func, $ToLoad{$DLib}->{$Func}->[0], $ToLoad{$DLib}->{$Func}->[1])
	     			or die "Cannot import function '$Func' from '$DLib' DLL: $^E";
	     		};
	     	};
	     };
	$@ and die $@;
	};

my $MAX_INTERFACE_NAME_LEN = 512;
my $MAXLEN_PHYSADDR        = 8;
my $MAXLEN_IFDESCR         = 256;

my $st_MIB_IFROW =
	['wszName'           => 'a'.$MAX_INTERFACE_NAME_LEN, #WCHAR wszName[MAX_INTERFACE_NAME_LEN];
	 'dwIndex'           => 'L',                         #DWORD dwIndex;
	 'dwType'            => 'L',                         #DWORD dwType;
	 'dwMtu'             => 'L',                         #DWORD dwMtu;
	 'dwSpeed'           => 'L',                         #DWORD dwSpeed;
	 'dwPhysAddrLen'     => 'L',                         #DWORD dwPhysAddrLen;
	 'bPhysAddr'         => 'a'.$MAXLEN_PHYSADDR,        #BYTE bPhysAddr[MAXLEN_PHYSADDR];
	 'dwAdminStatus'     => 'L',                         #DWORD dwAdminStatus;
	 'dwOperStatus'      => 'L',                         #DWORD dwOperStatus;
	 'dwLastChange'      => 'L',                         #DWORD dwLastChange;
	 'dwInOctets'        => 'L',                         #DWORD dwInOctets;
	 'dwInUcastPkts'     => 'L',                         #DWORD dwInUcastPkts;
	 'dwInNUcastPkts'    => 'L',                         #DWORD dwInNUcastPkts;
	 'dwInDiscards'      => 'L',                         #DWORD dwInDiscards;
	 'dwInErrors'        => 'L',                         #DWORD dwInErrors;
	 'dwInUnknownProtos' => 'L',                         #DWORD dwInUnknownProtos;
	 'dwOutOctets'       => 'L',                         #DWORD dwOutOctets;
	 'dwOutUcastPkts'    => 'L',                         #DWORD dwOutUcastPkts;
	 'dwOutNUcastPkts'   => 'L',                         #DWORD dwOutNUcastPkts;
	 'dwOutDiscards'     => 'L',                         #DWORD dwOutDiscards;
	 'dwOutErrors'       => 'L',                         #DWORD dwOutErrors;
	 'dwOutQLen'         => 'L',                         #DWORD dwOutQLen;
	 'dwDescrLen'        => 'L',                         #DWORD dwDescrLen;
	 'bDescr'            => 'a'.$MAXLEN_IFDESCR,         #BYTE bDescr[MAXLEN_IFDESCR];
	];


my $ShiftStruct = undef;
$ShiftStruct = sub($$)
	{
	my ($Array, $Struct) = @_;

	my $Result = {};
	#tie(%{$Result}, 'Tie::IxHash');

	for (my $RI = 0; defined($Struct->[$RI]); $RI += 2)
		{
		$Result->{$Struct->[$RI]} = ref($Struct->[$RI+1]) ?
		                             &{$ShiftStruct}($Array, $Struct->[$RI+1]) :
		                             shift(@{$Array});
		};
	return $Result;
	};

my $UnpackStr = undef;
$UnpackStr = sub($$)
	{
	my ($Struct, $Repeat) = @_;
	$Repeat or $Repeat = 1;

	my $StructUpStr = '';
	for (my $RI = 1; defined($Struct->[$RI]); $RI += 2)
		{
		$StructUpStr .= ref($Struct->[$RI]) ?
		                   &{$UnpackStr}($Struct->[$RI]) :
		                   $Struct->[$RI];
		};

	my $UpStr = '';
	for (; $Repeat > 0; $Repeat--)
		{ $UpStr .= $StructUpStr; };

	return $UpStr;
	};


my $UnpackStruct = sub($$)
	{
	my ($pBuff, $Struct) = @_;

	my $UpStr = &{$UnpackStr}($Struct);

	my @Array = unpack($UpStr, ${$pBuff});

	substr(${$pBuff}, 0, length(pack($UpStr)), '');

	return &{$ShiftStruct}(\@Array, $Struct);
	};

sub GetInfo
	{
	my $Buff = '';
	my $BuffLen = pack('L', 0);
	my $Res = $Win32API{'iphlpapi'}->{'GetIfTable'}->Call($Buff, $BuffLen, 0);
	
	while ($Res == ERROR_INSUFFICIENT_BUFFER)
		{
		$Buff = "\0" x unpack("L", $BuffLen);
		$Res = $Win32API{'iphlpapi'}->{'GetIfTable'}->Call($Buff, $BuffLen, 0);
		};
	
	if ($Res != NO_ERROR)
		{
		$! = $Res;
		$@ = "Error running 'GetIpAddrTable' function: ".&{$Win32_FormatMessage}($Res);
		return;
		};

	my $Info = {};
	my $IfTable = &{$UnpackStruct}(\$Buff, ['Len' => 'L']);

	print STDERR "T len: $IfTable->{'Len'}\n";
	for (; $IfTable->{'Len'} > 0; $IfTable->{'Len'}--)
		{
		my $IfInfo = &{$UnpackStruct}(\$Buff, $st_MIB_IFROW);

		foreach my $Field ('wszName', 'bDescr')
			{
			#print STDERR "$Field :".$IfInfo->{$Field}."\n";
			$IfInfo->{$Field} =~ s/\x00+\Z//o;
			};

		$Info->{$IfInfo->{'dwIndex'}} = $IfInfo;
		};

	return wantarray ? %{$Info} : $Info;
	};

sub SafeStr
	{
	my $Str = shift
		or return '!UNDEF!';
	$Str =~ s{ ([\x00-\x1f\xff]) } { sprintf("\\x%2.2X", ord($1)) }gsex;
	return $Str;
	};

sub PrintList
	{
	my ($List, $Pref, $Shift) = @_;

	if    (!(ref($List) eq 'ARRAY' || (ref($List) eq 'HASH')))
		{
		$@ = "First parameter have to be ARRAY or HASH reference!";
		if ($^W) { Carp::carp("$@\n"); };
		return;
		};

	my $Res = '';

	my $RunIndex = 0;
	my $Name = undef;
	foreach $Name ((ref($List) eq 'ARRAY') ? @{$List} : keys(%{$List}))
		{
		my $Key = (ref($List) eq 'ARRAY') ? "[$RunIndex]" : "'$Name'";
		my $Val = (ref($List) eq 'ARRAY') ? $Name      : $List->{$Name};
		my $Dlm = (ref($List) eq 'ARRAY') ? '= '       : '=>';
		if    (ref($Val) eq 'ARRAY')
			{ $Res .= sprintf("%s%s array\n%s",  $Pref, $Key, PrintList($Val, $Pref.$Shift, $Shift)); }
		elsif (ref($Val) eq 'HASH')
			{ $Res .= sprintf("%s%s hash\n%s",   $Pref, $Key, PrintList($Val, $Pref.$Shift, $Shift)); }
		else
			{ $Res .= sprintf("%s%s\t%s %s\n",   $Pref, $Key, $Dlm, (defined($Val) ? '"'.SafeStr($Val).'"' : 'undef')); }
		$RunIndex++;
		};

	return $Res;
	};


my $Info = GetInfo();

print PrintList($Info, '', '  ');

exit 0;

