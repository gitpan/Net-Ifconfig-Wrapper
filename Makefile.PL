use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my %Supported = ('freebsd' => 1,
                 'solaris' => 1,
                 'linux'   => 1,
                 'openbsd' => 1,
                 'MSWin32' => 1,
                );

$Supported{$^O}
	or warn "\nWARNING! Your system '$^O' is not supported\b\n\n";

my $PreReq = {};

if ( $^O eq 'MSWin32' )
	{
	Win32::IsWinNT()
		or warn "\nWARNING! Only WinNT (from Win2K) is supported\b\n\n";
	$PreReq->{'Win32::API'}      = 0;
	$PreReq->{'Win32::WinError'} = 0;
	};

WriteMakefile(
    'NAME'		=> 'Net::Ifconfig::Wrapper',
    'VERSION_FROM'	=> 'Wrapper.pm', # finds $VERSION
    'PREREQ_PM'		=> $PreReq, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'Wrapper.pm', # retrieve abstract from module
       AUTHOR     => 'Daniel Podolsky <tpaba@cpan.org>') : ()),
);
