package WWW::Curl::Share;

use strict;
use warnings;
use Carp;

use WWW::Curl ();
use Exporter  ();

our @ISA = qw(Exporter);

our @EXPORT = qw(
CURLSHOPT_LOCKFUNC
CURLSHOPT_NONE
CURLSHOPT_SHARE
CURLSHOPT_UNLOCKFUNC
CURLSHOPT_UNSHARE
CURLSHOPT_USERDATA
);

sub AUTOLOAD {
    our $AUTOLOAD;
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    ( my $constname = $AUTOLOAD ) =~ s/.*:://;
    my $value = constant( $constname );
    if ($!) {
        croak("Undefined subroutine &$AUTOLOAD failed for reasons of $!, constname was $constname, value was: $value");
    }

    {
        no strict 'refs';
        *{$AUTOLOAD} = sub { $value };
    }
    return $value;
}

1;
__END__


Copyright (C) 2008, Anton Fedorov (datacompboy <at> mail.ru)

You may opt to use, copy, modify, merge, publish, distribute and/or sell
copies of the Software, and permit persons to whom the Software is furnished
to do so, under the terms of the MIT license.
