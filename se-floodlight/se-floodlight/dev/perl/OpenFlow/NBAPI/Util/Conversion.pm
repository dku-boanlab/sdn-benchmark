=pod

=begin _copyright_notice_

Copyright (c) 2013, SRI International. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

      * Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.
      * Redistributions in binary form must reproduce the above
        copyright notice, this list of conditions and the following
        disclaimer in the documentation and/or other materials
        provided with the distribution.
      * Neither the name of the SRI International nor the names of its
        contributors may be used to endorse or promote products
        derived from this software without specific prior written
        permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=end _copyright_notice_

=cut

package OpenFlow::NBAPI::Util::Conversion;

BEGIN{
    our $VERSION = "0.1";
}

use threads::shared;
use strict;

use base qw(Exporter);

use Carp;
use Socket;

our @EXPORT_CONSTANTS = qw(
    );
our @EXPORT_SUBS = qw(
    dpidToString
    macToUint64
    uint64ToMac
    parseIPv4
    uint32ToIPv4
    );

our @EXPORT_OK = (@EXPORT_CONSTANTS, @EXPORT_SUBS);

our %EXPORT_TAGS = (
    all       => \@EXPORT_OK,
    constants => \@EXPORT_CONSTANTS,
    subs      => \@EXPORT_SUBS
    );

sub dpidToString {
    my $dpid = shift;

    defined $dpid or return undef;
    return sprintf "%llx", $dpid;
}

# If the argument looks like an integer, no conversion
# is performed; otherwise, the argument is treated as
# a string of hex digits, possibly with ':' or '-'
# separators, and converted to a uint64 value.
sub macToUint64 {
    my $arg = shift;
    defined $arg or return undef;

    "$arg" =~ /^[1-9]\d+$/ and return $arg;

    $arg =~ s/[:\-]//g;            # remove separators
    $arg = sprintf("%016s", $arg); # left-pad with '0' to 16 digits
    return unpack("Q>", pack("H16", $arg));
}

sub uint64ToMac {
    my $arg = shift;
    my $sep = shift;

    defined $arg or return undef;
    defined $sep or $sep = ':';
    return join $sep, unpack("xx(H2)6", pack("Q>", $arg));
}

# Parses an IPv4 address with optional mask,
# <addr>[/<mask>], into two uint32 values,
# the first representing the address, and
# the second representing the number of
# contiguous rightmost zero bits in the mask.
#
# <addr> can be a host name or dotted quad.
# <mask>, if present, can be a dotted quad or
# the number of mask bits (i.e., the returned value).
#
# Returns undef on failure.
sub parseIPv4 {
    my $addrSpec = shift;
    defined $addrSpec or return undef;

    my ($addr, $mask) = split '/', $addrSpec, 2;

    $addr = inet_aton($addr) or return undef;
    $addr = unpack("N", $addr);

    $mask = 32 unless defined($mask);
    if ("$mask" !~ /^\d+$/) {
	$mask = inet_aton($mask) or return undef;
	$mask = unpack("N", $mask);
	my $i = 32;
	until ($i == 0 || $mask & 0x1) {
	    $mask >>= 1;
	    --$i;
	}
	$mask = $i;
    }

    return ($addr, $mask);
}

sub uint32ToIPv4 {
    my $uint32 = shift || 0;

    return inet_ntoa(pack("N", $uint32));
}

1;
