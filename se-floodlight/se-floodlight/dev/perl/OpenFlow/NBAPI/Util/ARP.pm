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

package OpenFlow::NBAPI::Util::ARP;

BEGIN{
    our $VERSION = "0.1";
}

use threads::shared;
use strict;

use base qw(Exporter);

use Carp;

use OpenFlow::NBAPI::Util::Conversion qw(:all);

our @EXPORT_CONSTANTS = qw(
    DEFAULT_ARP_SENDER_IP
    DEFAULT_ARP_SENDER_MAC
    );
our @EXPORT_SUBS = qw(
    genARPRequest
    );

our @EXPORT_OK = (@EXPORT_CONSTANTS, @EXPORT_SUBS);

our %EXPORT_TAGS = (
    all       => \@EXPORT_OK,
    constants => \@EXPORT_CONSTANTS,
    subs      => \@EXPORT_SUBS
    );

use constant DEFAULT_ARP_SENDER_IP  => "0.0.0.0";
use constant DEFAULT_ARP_SENDER_MAC => "fe:ff:ff:ff:ff:ff";

sub genARPRequest {
    my $targetHostAddr = shift;
    my $senderHostAddr = shift || DEFAULT_ARP_SENDER_IP;
    my $senderMACAddr = shift || DEFAULT_ARP_SENDER_MAC;

    my ($targetIP, $_tmask) = parseIPv4($targetHostAddr) or return undef;
    my ($senderIP, $_smask) = parseIPv4($senderHostAddr) or return undef;
    my $targetEth = 'ffffffffffff';
    my $senderEth = uint64ToMac(macToUint64($senderMACAddr), '');

    return pack("H12H12nnnCCnH12NH12N",
		$targetEth, $senderEth,
		0x806, 1, 0x800, 6, 4, 1,
		$senderEth, $senderIP,
		0, $targetIP);
}


1;
