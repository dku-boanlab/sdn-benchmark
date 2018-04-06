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

package OpenFlow::NBAPI::AddrInfo;

BEGIN {
    our $VERSION = "0.1";
}

use threads::shared;

use base qw(OpenFlow::NBAPI::Base::Shared);
use fields qw(
    ctlCtx datapathID expiration port timestamp
    _ipV4Addr _ipV4AddrStr _macAddr _macAddrStr
    );
use strict;

use Scalar::Util qw(blessed);

use OpenFlow::NBAPI::Util::Conversion qw(:all);

__PACKAGE__->_create_accessors();

sub init {
    my $self = shift;

    $self->SUPER::init(@_) or return undef;
    $self->ctlCtx(undef);
    $self->datapathID(undef);
    $self->expiration(undef);
    $self->port(undef);
    $self->timestamp(undef);
    $self->_ipV4Addr(undef);
    $self->_ipV4AddrStr(undef);
    $self->_macAddr(undef);
    $self->_macAddrStr(undef);
    return 1;
}

sub ipV4Addr {
    my $self = shift;

    if (@_) {
	my ($ipV4Addr, $_mask) = parseIPv4(shift);
	if (defined $ipV4Addr) {
	    $self->_ipV4Addr($ipV4Addr);
	    $self->_ipV4AddrStr(uint32ToIPv4($ipV4Addr));
	}
    }
    return $self->_ipV4Addr;
}

sub ipV4AddrStr {
    my $self = shift;

    return $self->_ipV4AddrStr;
}

sub macAddr {
    my $self = shift;

    if (@_) {
	my $macAddr = macToUint64(shift);
	if (defined $macAddr) {
	    $self->_macAddr($macAddr);
	    $self->_macAddrStr(uint64ToMac($macAddr));
	}
    }
    return $self->_macAddr;
}

sub macAddrStr {
    my $self = shift;

    return $self->_macAddrStr;
}

sub equals {
    my $self = shift;
    my $addrInfo = shift or return 0;

    blessed $addrInfo && $addrInfo->isa(__PACKAGE__) or return 0;
    _equals($self->ipV4Addr, $addrInfo->ipV4Addr) or return 0;
    _equals($self->macAddr == $addrInfo->macAddr) or return 0;
    _equals($self->datapathID, $addrInfo->datapathID) or return 0;
    _equals($self->port, $addrInfo->port) or return 0;
    return 1;
}

sub expired {
    my $self = shift;
    my $time = shift || time();

    my $expiration = $self->expiration or return 0;
    return $time > $expiration;
}

sub _equals {
    my $val1 = shift;
    my $val2 = shift;

    if (defined $val1) {
	return defined $val2 ? $val1 == $val2 : 0;
    }
    else {
	return defined $val2 ? 0 : 1;
    }
}


1;
