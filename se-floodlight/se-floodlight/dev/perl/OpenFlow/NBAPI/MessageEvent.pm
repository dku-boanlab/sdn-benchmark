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

package OpenFlow::NBAPI::MessageEvent;

use threads::shared;

use base qw(OpenFlow::NBAPI::Base::Shared);
use fields qw(auxData ctlCtx eventID eventTime pbMsg);

__PACKAGE__->_create_accessors();

use Carp;

use OpenFlow::NBAPI::LowLevel::PB::NorthboundAPIPB;

our $_class :shared = __PACKAGE__;
our $_classRef :shared = \$_class;
our $_numEvents :shared = 0;

sub init {
    my $self = shift;

    $self->SUPER::init(@_) or return undef;
    {
	lock $_classRef;
	$self->eventID(++$_numEvents);
    }
    $self->auxData(undef);
    $self->ctlCtx(undef);
    $self->pbMsg(undef);
    $self->eventTime(time());
    return 1;
}

sub ctlCtx {
    my $self = shift;

    if (@_) {
	$self->{ctlCtx} = shift unless defined $self->{ctlCtx};
    }
    return $self->{ctlCtx};
}

sub eventID {
    my $self = shift;

    if (@_) {
	$self->{eventID} = shift unless defined $self->{eventID};
    }
    return $self->{eventID};
}

sub eventTime {
    my $self = shift;

    if (@_) {
	$self->{eventTime} = shift unless defined $self->{eventTime};
    }
    return $self->{eventTime};
}

sub pbMsg {
    my $self = shift;

    if (@_) {
	$self->{pbMsg} = shift unless defined $self->{pbMsg};
    }
    return $self->{pbMsg};
}


1;
