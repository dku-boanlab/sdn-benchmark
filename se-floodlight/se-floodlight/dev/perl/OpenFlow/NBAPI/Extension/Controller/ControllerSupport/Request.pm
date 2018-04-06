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

package OpenFlow::NBAPI::Extension::Controller::ControllerSupport::Request;

BEGIN {
    our $VERSION = "0.1";
}

use threads::shared;

use base qw(OpenFlow::NBAPI::Base::Shared Exporter);
use fields qw(defaultReturnValue hasReturnValue name _args);
use strict;

our @EXPORT_SUB = qw();
our @EXPORT_CONST = qw(
    EXTENSION
    );

our @EXPORT_OK = (
    @EXPORT_SUB,
    @EXPORT_CONST
    );

our %EXPORT_TAGS = (
    all => \@EXPORT_OK,
    subs => \@EXPORT_SUB,
    constants => \@EXPORT_CONST
    );

use Carp;

use OpenFlow::NBAPI::Util::Extension qw(:all);
use OpenFlow::NBAPI::Util::Logger qw(:all);
use OpenFlow::NBAPI::Util::Value qw(:all);

__PACKAGE__->_create_accessors();

use constant EXTENSION => "ControllerSupport";

sub init {
    my $self = shift;

    $self->SUPER::init(@_) or return undef;
    $self->defaultReturnValue(undef);
    $self->name(shift);
    $self->hasReturnValue(0);
    $self->clearArgs();
    return 1;
}

sub addOptionalArg {
    my $self = shift;
    my $name = shift;
    my $type = shift;
    my $value = shift;

    return $self->_addArg($name, $type, $value);
}

sub addRequiredArg {
    my $self = shift;
    my $name = shift;
    my $type = shift;
    my $value = shift;

    defined $value or do {
	my $reqName = $self->name || "<unknown>";
	writeLog(ERROR, EXTENSION . ": $reqName request missing required argument $name");
	return undef;
    };
    return $self->_addArg($name, $type, $value);
}

sub clearArgs {
    my $self = shift;

    $self->_args([]);
}

sub genExtensionMsg {
    my $self = shift;

    my $request = $self->name or do {
	carp EXTENSION . " request type not specified";
	return undef;
    };
    my $msg = newExtensionMessage(EXTENSION);
    my @dict = ([newValue("aString", "request"), newValue("aString", $request)]);
    push @dict, @{$self->_args};
    $msg->value(newValue("dict", @dict));
    return $msg;
}

sub _addArg {
    my $self = shift;
    my $name = shift;
    my $type = shift;
    my $value = shift;

    if (defined $value) {
	my $args = $self->_args;
	my $pair = &share([]);
	push @$pair, (newValue("aString", $name), newValue($type, $value));
	push @$args, $pair;
    }
    return 1;
}


1;
