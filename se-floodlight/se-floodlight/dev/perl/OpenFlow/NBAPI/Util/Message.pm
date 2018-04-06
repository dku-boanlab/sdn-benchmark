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

package OpenFlow::NBAPI::Util::Message;

BEGIN{
    our $VERSION = "0.1";
}

use threads::shared;
use strict;

use base qw(Exporter);

use Carp;
use Socket;

use OpenFlow::NBAPI::LowLevel::PB::NorthboundAPIPB;
use OpenFlow::NBAPI::Util::Conversion qw(:all);
use OpenFlow::NBAPI::Util::Value qw(:all);

our @EXPORT_CONSTANTS = qw(
    MSG_CLASS
    MSG_TYPE_FIELD
    MSG_FIELD_TO_TYPE
    MSG_SUBTYPES
    MSG_ST_FIELD
    MSG_ST_TYPE
    MSG_ST_CONV
    MSG_ST_LABEL
    MSG_ST_TOSTRING
    );
our @EXPORT_SUBS = qw(
    newMessage
    errorStatus
    statusReplyMessage
    );

our @EXPORT_OK = (@EXPORT_CONSTANTS, @EXPORT_SUBS);

our %EXPORT_TAGS = (
    all       => \@EXPORT_OK,
    constants => \@EXPORT_CONSTANTS,
    subs      => \@EXPORT_SUBS
    );

use constant MSG_CLASS            => "class";
use constant MSG_TYPE_FIELD       => "typeField";
use constant MSG_FIELD_TO_TYPE    => "fieldToType";
use constant MSG_SUBTYPES         => "subtypes";
use constant MSG_ST_FIELD         => "field";
use constant MSG_ST_TYPE          => "type";
use constant MSG_ST_CONV          => "conv";
use constant MSG_ST_LABEL         => "label";
use constant MSG_ST_TOSTRING      => "toString";

use constant _STATUS              => "StatusReplyPB::StatusEnum";

sub newMessage {
    my $msgTmpl = shift;
    my $subtype = shift;
    my $subfields = shift || {};

    my $class = $msgTmpl->{MSG_CLASS()};
    my $msg = &share($class->new());

    defined($subtype) or return $msg;

    my $stDesc = $msgTmpl->{MSG_SUBTYPES()}->{$subtype} or do {
	carp "unknown $class type $subtype";
	return undef;
    };

    $msg->{$msgTmpl->{MSG_TYPE_FIELD()}} = shared_clone($subtype);

    my $fieldName = $stDesc->{MSG_ST_FIELD()};
    my $fieldType = $stDesc->{MSG_ST_TYPE()} ||
	($stDesc->{MSG_ST_TYPE()} = $msgTmpl->{MSG_FIELD_TO_TYPE()}($fieldName));
    my $field = &share($fieldType->new());
    foreach my $sfName (keys %$subfields) {
	$field->can($sfName) or do {
	    carp "unknown subfield $sfName in $fieldName";
	    return undef;
	};
	my $sfValue = $subfields->{$sfName};
	if (my $conv = $stDesc->{MSG_ST_CONV()}->{$sfName}) {
	    $sfValue = &$conv($sfValue);
	}
	defined($sfValue) or do {
	    carp "invalid or undefined value for subfield $sfName";
	    return undef;
	};
	$field->$sfName(shared_clone($sfValue));
    }
    $msg->$fieldName($field);

    return $msg;
}

sub errorStatus {
    my $msg = shift;

    if (my $statusReplies = $msg->replyStatus) {
	foreach my $statusReply (@$statusReplies) {
	    return $statusReply if $statusReply->status == _STATUS->ERROR;
	}
    }

    return undef;
}

sub statusReplyMessage {
    my $statusReply = shift or return undef;

    return convertValue($statusReply->detail, "aString");
}


1;
