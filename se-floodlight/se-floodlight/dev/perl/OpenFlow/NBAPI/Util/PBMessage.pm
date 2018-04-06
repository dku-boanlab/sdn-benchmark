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

package OpenFlow::NBAPI::Util::PBMessage;

BEGIN {
    our $VERSION = "0.1";
}

use base qw(Exporter);
use strict;

our @EXPORT_SUB = qw(
    pbMessageType pbMessageTypeField pbGetMessage
    pbMessageSubtype pbMessageSubtypeNames pbMessageSubtypeValues
    pbInternalTypeField
    );
our @EXPORT_CONST = qw(
    PB_OF_TYPE PB_CTL_TYPE PB_INT_TYPE PB_EXT_TYPE
    PB_OF PB_CTL PB_INT PB_EXT
    );

our @EXPORT_OK = (
    @EXPORT_SUB,
    @EXPORT_CONST
    );

our %EXPORT_TAGS = (
    all => \@EXPORT_OK,
    functions => \@EXPORT_SUB,
    constants => \@EXPORT_CONST
    );

use OpenFlow::NBAPI::LowLevel::PB::NorthboundAPIPB;

use constant _MSGTYPE      => "MessagePB::MessageType";
use constant PB_OF_TYPE    => _MSGTYPE->SBOFMessageType;
use constant PB_CTL_TYPE   => _MSGTYPE->NBCtrlServiceType;
use constant PB_INT_TYPE   => _MSGTYPE->NBInternalType;
use constant PB_EXT_TYPE   => _MSGTYPE->NBExtensionType;

use constant PB_OF         => "OFMessagePB::OFTypePB";
use constant PB_CTL        => "NBCtlServicePB::ServiceMsgType";
use constant PB_INT        => "NBInternalMsgPB::InternalMsgType";
use constant PB_EXT        => ""; # not defined

use constant PB_TYPE_STRING => {
    PB_OF_TYPE()  => 'OpenFlow',
    PB_CTL_TYPE() => 'CtlService',
    PB_INT_TYPE() => 'Internal',
    PB_EXT_TYPE() => 'Extension'
};

use constant PB_TYPE_FIELD => {
    PB_OF_TYPE()  => 'sbOFMessage',
    PB_CTL_TYPE() => 'nbCtlService',
    PB_INT_TYPE() => 'nbInternal',
    PB_EXT_TYPE() => 'nbExtension'
};

use constant PB_INT_TYPE_FIELD => {
    PB_INT->Error               => 'errorMessage',
    PB_INT->Hello               => 'helloMessage',
    PB_INT->Welcome             => 'welcomeMessage',
    PB_INT->Goodbye             => 'goodbyeMessage',
    PB_INT->AuthenRequest       => 'authenRequestMessage',
    PB_INT->AuthenReply         => 'authenReplyMessage',
    PB_INT->SetQueuePolicy      => 'setQueuePolicyMessage',
    PB_INT->SetQueuePolicyReply => 'setQueuePolicyReplyMessage',
    PB_INT->Ping                => 'pingMessage',
    PB_INT->Extension           => 'extensionMessage'
};

sub pbMessageType {
    my $pbMsg = shift;
    return $pbMsg->messageType;
}

sub pbMessageTypeString {
    defined(my $msgType = shift) or return undef;
    return PB_TYPE_STRING->{$msgType};
}

sub pbMessageTypeField {
    defined(my $msgType = shift) or return undef;
    return PB_TYPE_FIELD->{$msgType};
}

sub pbGetMessage {
    my $pbMsg = shift;
    my $type = pbMessageType($pbMsg);
    my $field = pbMessageTypeField($type) or return undef;
    return $pbMsg->$field();
}

sub pbMessageSubtype {
    my $pbMsg = shift;

    my $type = pbMessageType($pbMsg);
    $type == PB_OF_TYPE and
	return $pbMsg->sbOFMessage->ofMessage->ofType;
    $type == PB_CTL_TYPE and
	return $pbMsg->nbCtlService->msgType;
    $type == PB_INT_TYPE and
	return $pbMsg->nbInternal->msgType;
    $type == PB_EXT_TYPE and
	return 0; # no subtype

    return undef;
}

sub pbMessageSubtypeFields {
    my $type = shift or return undef;

    $type == PB_OF_TYPE and
	return OFMessagePB::OFTypePB::_pb_fields_list;
    $type == PB_CTL_TYPE and
	return NBCtlServicePB::ServiceMsgType::_pb_fields_list;
    $type == PB_INT_TYPE and
	return NBInternalMsgPB::InternalMsgType::_pb_fields_list;
    $type == PB_EXT_TYPE and
	return [["", 0]]; # no enumerated subtypes

    return undef;
}

sub pbMessageSubtypeNames {
    my $type = shift or return undef;
    return map { $_->[0] } @{pbMessageSubtypeFields($type)};
}

sub pbMessageSubtypeValues {
    my $type = shift or return undef;
    return map { $_->[1] } @{pbMessageSubtypeFields($type)};
}

sub pbInternalTypeField {
    defined(my $intType = shift) or return undef;
    return PB_INT_TYPE_FIELD->{$intType};
}


1;
