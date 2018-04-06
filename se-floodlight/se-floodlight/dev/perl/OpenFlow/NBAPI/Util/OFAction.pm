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

package OpenFlow::NBAPI::Util::OFAction;

BEGIN{
    our $VERSION = "0.1";
}

use threads::shared;
use strict;

use base qw(Exporter);

use Carp;
use Socket;

use OpenFlow::NBAPI::LowLevel::PB::SBOFActionsPB;
use OpenFlow::NBAPI::Util::Conversion qw(:all);
use OpenFlow::NBAPI::Util::Message qw(:all);
use OpenFlow::NBAPI::Util::OFMatch qw(:all);
use OpenFlow::NBAPI::Util::OFMessage qw(:all);

our @EXPORT_CONSTANTS = qw(
    OF_ACTION
    );
our @EXPORT_SUBS = qw(
    newOFAction
    newOFActionList
    addOFActions
    ofActionListToString
    ofActionToString
    );

our @EXPORT_OK = (@EXPORT_CONSTANTS, @EXPORT_SUBS);

our %EXPORT_TAGS = (
    all       => \@EXPORT_OK,
    constants => \@EXPORT_CONSTANTS,
    subs      => \@EXPORT_SUBS
    );

use constant OF_ACTION     => "OFActionPB::OFActionTypePB";

use constant _DEFAULT_OUTPUT_LIMIT => 1600;

use constant _ACTION_TMPL => {
    MSG_CLASS() => "OFActionPB",
    MSG_TYPE_FIELD() => "actionType",
    MSG_FIELD_TO_TYPE() => sub { "OF\u$_[0]PB" },
    MSG_SUBTYPES() => {
        OF_ACTION->OUTPUT => {
            MSG_ST_FIELD() => "actionOutput",
	    MSG_ST_LABEL() => "output",
	    MSG_ST_TOSTRING() => \&_outputToString,
        },
        OF_ACTION->SET_VLAN_ID => {
            MSG_ST_FIELD() => "actionVirtualLanIdentifier",
	    MSG_ST_LABEL() => "set_vlan_id",
	    MSG_ST_TOSTRING() => \&_setVLANIDToString,
        },
        OF_ACTION->SET_VLAN_PCP => {
            MSG_ST_FIELD() => "actionVirtualLanPriorityCodePoint",
	    MSG_ST_LABEL() => "set_vlan_pcp",
	    MSG_ST_TOSTRING() => \&_setVLANPCPToString,
        },
        OF_ACTION->STRIP_VLAN => {
            MSG_ST_FIELD() => "actionStripVirtualLan",
	    MSG_ST_LABEL() => "strip_vlan",
	    MSG_ST_TOSTRING() => \&_stripVLANToString,
        },
        OF_ACTION->SET_DL_SRC => {
            MSG_ST_FIELD() => "actionDataLayerSource",
            MSG_ST_CONV() => {
                dataLayerAddress => \&_dlAddrParse
            },
	    MSG_ST_LABEL() => "set_dl_src",
	    MSG_ST_TOSTRING() => \&_setDLToString,
        },
        OF_ACTION->SET_DL_DST => {
            MSG_ST_FIELD() => "actionDataLayerDestination",
            MSG_ST_CONV() => {
                dataLayerAddress => \&_dlAddrParse
            },
	    MSG_ST_LABEL() => "set_dl_dst",
	    MSG_ST_TOSTRING() => \&_setDLToString,
        },
        OF_ACTION->SET_NW_SRC => {
            MSG_ST_FIELD() => "actionNetworkLayerSource",
            MSG_ST_CONV() => {
                networkAddress => \&_nwAddrParse
            },
	    MSG_ST_LABEL() => "set_nw_src",
	    MSG_ST_TOSTRING() => \&_setNWToString,
        },
        OF_ACTION->SET_NW_DST => {
            MSG_ST_FIELD() => "actionNetworkLayerDestination",
            MSG_ST_CONV() => {
                networkAddress => \&_nwAddrParse
            },
	    MSG_ST_LABEL() => "set_nw_dst",
	    MSG_ST_TOSTRING() => \&_setNWToString,
        },
        OF_ACTION->SET_NW_TOS => {
            MSG_ST_FIELD() => "actionNetworkTypeOfService",
	    MSG_ST_LABEL() => "set_nw_tos",
	    MSG_ST_TOSTRING() => \&_setTOSToString,
        },
        OF_ACTION->SET_TP_SRC => {
            MSG_ST_FIELD() => "actionTransportLayerSource",
	    MSG_ST_LABEL() => "set_tp_src",
	    MSG_ST_TOSTRING() => \&_setTPToString,
        },
        OF_ACTION->SET_TP_DST => {
            MSG_ST_FIELD() => "actionTransportLayerDestination",
	    MSG_ST_LABEL() => "set_tp_dst",
	    MSG_ST_TOSTRING() => \&_setTPToString,
        },
        OF_ACTION->OPAQUE_ENQUEUE => {
            MSG_ST_FIELD() => "actionEnqueue",
	    MSG_ST_LABEL() => "enqueue",
	    MSG_ST_TOSTRING() => \&_enqueueToString,
        },
        OF_ACTION->VENDOR => {
            MSG_ST_FIELD() => "actionVendor",
	    MSG_ST_LABEL() => "vendor",
	    MSG_ST_TOSTRING() => \&_vendorToString,
        }
    }
};

sub newOFAction {
    return newMessage(_ACTION_TMPL, @_);
}

sub newOFActionList {
    my $list = &share([]);
    return addOFActions($list, @_);
}

sub addOFActions {
    my $list = shift;
    push @$list, @_;
    return $list;
}

sub ofActionListToString {
    my $ofActions = shift or return "<undef>";

    my $str = "";
    for my $ofAction(@$ofActions) {
	$str .= ", " if $str;
	$str .= ofActionToString($ofAction);
    }
    return $str ? "[$str]" : "drop";
}

sub ofActionToString {
    my $ofAction = shift or return "<undef>";

    my $types = _ACTION_TMPL->{MSG_SUBTYPES()};
    my $subtype = $types->{$ofAction->actionType};
    my $label = $subtype->{MSG_ST_LABEL()};
    my $fieldName = $subtype->{MSG_ST_FIELD()};
    my $str = "";
    if (my $field = $ofAction->$fieldName()) {
	my $toString = $subtype->{MSG_ST_TOSTRING()};
	$str = &$toString($field);
    }
    else {
	$str = "<undef>";
    }
    return $str ? "$label=$str" : $label;
}

sub _dlAddrParse {
    return macToUint64(shift);
}

sub _nwAddrParse {
    my ($addr, $mask) = parseIPv4(shift) or return undef;
    return $addr;
}

sub _outputToString {
    my $field = shift;

    my $str = swPortNumberToString($field->port);
    my $maxLen = $field->maxLength;
    $str .= ":$maxLen" if defined $maxLen && $maxLen != _DEFAULT_OUTPUT_LIMIT;
    return $str;
}

sub _setVLANIDToString {
    my $field = shift;

    return $field->virtualLanIdentifier;
}

sub _setVLANPCPToString {
    my $field = shift;

    return $field->virtualLanPriorityCodePoint;
}

sub _stripVLANToString {
    my $field = shift;

    return "";
}

sub _setDLToString {
    my $field = shift;

    return uint64ToMac($field->dataLayerAddress);
}

sub _setNWToString {
    my $field = shift;

    return uint32ToIPv4($field->networkAddress);
}

sub _setTOSToString {
    my $field = shift;

    return $field->networkTypeOfService;
}

sub _setTPToString {
    my $field = shift;

    return $field->transportPort;
}

sub _enqueueToString {
    my $field = shift;

    return swPortNumberToString($field->port) . ":" . $field->queueId;
}

sub _vendorToString {
    my $field = shift;

    return $field->vendor;
}


1;
