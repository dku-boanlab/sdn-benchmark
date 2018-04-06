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

package OpenFlow::NBAPI::Util::OFMessage;

BEGIN{
    our $VERSION = "0.1";
}

use threads::shared;
use strict;

no warnings('portable');

use base qw(Exporter);

use Carp;
use Socket;

use OpenFlow::NBAPI::LowLevel::PB::SBOFMessagesPB;
use OpenFlow::NBAPI::Util::Conversion qw(:all);
use OpenFlow::NBAPI::Util::Logger qw(:all);
use OpenFlow::NBAPI::Util::Message qw(:all);

our @EXPORT_CONSTANTS = qw(
    OF
    OFPFC
    OFPFF
    OFPP
    OFPPC
    OFPPF
    OFPPS
    OFPRR
    OF_SWITCH_STATUS
    );
our @EXPORT_SUBS = qw(
    isIPClassDorE
    isLocalHostIP
    isMACBroadcast
    isValidHostIP
    isValidHostMAC
    isValidHostSwitchPort
    newOFMessage
    swPortAddrToString
    swPortConfigToString
    swPortFeaturesToString
    swPortNumberToString
    swPortStateToString
    swPortToString
    );

our @EXPORT_OK = (@EXPORT_CONSTANTS, @EXPORT_SUBS);

our %EXPORT_TAGS = (
    all       => \@EXPORT_OK,
    constants => \@EXPORT_CONSTANTS,
    subs      => \@EXPORT_SUBS
    );

use constant OF               => "OFMessagePB::OFTypePB";
use constant OFPFC            => "OFFlowModPB::OFFlowModCommandPB";
use constant OFPFF            => "OFFlowModPB::OFPFlowModFlagsPB";
use constant OFPP             => "OFPortPB";
use constant OFPPC            => "OFPhysicalPortPB::OFPortConfigPB";
use constant OFPPF            => "OFPhysicalPortPB::OFPortFeaturesPB";
use constant OFPPS            => "OFPhysicalPortPB::OFPortStatePB";
use constant OFPRR            => "OFFlowRemovedPB::OFFlowRemovedReasonPB";
use constant OF_SWITCH_STATUS => "OFSwitchStatusPB::SwitchStatusPB";

use constant _OFPP_NAME => {
    OFPP->OFPP_IN_PORT()    => 'IN',
    OFPP->OFPP_TABLE()      => 'TABLE',
    OFPP->OFPP_NORMAL()     => 'NORMAL',
    OFPP->OFPP_FLOOD()      => 'FLOOD',
    OFPP->OFPP_ALL()        => 'ALL',
    OFPP->OFPP_CONTROLLER() => 'CTLR',
    OFPP->OFPP_LOCAL()      => 'LOCAL',
    OFPP->OFPP_NONE()       => 'NONE',
};

use constant _OFPPC_NAME => {
    OFPPC->OFPPC_PORT_DOWN    => 'port-down',
    OFPPC->OFPPC_NO_STP       => 'no-stp',
    OFPPC->OFPPC_NO_RECV      => 'no-recv',
    OFPPC->OFPPC_NO_RECV_STP  => 'no-recv-stp',
    OFPPC->OFPPC_NO_FLOOD     => 'no-flood',
    OFPPC->OFPPC_NO_FWD       => 'no-fwd',
    OFPPC->OFPPC_NO_PACKET_IN => 'no-pkt-in',
};

use constant _OFPPS_NAME => {
    OFPPS->OFPPS_LINK_DOWN   => 'link-down',
#    OFPPS->OFPPS_STP_LISTEN  => 'stp-none',
    OFPPS->OFPPS_STP_LEARN   => 'stp-learn',
    OFPPS->OFPPS_STP_FORWARD => 'stp-relay',
    OFPPS->OFPPS_STP_BLOCK   => 'stp-block',
};

use constant _OFPPF_NAME => {
    OFPPF->OFPPF_10MB_HD    => '10mb-hd',
    OFPPF->OFPPF_10MB_FD    => '10mb-fd',
    OFPPF->OFPPF_100MB_HD   => '100mb-hd',
    OFPPF->OFPPF_100MB_FD   => '100mb-fd',
    OFPPF->OFPPF_1GB_HD     => '1gb-hd',
    OFPPF->OFPPF_1GB_FD     => '1gb-fd',
    OFPPF->OFPPF_10GB_FD    => '10gb-fd',
    OFPPF->OFPPF_COPPER     => 'copper',
    OFPPF->OFPPF_FIBER      => 'fiber',
    OFPPF->OFPPF_AUTONEG    => 'autoneg',
    OFPPF->OFPPF_PAUSE      => 'pause',
    OFPPF->OFPPF_PAUSE_ASYM => 'pause-asym',
};

use constant _OF_TMPL => {
    MSG_CLASS() => "OFMessagePB",
    MSG_TYPE_FIELD() => "ofType",
    MSG_FIELD_TO_TYPE() => sub { "OF" . substr($_[0], 2) . "PB" },
    MSG_SUBTYPES() => {
        OF->HELLO => {
            MSG_ST_FIELD() => "ofHello"
        },
        OF->ERROR => {
            MSG_ST_FIELD() => "ofError"
        },
        OF->ECHO_REQUEST => {
            MSG_ST_FIELD() => "ofEchoRequest"
        },
        OF->ECHO_REPLY => {
            MSG_ST_FIELD() => "ofEchoReply"
        },
        OF->VENDOR => {
            MSG_ST_FIELD() => "ofVendor"
        },
        OF->FEATURES_REQUEST => {
            MSG_ST_FIELD() => "ofFeaturesRequest"
        },
        OF->FEATURES_REPLY => {
            MSG_ST_FIELD() => "ofFeaturesReply"
        },
        OF->GET_CONFIG_REQUEST => {
            MSG_ST_FIELD() => "ofGetConfigRequest"
        },
        OF->GET_CONFIG_REPLY => {
            MSG_ST_FIELD() => "ofGetConfigReply"
        },
        OF->SET_CONFIG => {
            MSG_ST_FIELD() => "ofSetConfg"
        },
        OF->PACKET_IN => {
            MSG_ST_FIELD() => "ofPacketIn"
        },
        OF->FLOW_REMOVED => {
            MSG_ST_FIELD() => "ofFlowRemoved"
        },
        OF->PORT_STATUS => {
            MSG_ST_FIELD() => "ofPortStatus"
        },
        OF->PACKET_OUT => {
            MSG_ST_FIELD() => "ofPacketOut"
        },
        OF->FLOW_MOD => {
            MSG_ST_FIELD() => "ofFlowMod"
        },
        OF->PORT_MOD => {
            MSG_ST_FIELD() => "ofPortMod",
            MSG_ST_CONV() => {
                hardwareAddress => \&_dlAddrParse
            }
        },
        OF->STATS_REQUEST => {
            MSG_ST_FIELD() => "ofStatisticsRequest"
        },
        OF->STATS_REPLY => {
            MSG_ST_FIELD() => "ofStatisticsReply"
        },
        OF->BARRIER_REQUEST => {
            MSG_ST_FIELD() => "ofBarrierRequest"
        },
        OF->BARRIER_REPLY => {
            MSG_ST_FIELD() => "ofBarrierReply"
        },
        OF->QUEUE_GET_CONFIG_REQUEST => {
            MSG_ST_FIELD() => "ofQueueGetConfigRequest"
        },
        OF->QUEUE_GET_CONFIG_REPLY => {
            MSG_ST_FIELD() => "ofQueueGetConfigReply"
        },
        OF->SWITCH_STATUS => {
	    MSG_ST_FIELD() => "ofSwitchStatus"
        },
    }
};

sub isIPClassDorE {
    my ($ipV4Addr, $_mask) = parseIPv4(shift);

    return ($ipV4Addr & 0xe0000000) == 0xe0000000;
}

sub isLocalHostIP {
    my ($ipV4Addr, $_mask) = parseIPv4(shift);

    return ($ipV4Addr & 0xff000000) == 0x70000000;
}

sub isMACBroadcast {
    my $mac = shift;

    return ($mac & 0x010000000000);
}

sub isValidHostIP {
    my ($ipV4Addr, $_mask) = parseIPv4(shift);

    # Valid if not 0, not local (127/8), and not class D or E (224/3)
    my $isValid = ($ipV4Addr && ! isLocalHostIP($ipV4Addr) && ! isIPClassDorE($ipV4Addr)) or do {
	debugLog(uint32ToIPv4($ipV4Addr) . " is not a valid host IPv4 address");
    };
    return $isValid;
}

sub isValidHostMAC {
    my $mac = shift;

    # Valid if not 0 and not broadcast
    my $isValid = ($mac && ! isMACBroadcast($mac)) or do {
	debugLog(uint64ToMac($mac) . " is not a valid host MAC address");
    };
    return $isValid;
}

sub isValidHostSwitchPort {
    my $port = shift;
    defined $port or return 0;

    my $isValid = ($port > 0 && $port <= OFPortPB->OFPP_MAX) or do {
	debugLog($port . " is not a valid host switch port");
    };
    return $isValid;
}

sub newOFMessage {
    return newMessage(_OF_TMPL, @_);
}

sub swPortAddrToString {
    my $addr = shift;

    defined $addr or return "<undef>";
    return uint64ToMac($addr);
}

sub swPortConfigToString {
    return _swPortBitsToString(_OFPPC_NAME, @_);
}

sub swPortFeaturesToString {
    return _swPortBitsToString(_OFPPF_NAME, @_);
}

sub swPortNumberToString {
    my $port = shift;

    defined $port or return "<undef>";
    my $name = _OFPP_NAME->{$port} || "$port";
    return $name;
}

sub swPortStateToString {
    return _swPortBitsToString(_OFPPS_NAME, @_);
}

sub swPortToString {
    my $ofPort = shift or return "<undef>";

    my $str = "";
    $str .= swPortNumberToString($ofPort->portNumber);
    $str .= " (";
    $str .= "hwAddr=" . swPortAddrToString($ofPort->hardwareAddress);
    $str .= ", ";
    my $name = $ofPort->name || "<undef>";
    $str .= "name=" . $name;
    $str .= ", ";
    my $config = $ofPort->config || 0;
    $str .= "config=" . _intAsHex($config);
    $str .= "[" . swPortConfigToString($config) . "]" if $config;
    $str .= ", ";
    my $state = $ofPort->state || 0;
    $str .= "state=" . _intAsHex($state);
    $str .= "[" . swPortStateToString($state) . "]" if $state;
    $str .= ", ";
    my $current = $ofPort->currentFeatures || 0;
    $str .= "current=" . _intAsHex($current);
    $str .= "[" . swPortFeaturesToString($current) . "]" if $current;
    $str .= ", ";
    my $advertised = $ofPort->advertisedFeatures || 0;
    $str .= "advertised=" . _intAsHex($advertised);
    $str .= "[" . swPortFeaturesToString($advertised) . "]" if $advertised;
    $str .= ", ";
    my $supported = $ofPort->supportedFeatures;
    $str .= "supported=" . _intAsHex($supported);
    $str .= "[" . swPortFeaturesToString($supported) . "]" if $supported;
    $str .= ", ";
    my $peer = $ofPort->peerFeatures;
    $str .= "peer=" . _intAsHex($peer);
    $str .= "[" . swPortFeaturesToString($peer) . "]" if $peer;
    $str .= ")";
    return $str;
}

sub _intAsHex {
    return sprintf("0x%lx", shift);
}

sub _byNumber { $a <=> $b }

sub _dlAddrParse {
    return macToUint64(shift);
}

sub _swPortBitsToString {
    my $nameMap = shift;
    my $bits = shift;

    defined $bits or return "<undef>";
    my $str = "";
    for my $bit (sort _byNumber keys %$nameMap) {
	next unless ($bits & $bit);
	$str .= ", " if $str;
	$str .= $nameMap->{$bit};
    }
    return $str;
}


1;
