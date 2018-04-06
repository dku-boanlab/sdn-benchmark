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

package OpenFlow::NBAPI::Util::OFMatch;

BEGIN{
    our $VERSION = "0.1";
}

use threads::shared;
use strict;

use base qw(Exporter);

use Carp;
use Scalar::Util qw(blessed);
use Socket;

use OpenFlow::NBAPI::LowLevel::PB::NBCtlServicesPB;
use OpenFlow::NBAPI::LowLevel::PB::SBOFMatchesPB;
use OpenFlow::NBAPI::Util::Conversion qw(:all);
use OpenFlow::NBAPI::Util::OFMessage qw(:all);
use OpenFlow::NBAPI::Util::Value qw(:all);

our @EXPORT_CONSTANTS = qw(
    ARP_REQUEST
    ARP_REPLY
    DL_TYPE_IPV4
    DL_TYPE_ARP
    NW_PROTO_ICMP
    NW_PROTO_TCP
    NW_PROTO_UDP
    EQUAL
    NARROWER
    WIDER
    );
our @EXPORT_SUBS = qw(
    hashOFMatch
    isComparable
    isCondition
    isEqual
    isNarrower
    isWider
    matchCompare
    matches
    newIPMatch
    newNBOFMatch
    newOFMatch
    ofMatchToString
    );

our @EXPORT_OK = (@EXPORT_CONSTANTS, @EXPORT_SUBS);

our %EXPORT_TAGS = (
    all       => \@EXPORT_OK,
    constants => \@EXPORT_CONSTANTS,
    subs      => \@EXPORT_SUBS
    );

use constant ARP_REQUEST   => 1;
use constant ARP_REPLY     => 2;

use constant DL_TYPE_IPV4  => 0x800;
use constant DL_TYPE_ARP   => 0x806;

use constant NW_PROTO_ICMP => 1;
use constant NW_PROTO_TCP  => 6;
use constant NW_PROTO_UDP  => 17;

use constant EQUAL         =>  0;
use constant NARROWER      => -1;
use constant WIDER         =>  1;

use constant _OFWC   => "OFMatchPB::OFWildcardFlagsPB";
use constant _NW_SRC_SHIFT => 8;
use constant _NW_DST_SHIFT => 14;

use constant _NB_MATCH_FIELD => {
    datapathID => {
	compare => \&_nbCompareInt,
        order => 1
        },
    pInReason => {
	compare => \&_nbCompareInt,
        order => 2
        },
    sbOFMatch => {
	compare => \&_sbMatchCompare,
        order => 3
        },
};

use constant _SB_MATCH_FIELD => {
    inputPort => {
	wildcard => _OFWC->OFPFW_IN_PORT,
	parse    => \&_noParse,
	compare  => \&_compareInt,
        hash     => \&_hashInputPort,
	label    => 'inPort',
        toString => \&_swPortToString,
        },
    dataLayerSource => {
	wildcard => _OFWC->OFPFW_DL_SRC,
	parse    => \&_dlAddrParse,
	compare  => \&_compareInt,
	hash     => \&_hashDLSrc,
	label    => 'dlSrc',
        toString => \&_macToString,
        },
    dataLayerDestination => {
	wildcard => _OFWC->OFPFW_DL_DST,
	parse    => \&_dlAddrParse,
	compare  => \&_compareInt,
        hash     => \&_hashDLDst,
	label    => 'dlDst',
        toString => \&_macToString,
        },
    dataLayerVirtualLAN => {
	wildcard => _OFWC->OFPFW_DL_VLAN,
	parse    => \&_noParse,
	compare  => \&_compareInt,
        hash     => \&_hashDLVLAN,
	label    => 'dlVLAN',
        toString => \&_vlanToString,
        },
    dataLayerVirtualLANPriorityCodePoint => {
	wildcard => _OFWC->OFPFW_DL_VLAN_PCP,
	parse    => \&_noParse,
	compare  => \&_compareInt,
        hash     => \&_hashDLVLANPCP,
	label    => 'dlVLANPCP',
        toString => \&_vlanPCPToString,
        },
    dataLayerType => {
	wildcard => _OFWC->OFPFW_DL_TYPE,
	parse    => \&_noParse,
	compare  => \&_compareInt,
        hash     => \&_hashDLType,
	label    => 'dlType',
        toString => \&_dlTypeToString,
        },
    networkTypeOfService => {
	wildcard => _OFWC->OFPFW_NW_TOS,
	parse    => \&_noParse,
	compare  => \&_compareInt,
        hash     => \&_hashNWTOS,
	label    => 'nwTOS',
        toString => \&_tosToString,
        },
    networkProtocol => {
	wildcard => _OFWC->OFPFW_NW_PROTO,
	parse    => \&_nwProtoParse,
	compare  => \&_compareInt,
        hash     => \&_hashNWProto,
	label    => 'nwProto',
        toString => \&_protoToString,
        },
    networkSource => {
	wildcard => _NW_SRC_SHIFT(),
	mask => _OFWC->OFPFW_NW_SRC_MASK,
	parse    => \&_nwAddrParse,
	compare  => \&_compareNWAddr,
        hash     => \&_hashNWSrc,
	label    => 'nwSrc',
        toString => \&_ipV4ToString,
        },
    networkDestination => {
	wildcard => _NW_DST_SHIFT(),
	mask => _OFWC->OFPFW_NW_DST_MASK,
	parse    => \&_nwAddrParse,
	compare  => \&_compareNWAddr,
        hash     => \&_hashNWDst,
	label    => 'nwDst',
        toString => \&_ipV4ToString,
        },
    transportSource => {
	wildcard => _OFWC->OFPFW_TP_SRC,
	parse    => \&_noParse,
	compare  => \&_compareInt,
        hash     => \&_hashTPSrc,
	label    => 'tpSrc',
        toString => \&_tpToString,
        },
    transportDestination => {
	wildcard => _OFWC->OFPFW_TP_DST,
	parse    => \&_noParse,
	compare  => \&_compareInt,
        hash     => \&_hashTPDst,
	label    => 'tpDst',
        toString => \&_tpToString,
        },
};

use constant _STRING_FIELDS => qw(
    inputPort
    dataLayerType
    dataLayerSource
    dataLayerDestination
    networkProtocol
    networkSource
    networkDestination
    transportSource
    transportDestination
);

use constant _DLTYPE_NAME => {
    DL_TYPE_ARP()  => 'arp',
    DL_TYPE_IPV4() => 'ipv4',
};

use constant _PROTO_NAME => {
    NW_PROTO_ICMP() => 'icmp',
    NW_PROTO_TCP()  => 'tcp',
    NW_PROTO_UDP()  => 'udp',
};

sub hashOFMatch {
    my $ofMatch = shift or return 0;

    my $hashSum = 0;
    for my $fieldName (keys %{_SB_MATCH_FIELD()}) {
	my $hashSub = _SB_MATCH_FIELD->{$fieldName}->{'hash'};
	$hashSum += &$hashSub($ofMatch);
    }
    return $hashSum % 2147483647;
}

sub isComparable {
    return defined(shift);
}

sub isCondition {
    my $value = shift;
    my $condition = shift;

    return (defined($value) && $value == $condition);
}

sub isEqual {
    return isCondition(shift, EQUAL);
}

sub isNarrower {
    return isCondition(shift, NARROWER);
}

sub isWider {
    return isCondition(shift, WIDER);
}

# Compares two OFMatch or two NBOFMatch structures.
# Returns
#   -1 (NARROWER) if first narrower (more specific) than second
#    0 (EQUAL)    if first equal to second
#    1 (WIDER)    if first wider (more general) than second
#    undef if the two are incomparable
sub matchCompare {
    my $match1 = shift or return undef;
    my $match2 = shift or return undef;
    my $strict = shift || 0;

    return undef unless blessed $match1 && blessed $match2;
    return _nbMatchCompare($match1, $match2, $strict) if $match1->isa("NBOFMatchPB") && $match2->isa("NBOFMatchPB");
    return _sbMatchCompare($match1, $match2, $strict) if $match1->isa("OFMatchPB") && $match2->isa("OFMatchPB");
    return undef;
}

sub matches {
    my $match1 = shift;
    my $match2 = shift;
    my $strict = shift || 0;

    return defined(matchCompare($match1, $match2, $strict));
}

sub newIPMatch {
    my $fields = shift || {};

    $fields->{dataLayerType} = DL_TYPE_IPV4;
    return newOFMatch($fields);
}

sub newNBOFMatch {
    my $ofMatch = shift || newOFMatch();
    my $datapathID = shift;
    my $pInReason = shift;
    my $auxData = shift;

    unless (blessed($ofMatch) && $ofMatch->isa("OFMatchPB")) {
	if (ref($ofMatch) eq "HASH") {
	    $ofMatch = newOFMatch($ofMatch) or return undef;
	}
	else {
	    carp "newNBOFMatch: first argument must be OFMatchPB or hash reference";
	    return undef;
	}
    }

    if (defined $auxData) {
	(blessed $auxData && $auxData->isa("ValuePB")) or do {
	    $auxData = toValue($auxData);
	};
    }

    my $nbOFMatch = &share(NBOFMatchPB->new());
    $nbOFMatch->sbOFMatch($ofMatch);
    $nbOFMatch->datapathID($datapathID) if defined $datapathID;
    $nbOFMatch->pInReason($pInReason) if defined $pInReason;
    $nbOFMatch->auxData($auxData) if defined $auxData;

    return $nbOFMatch;
}

sub newOFMatch {
    my $fields = shift || {};

    my $ofMatch = &share(OFMatchPB->new());
    my $wildcards = _OFWC->OFPFW_ALL;
    foreach my $fieldName (keys %$fields) {
	defined(my $matchField = _SB_MATCH_FIELD->{$fieldName}) or do {
	    carp "unknown match field: $fieldName";
	    return undef;
	};
	my ($fieldValue, $wcFlag) = _parseField($matchField, $fields->{$fieldName});
	defined($fieldValue) or do {
	    carp "invalid or undefined value for $fieldName";
	    return undef;
	};
	$wildcards &= ~$wcFlag;
	$ofMatch->$fieldName(shared_clone($fieldValue));
    }
    if (! _isTransportLayerWild($wildcards)) {
	# Some transport-layer value is NOT wildcarded;
	# network protocol must be specified.
	defined($fields->{networkProtocol}) or do {
	    carp "Transport match requires network protocol match";
	    return undef;
	};
    }
    if (! _isNetworkLayerWild($wildcards)) {
	# Some network-layer value is NOT wildcarded; sanity check the data-link type
	my $dlType = $fields->{dataLayerType} || 0;
	carp "Data layer type $dlType is not IPv4 or ARP; rule may not match"
	    unless ($dlType == DL_TYPE_IPV4 || $dlType == DL_TYPE_ARP);
    }
    $ofMatch->wildcards(shared_clone($wildcards));
    return $ofMatch;
}

sub ofMatchToString {
    my $ofMatch = shift or return "<undef>";

    my $str = "";
    for my $field (_STRING_FIELDS) {
	my $fieldStr = _fieldToString($ofMatch, $field) or next;
	$str .= ", " if $str;
	$str .= $fieldStr;
    }
    return "{$str}";
}

sub _nbMatchCompare {
    my $nbOFMatch1 = shift or return undef;
    my $nbOFMatch2 = shift or return undef;
    my $strict = shift || 0;

    my $retval = EQUAL;
    my @fields = sort { _NB_MATCH_FIELD->{$a}->{order} <=> _NB_MATCH_FIELD->{$b}->{order} } keys %{_NB_MATCH_FIELD()};
    for my $fieldName (@fields) {
	my $matchField = _NB_MATCH_FIELD->{$fieldName};
	my $compare = $matchField->{compare};
	my $result = &$compare($nbOFMatch1->$fieldName(), $nbOFMatch2->$fieldName(), $strict);
	defined($result) or return undef;
	$retval == EQUAL and do {
	    # equal up to this point; continue with latest result
	    $retval = $result;
	    next;
	};
	return undef if ($retval * $result < 0); # wider -> narrower or vice-versa
    }
    return $retval;
}

sub _sbMatchCompare {
    my $ofMatch1 = shift or return undef;
    my $ofMatch2 = shift or return undef;
    my $strict = shift || 0;

    my $retval = EQUAL;
    keys %{_SB_MATCH_FIELD()}; # reset iterator
    while (my ($fieldName, $matchField) = each %{_SB_MATCH_FIELD()}) {
	my $compare = $matchField->{compare};
	my $wildcard = $matchField->{wildcard};
	my $mask = $matchField->{mask};
	my $result = &$compare($ofMatch1, $ofMatch2, $strict, $fieldName, $wildcard, $mask);
	defined($result) or return undef;
	$retval == EQUAL and do {
	    # equal up to this point; continue with latest result
	    $retval = $result;
	    next;
	};
	return undef if ($retval * $result < 0); # wider -> narrower or vice-versa
    }
    return $retval;
}

sub _nbCompareInt {
    my $val1 = shift;
    my $val2 = shift;

    if (defined $val1 && defined $val2) {
	return $val1 == $val2 ? EQUAL : undef;
    }
    else {
	return defined $val1 ? NARROWER : (defined $val2 ? WIDER : EQUAL);
    }
}

sub _compareInt {
    my $ofMatch1 = shift;
    my $ofMatch2 = shift;
    my $strict = shift;
    my $fieldName = shift;
    my $wildcard = shift;

    # Wildcard matching
    my $wc1 = $ofMatch1->wildcards & $wildcard;
    my $wc2 = $ofMatch2->wildcards & $wildcard;
    return ($strict ? undef : ($wc1 ? WIDER : NARROWER)) if ($wc1 != $wc2);
    return EQUAL if $wc1;

    # Value matching
    my $val1 = $ofMatch1->$fieldName();
    my $val2 = $ofMatch2->$fieldName();
    return defined $val1 && defined $val2 && $val1 == $val2 ? EQUAL : undef;
}

sub _compareNWAddr {
    my $ofMatch1 = shift;
    my $ofMatch2 = shift;
    my $strict = shift;
    my $fieldName = shift;
    my $wcShift = shift;
    my $wcMask = shift;

    # Wildcard matching; treat undefined values as wild
    my $wc1 = ($ofMatch1->wildcards & $wcMask) >> $wcShift;
    $wc1 = 32 unless ($wc1 < 32 && defined($ofMatch1->$fieldName()));
    my $wc2 = ($ofMatch2->wildcards & $wcMask) >> $wcShift;
    $wc2 = 32 unless ($wc2 < 32 && defined($ofMatch2->$fieldName()));
    return EQUAL if ($wc1 == 32 && $wc2 == 32);
    return undef if $strict && ($wc1 != $wc2);

    # Value matching
    my $wc = $wc1 > $wc2 ? $wc1 : $wc2;
    my $mask = (0xffffffff << $wc) & 0xffffffff;
    my $addr1 = ($ofMatch1->$fieldName() || 0) & $mask;
    my $addr2 = ($ofMatch2->$fieldName() || 0) & $mask;
    return undef if ($addr1 != $addr2);
    return ($wc1 == $wc2 ? EQUAL : ($wc1 > $wc2 ? WIDER : NARROWER));
}

sub _allSet {
    my $wc = shift;
    my $flags = shift;

    return (($wc & $flags) == $flags);
}

sub _nwAddrIgnore {
    my $wc = shift;
    my $addrMask = shift;
    my $addrShift = shift;

    return (($wc & $addrMask) >> $addrShift);
}

sub _nwSrcIgnore {
    my $wc = shift;

    return _nwAddrIgnore($wc, _OFWC->OFPFW_NW_SRC_MASK, _NW_SRC_SHIFT);
}

sub _nwDstIgnore {
    my $wc = shift;

    return _nwAddrIgnore($wc, _OFWC->OFPFW_NW_DST_MASK, _NW_DST_SHIFT);
}

sub _isNetworkLayerWild {
    my $wc = shift;

    return (_allSet($wc, _OFWC->OFPFW_NW_PROTO | _OFWC->OFPFW_NW_TOS) &&
	    _nwSrcIgnore($wc) >= 32 && _nwDstIgnore($wc) >= 32);
}

sub _isTransportLayerWild {
    my $wc = shift;

    return _allSet($wc, _OFWC->OFPFW_TP_SRC | _OFWC->OFPFW_TP_DST);
}

sub _parseField {
    my $matchField = shift;
    my $fieldValue = shift;

    my $parse = $matchField->{parse};
    return &$parse($fieldValue, $matchField->{wildcard});
}

sub _noParse {
    my $fieldValue = shift;
    my $wildcard = shift;

    return ($fieldValue, $wildcard);
}

sub _dlAddrParse {
    my $mac = shift;
    my $wildcard = shift;

    defined(my $addr = macToUint64($mac)) or return (undef, undef);
    return ($addr, $wildcard);
}

sub _nwProtoParse {
    my $protoSpec = shift;
    my $wildcard = shift;

    my $proto = $protoSpec;
    $proto = getprotobyname($protoSpec) if "$protoSpec" !~ /^\d+$/;
    $proto or return (undef, undef);
    return ($proto, $wildcard);
}

sub _nwAddrParse {
    my $addrSpec = shift;
    my $wcShift = shift;

    my ($addr, $mask) = parseIPv4($addrSpec);
    (defined $addr && defined $mask) or return (undef, undef);
    $mask = 32 - $mask; # mask has opposite interpretation for OFMatch
    $mask = 0 if $mask < 0;

    # n.b., $wildcard must specify the wildcard flags to be CLEARED
    my $wildcard = (0x3f - ($mask & 0x3f)) << $wcShift;

    return ($addr, $wildcard);
}

sub _hashInputPort {
    my $ofMatch = shift;

    return 0 if $ofMatch->wildcards & _OFWC->OFPFW_IN_PORT;
    my $value = $ofMatch->inputPort || 0;
    return $value;
}

sub _hashDLSrc {
    my $ofMatch = shift;

    return 0 if $ofMatch->wildcards & _OFWC->OFPFW_DL_SRC;
    my $value = $ofMatch->dataLayerSource || 0;
    return $value;
}

sub _hashDLDst {
    my $ofMatch = shift;

    return 0 if $ofMatch->wildcards & _OFWC->OFPFW_DL_DST;
    my $value = $ofMatch->dataLayerDestination || 0;
    return $value << 8;
}

sub _hashDLVLAN {
    my $ofMatch = shift;

    return 0;
}

sub _hashDLVLANPCP {
    my $ofMatch = shift;

    return 0;
}

sub _hashDLType {
    my $ofMatch = shift;

    return 0 if $ofMatch->wildcards & _OFWC->OFPFW_DL_TYPE;
    my $value = $ofMatch->dataLayerType || 0;
    return $value;
}

sub _hashNWTOS {
    my $ofMatch = shift;

    return 0;
}

sub _hashNWProto {
    my $ofMatch = shift;

    return 0 if $ofMatch->wildcards & _OFWC->OFPFW_NW_PROTO;
    my $value = $ofMatch->networkProtocol || 0;
    return $value;
}

sub _hashNWSrc {
    my $ofMatch = shift;

    my $wc = ($ofMatch->wildcards & _OFWC->OFPFW_NW_SRC_MASK) >> _NW_SRC_SHIFT;
    my $mask = (0xffffffff << $wc) & 0xffffffff;
    my $value = $ofMatch->networkSource || 0;
    return $value & $mask;
}

sub _hashNWDst {
    my $ofMatch = shift;

    my $wc = ($ofMatch->wildcards & _OFWC->OFPFW_NW_DST_MASK) >> _NW_DST_SHIFT;
    my $mask = (0xffffffff << $wc) & 0xffffffff;
    my $value = $ofMatch->networkDestination || 0;
    return ($value & $mask) << 16;
}

sub _hashTPSrc {
    my $ofMatch = shift;

    return 0 if $ofMatch->wildcards & _OFWC->OFPFW_TP_SRC;
    my $value = $ofMatch->transportSource || 0;
    return $value;
}

sub _hashTPDst {
    my $ofMatch = shift;

    return 0 if $ofMatch->wildcards & _OFWC->OFPFW_TP_DST;
    my $value = $ofMatch->transportDestination || 0;
    return $value << 16;
}

sub _fieldToString {
    my $ofMatch = shift;
    my $fieldName = shift;

    my $value = $ofMatch->$fieldName();
    defined $value or return "";

    my $matchField = _SB_MATCH_FIELD->{$fieldName};
    my $toString = $matchField->{toString};
    my $wildcard = $matchField->{wildcard};
    my $mask = $matchField->{mask};
    my $str;
    if (defined $mask) {
	# network address field; $wildcard is shift
	my $wc = ($ofMatch->wildcards & $mask) >> $wildcard;
	return "" unless ($wc < 32);
	$str = &$toString($ofMatch, $value, 32 - $wc);
    }
    else {
	# single-bit-wildcard field
	return "" if ($ofMatch->wildcards & $wildcard);
	$str = &$toString($ofMatch, $value);
    }
    my $label = $matchField->{label};
    return "$label=$str";
}

sub _swPortToString {
    my $ofMatch = shift;
    my $port = shift;

    return swPortNumberToString($port);
}

sub _macToString {
    my $ofMatch = shift;
    my $mac = shift;

    return uint64ToMac($mac);
}

sub _dlTypeToString {
    my $ofMatch = shift;
    my $dlType = shift;

    my $name = _DLTYPE_NAME->{$dlType} || "$dlType";
    return $name;
}

sub _vlanToString {
    my $ofMatch = shift;
    my $vlan = shift;

    return "$vlan";
}

sub _vlanPCPToString {
    my $ofMatch = shift;
    my $vlanPCP = shift;

    return "$vlanPCP";
}

sub _tosToString {
    my $ofMatch = shift;
    my $tos = shift;

    return "$tos";
}

sub _protoToString {
    my $ofMatch = shift;
    my $proto = shift;

    return "$proto" unless $ofMatch->dataLayerType == DL_TYPE_IPV4;

    my $name = _PROTO_NAME->{$proto} || "$proto";
    return $name;
}

sub _ipV4ToString {
    my $ofMatch = shift;
    my $ipV4Addr = shift;
    my $masksize = shift;

    my $str = uint32ToIPv4($ipV4Addr);
    $str .= "/$masksize" if $masksize < 32;
    return $str;
}

sub _tpToString {
    my $ofMatch = shift;
    my $tp = shift;

    return "$tp";
}


1;
