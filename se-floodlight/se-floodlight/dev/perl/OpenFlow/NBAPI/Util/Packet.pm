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

package OpenFlow::NBAPI::Util::Packet;

BEGIN{
    our $VERSION = "0.1";
}

use threads::shared;
use strict;

no warnings('portable');

use base qw(Exporter);

use Carp;
use Scalar::Util qw(blessed);
use Socket;

our @EXPORT_CONSTANTS = qw(
    ETH_ADDR_LEN
    ETH_HDR_LEN
    ETH_802_1Q_VLAN_TAG_SIZE
    ETH_802_1ad_VLAN_TAG_SIZE
    ETH_DL_TYPE_IPV4
    ETH_DL_TYPE_ARG
    ETH_ADDR_BCAST
    ETH_ADDR_BCAST_BIT
    ICMP_UNREACHABLE
    IPV4_ADDR_LEN
    IPV4_NW_PROTO_ICMP
    IPV4_NW_PROTO_TCP
    IPV4_NW_PROTO_UDP
    IPV4_MIN_HDR_LEN
    TCP_MIN_HDR_LEN
    TCP_PFX_HDR_LEN
    TCP_FLAG_MASK
    TCP_FLAG_FIN
    TCP_FLAG_SYN
    TCP_FLAG_RST
    TCP_FLAG_PSH
    TCP_FLAG_ACK
    TCP_FLAG_URG
    );
our @EXPORT_SUBS = qw(
    bytesToPacket
    computeChecksum
    genICMPUnreachable
    genTCPReset
    getIPv4DataLen
    getIPv4DataOff
    getIPv4HdrLen
    getIPv4HdrOff
    getPacketByte
    getPacketInt
    getPacketShort
    getReflectionIPv4Bytes
    getTCPDataLen
    getTCPDstPort
    getTCPHdrOff
    getTCPHdrPfxBytes
    getTCPFlags
    getTCPSrcPort
    isTCPReset
    packetToBytes
    putPacketByte
    putPacketInt
    putPacketShort
    );

our @EXPORT_OK = (@EXPORT_CONSTANTS, @EXPORT_SUBS);

our %EXPORT_TAGS = (
    all       => \@EXPORT_OK,
    constants => \@EXPORT_CONSTANTS,
    subs      => \@EXPORT_SUBS
    );

use constant ETH_ADDR_LEN              => 6;
use constant ETH_HDR_LEN               => (ETH_ADDR_LEN * 2) + 2;
use constant ETH_802_1Q_VLAN_TAG_SIZE  => 4;
use constant ETH_802_1ad_VLAN_TAG_SIZE => 4;
use constant ETH_DL_TYPE_IPV4          => 0x800;
use constant ETH_DL_TYPE_ARP           => 0x806;
use constant ETH_ADDR_BCAST            => 0xffffffffffff;
use constant ETH_ADDR_BCAST_BIT        => 0x010000000000;

use constant IPV4_ADDR_LEN       => 4;
use constant IPV4_NW_PROTO_ICMP  => 1;
use constant IPV4_NW_PROTO_TCP   => 6;
use constant IPV4_NW_PROTO_UDP   => 17;
use constant IPV4_MIN_HDR_LEN    => 20;

use constant TCP_MIN_HDR_LEN     => 20;
use constant TCP_PFX_HDR_LEN     => 12;

use constant TCP_FLAG_MASK       => 0x3f;
use constant TCP_FLAG_FIN        => 0x01;
use constant TCP_FLAG_SYN        => 0x02;
use constant TCP_FLAG_RST        => 0x04;
use constant TCP_FLAG_PSH        => 0x08;
use constant TCP_FLAG_ACK        => 0x10;
use constant TCP_FLAG_URG        => 0x20;

use constant ICMP_UNR_ADD        => 8;
use constant ICMP_PKT_BASE       => 8;
use constant ICMP_UNR_LEN        => ICMP_PKT_BASE + IPV4_MIN_HDR_LEN + ICMP_UNR_ADD;
use constant ICMP_MIN_PKT_LEN    => IPV4_MIN_HDR_LEN + ICMP_PKT_BASE;
use constant ICMP_UNREACHABLE    => 3;

sub bytesToPacket {
    my $bytes = shift;

    if (ref($bytes) eq "ARRAY") {
	return pack("C*", @$bytes);
    }
    else {
	return $bytes;
    }
}

sub computeChecksum {
    my $bytes = shift or return undef;
    my $off = shift;
    my $len = shift;
    my $pfx = shift;

    my $sum = 0;
    if ($pfx) {
	my $pfxLen = scalar @$pfx;
	for (my $i = 0; $i < $pfxLen; $i++) {
	    $sum += ($pfx->[$i] & 0xff) << (($i & 1) == 0 ? 8 : 0);
	}
    }
    for (my $i = 0; $i < $len; $i++) {
	$sum += ($bytes->[$off + $i] & 0xff) << (($i & 1) == 0 ? 8 : 0);
    }
    $sum = ($sum & 0xffff) + ($sum >> 16);
    return (~ $sum) & 0xffff;
}

sub genICMPUnreachable {
    my $pkt = packetToBytes(shift) or return undef;
    my $unrCode = shift;

    my $pktLen = scalar @$pkt;
    my $ipHdrOff = getIPv4HdrOff($pkt);
    my $ipHdrLen = getIPv4HdrLen($pkt, $ipHdrOff);
    my $ipSend = $ipHdrLen + ICMP_UNR_ADD;
    my $ipEnd = $ipHdrOff + $ipSend;
    if ($ipHdrLen < 1 || $ipEnd > $pktLen) {
	carp "insufficient packet data for ICMP response";
	return undef;
    }
    my $icmpBase = ICMP_PKT_BASE + $ipSend;
    my $icmpLen = IPV4_MIN_HDR_LEN + $icmpBase;
    my $icmpPkt = getReflectionIPv4Bytes($pkt, $ipHdrOff, $icmpLen, IPV4_NW_PROTO_ICMP);
    my $icmpOff = getIPv4HdrOff($icmpPkt) or do {
	carp "ICMP offset calculation failed";
	return undef;
    };

    # Verify the IP header checksum
    _verifyIPChecksum($icmpPkt, $icmpOff) or do {
	carp "failed to verify IP header checksum for ICMP packet";
	return undef;
    };

    $icmpOff += IPV4_MIN_HDR_LEN;
    my $off = $icmpOff;
    $icmpPkt->[$off++] = ICMP_UNREACHABLE;
    $icmpPkt->[$off++] = $unrCode & 0xff;
    my $chksumOff = $off;
    $icmpPkt->[$off++] = 0;
    $icmpPkt->[$off++] = 0;

    $icmpPkt->[$off++] = 0;
    $icmpPkt->[$off++] = 0;
    $icmpPkt->[$off++] = 0;
    $icmpPkt->[$off++] = 0;

    # Copy IP header (with options) plus ICMP_UNR_ADD bytes
    # of IP data from the original packet
    for (my $i = 0; $i < $ipSend; $i++) {
	$icmpPkt->[$off++] = $pkt->[$ipHdrOff + $i];
    }

    # Compute the ICMP checksum
    my $icmpChksum = computeChecksum($icmpPkt, $icmpOff, $icmpBase);
    $icmpPkt->[$chksumOff] = ($icmpChksum >> 8) & 0xff;
    $icmpPkt->[$chksumOff + 1] = $icmpChksum & 0xff;

    # Verify the ICMP checksum
    _verifyChecksum($icmpPkt, $icmpOff, $icmpBase) or do {
	carp "failed to verify ICMP checksum";
	return undef;
    };

    return bytesToPacket($icmpPkt);
}

sub genTCPReset {
    my $pkt = packetToBytes(shift) or return undef;

    my $pktLen = scalar @$pkt;
    my $ipHdrOff = getIPv4HdrOff($pkt);
    my $ipHdrLen = getIPv4HdrLen($pkt, $ipHdrOff);
    my $tcpOff = $ipHdrOff + $ipHdrLen;
    my $tcpEnd = $tcpOff + TCP_MIN_HDR_LEN;

    if ($ipHdrLen < 1 || $tcpEnd > $pktLen) {
	carp "insufficient packet data for TCP reset response";
	return undef;
    }

    my $tcprLen = IPV4_MIN_HDR_LEN + TCP_MIN_HDR_LEN;
    my $tcprPkt = getReflectionIPv4Bytes($pkt, $ipHdrOff, $tcprLen, IPV4_NW_PROTO_TCP);
    my $tcprOff = getIPv4HdrOff($tcprPkt) or do {
	carp "TCP reset offset calculation failed";
	return undef;
    };

    # Verify the IP header checksum
    _verifyIPChecksum($tcprPkt, $tcprOff) or do {
	carp "failed to verify IP header checksum for TCP reset packet";
	return undef;
    };

    my $tcprPfx = getTCPHdrPfxBytes($tcprPkt, $tcprOff);
    $tcprOff += IPV4_MIN_HDR_LEN;

    # Fill in the minimal TCP header (no data)
    my $off = $tcprOff;
    my $srcPort = getTCPSrcPort($pkt, $tcpOff);
    my $dstPort = getTCPDstPort($pkt, $tcpOff);
    my $flags = getTCPFlags($tcprPkt, $tcprOff);
    my $tcprFlags = TCP_FLAG_RST;

    # Swap src and dst ports in return packet
    $tcprPkt->[$off++] = ($dstPort >> 8) & 0xff;
    $tcprPkt->[$off++] = $dstPort & 0xff;
    $tcprPkt->[$off++] = ($srcPort >> 8) & 0xff;
    $tcprPkt->[$off++] = $srcPort & 0xff;

    if (($flags & TCP_FLAG_ACK) != 0) {
	# Sequence number comes from the ACK field of the original packet
	my $ackOff = $tcpOff + 8;
	for (my $i = 0; $i < 4; $i++) {
	    $tcprPkt->[$off++] = $pkt->[$ackOff++];
	}
	for (my $i = 0; $i < 4; $i++) {
	    $tcprPkt->[$off++] = 0;
	}
    }
    else {
	# Otherwise, sequence number is zero and the ACK field is set to the sum
	# of the sequence number and segment length of the incoming segment
	my $seq = getPacketInt($pkt, $tcpOff + 4);
	for (my $i = 0; $i < 4; $i++) {
	    $tcprPkt->[$off++] = 0;
	}
	if (($flags & TCP_FLAG_SYN) != 0) {
	    # SYN flag set; response is ISN plus one
	    $seq++;
	}
	else {
	    # Otherwise the response is sequence plug segment length
	    $seq += getTCPDataLen($pkt, $ipHdrOff);
	}
	# Encode the ACK field
	putPacketInt($seq + 1, $tcprPkt, $off);
	$off += 4;
	$tcprFlags |= TCP_FLAG_ACK;
    }

    # Data offset (TCP header length in 32-bit words)
    $tcprPkt->[$off++] = TCP_MIN_HDR_LEN << 2; # (same as >> 2, followed by << 4)
    $tcprPkt->[$off++] = $tcprFlags;
    $tcprPkt->[$off++] = 0; # window
    $tcprPkt->[$off++] = 0;
    my $chksumOff = $off;
    $tcprPkt->[$off++] = 0; # checksum
    $tcprPkt->[$off++] = 0;
    $tcprPkt->[$off++] = 0; # urgent pointer
    $tcprPkt->[$off++] = 0;

    # Compute the TCP checksum
    my $tcpChksum = computeChecksum($tcprPkt, $tcprOff, TCP_MIN_HDR_LEN, $tcprPfx);
    $tcprPkt->[$chksumOff] = ($tcpChksum >> 8) & 0xff;
    $tcprPkt->[$chksumOff + 1] = $tcpChksum & 0xff;

    # Verify the checksum
    _verifyTCPChecksum($tcprPkt, $tcprOff, $tcprPfx) or do {
	carp "failed to verify TCP checksum in TCP reset";
	return undef;
    };

    return bytesToPacket($tcprPkt);
}

sub getIPv4DataLen {
    my $pkt = packetToBytes(shift) or return undef;
    my $hdrOff = shift || getIPv4HdrOff($pkt);
    $hdrOff or return undef;
    my $limit = shift;

    my $hdrLen = getIPv4HdrLen($pkt, $hdrOff) or return undef;
    my $pktLen = (scalar @$pkt) - ($hdrOff + $hdrLen);
    my $totalLen = getPacketShort($pkt, $hdrOff + 2);
    my $limitLen = $limit ? $pktLen : $totalLen;
    if (($pktLen < $totalLen) && ($limitLen > $hdrLen)) {
	return $limitLen - $hdrLen;
    }
    return undef;
}

sub getIPv4DataOff {
    my $pkt = packetToBytes(shift) or return undef;
    my $hdrOff = shift || getIPv4HdrOff($pkt);
    $hdrOff or return undef;

    my $hdrLen = getIPv4HdrLen($pkt) or return undef;
    return $hdrOff + $hdrLen;
}

sub getIPv4HdrLen {
    my $pkt = packetToBytes(shift) or return undef;
    my $hdrOff = shift || getIPv4HdrOff($pkt);
    $hdrOff or return undef;

    my $len = scalar @$pkt;
    if ($len > $hdrOff && ($pkt->[$hdrOff] & 0xf0) == 0x40) {
	my $hdrLen = ($pkt->[$hdrOff] & 0xf) << 2;
	return $hdrLen if $hdrLen >= IPV4_MIN_HDR_LEN;
    }
    return undef;
}

sub getIPv4HdrOff {
    my $pkt = packetToBytes(shift) or return undef;

    my $len = scalar @$pkt;
    return undef unless $len > ETH_HDR_LEN;

    my $off = ETH_HDR_LEN - 2;
    # Skip IEEE 802.1ad (doubled) VLAN tags
    while ($pkt->[$off] == 0x88 && $pkt->[$off + 1] == 0xa8 && ($off + ETH_802_1ad_VLAN_TAG_SIZE) < $len) {
	$off += ETH_802_1ad_VLAN_TAG_SIZE;
    }
    # Skip IEEE 802.1Q VLAN tags
    while ($pkt->[$off] == 0x81 && $pkt->[$off + 1] == 0x00 && ($off + ETH_802_1Q_VLAN_TAG_SIZE) < $len) {
	$off += ETH_802_1Q_VLAN_TAG_SIZE;
    }
    # Check ethertype is IPv4
    if ($pkt->[$off] == 0x08 && $pkt->[$off + 1] == 0x00 && ($off + IPV4_MIN_HDR_LEN) <= $len) {
	$off += 2;
	return $off if ($pkt->[$off] & 0xf0) == 0x40;
    }
    return undef;
}

sub getPacketByte {
    my $pkt = packetToBytes(shift) or return undef;
    my $off = shift;
    $off < scalar @$pkt or return undef;

    return $pkt->[$off];
}

sub getPacketInt {
    my $pkt = packetToBytes(shift) or return undef;
    my $off = shift;
    $off < (scalar @$pkt) - 3 or return undef;

    return ($pkt->[$off] << 24) | ($pkt->[$off + 1] << 16) | ($pkt->[$off + 2] << 8) | $pkt->[$off + 3];
}

sub getPacketShort {
    my $pkt = packetToBytes(shift) or return undef;
    my $off = shift;
    $off < (scalar @$pkt) - 1 or return undef;

    return ($pkt->[$off] << 8) | $pkt->[$off + 1];
}

sub getReflectionIPv4Bytes {
    my $pkt = packetToBytes(shift) or return undef;
    my $ipHdrOff = shift || getIPv4HdrOff($pkt);
    my $reflIPLen = shift;
    my $ipProto = shift;

    my @bytes = (0) x ($reflIPLen + ETH_HDR_LEN);
    my $bytesRef = \@bytes;

    # Transfer and swap ethernet addresses
    for (my $i = 0; $i < ETH_ADDR_LEN; $i++) {
	my $iSwap = ETH_ADDR_LEN + $i;
	$bytes[$i] = $pkt->[$iSwap];
	$bytes[$iSwap] = $pkt->[$i];
    }

    # TODO: handle VLAN tags

    # Set ethernet type
    my $off = ETH_ADDR_LEN << 1;
    $bytes[$off++] = 0x08;
    $bytes[$off++] = 0x00;

    # Set IP header
    my $reflIPHdrOff = $off;
    $bytes[$off++] = 0x45; # version, IHL
    $bytes[$off++] = 0; # DSCP, ECN
    $bytes[$off++] = ($reflIPLen >> 8) & 0xff; # IP packet length
    $bytes[$off++] = $reflIPLen & 0xff;
    $bytes[$off++] = 0; # identification, flags, fragment offset
    $bytes[$off++] = 0;
    $bytes[$off++] = 0;
    $bytes[$off++] = 0;
    $bytes[$off++] = 0xff; # TTL
    $bytes[$off++] = $ipProto & 0xff; # protocol
    my $chksumOff = $off;
    $bytes[$off++] = 0; # header checksum
    $bytes[$off++] = 0;

    # Transfer and swap IP addresses
    my $addrOff = $ipHdrOff + 12;
    for (my $i = 0; $i < IPV4_ADDR_LEN; $i++) {
	my $iSwap = IPV4_ADDR_LEN + $i;
	$bytes[$off + $i] = $pkt->[$addrOff + $iSwap];
	$bytes[$off + $iSwap] = $pkt->[$addrOff + $i];
    }

    # Compute IP header checksum
    my $chksum = computeChecksum($bytesRef, $reflIPHdrOff, IPV4_MIN_HDR_LEN);
    $bytes[$chksumOff] = ($chksum >> 8) & 0xff;
    $bytes[$chksumOff + 1] = $chksum & 0xff;

    return $bytesRef;
}

sub getTCPDataLen {
    my $pkt = packetToBytes(shift) or return undef;
    my $hdrOff = shift || getIPv4HdrOff($pkt);
    $hdrOff or return undef;

    my $tcpOff = getIPv4DataOff($pkt, $hdrOff) or return undef;
    my $dataLen = getIPv4DataLen($pkt, $hdrOff) or return undef;
    if ($dataLen > 12) {
	my $tcpHdrLen = ($pkt->[$tcpOff + 12] >> 2) & 0x3c;
	if ($tcpHdrLen >= TCP_MIN_HDR_LEN && $tcpHdrLen <= $dataLen) {
	    return $dataLen - $tcpHdrLen;
	}
    }
    return undef;
}

sub getTCPDstPort {
    my $pkt = packetToBytes(shift) or return undef;
    my $tcpHdrOff = shift || getTCPHdrOff($pkt);
    $tcpHdrOff or return undef;

    scalar @$pkt >= $tcpHdrOff + 4 or return undef;
    return getPacketShort($pkt, $tcpHdrOff + 2);
}

sub getTCPHdrOff {
    my $pkt = packetToBytes(shift) or return undef;
    my $ipHdrOff = shift || getIPv4HdrOff($pkt);
    $ipHdrOff or return undef;

    my $ipHdrLen = getIPv4HdrLen($pkt, $ipHdrOff);
    return $ipHdrOff + $ipHdrLen;
}

sub getTCPHdrPfxBytes {
    my $pkt = packetToBytes(shift) or return undef;
    my $hdrOff = shift || getIPv4HdrOff($pkt);
    $hdrOff or return undef;

    my @bytes = (0) x TCP_PFX_HDR_LEN;
    my $addrLen = IPV4_ADDR_LEN << 1;
    my $addrOff = $hdrOff + 12;
    my $tcpLen = (scalar @$pkt) - ($hdrOff + getIPv4HdrLen($pkt, $hdrOff));
    for (my $i = 0; $i < $addrLen; $i++) {
	$bytes[$i] = $pkt->[$addrOff + $i];
    }
    $bytes[$addrLen++] = 0;
    $bytes[$addrLen++] = IPV4_NW_PROTO_TCP;
    $bytes[$addrLen++] = ($tcpLen >> 8) & 0xff;
    $bytes[$addrLen] = $tcpLen & 0xff;
    return \@bytes;
}

sub getTCPFlags {
    my $pkt = packetToBytes(shift) or return undef;
    my $tcpOff = shift || getIPv4DataOff($pkt);
    $tcpOff or return undef;

    my $flagIdx = $tcpOff + 12;
    if ($flagIdx < scalar @$pkt) {
	return $pkt->[$flagIdx] & TCP_FLAG_MASK;
    }
    return undef;
}

sub getTCPSrcPort {
    my $pkt = packetToBytes(shift) or return undef;
    my $tcpHdrOff = shift || getTCPHdrOff($pkt);
    $tcpHdrOff or return undef;

    scalar @$pkt >= $tcpHdrOff + 4 or return undef;
    return getPacketShort($pkt, $tcpHdrOff);
}

sub isTCPReset {
    my $pkt = packetToBytes(shift) or return undef;
    my $tcpOff = shift || getIPv4DataOff($pkt);
    $tcpOff or return undef;

    my $flags = getTCPFlags($pkt, $tcpOff);
    return ($flags & TCP_FLAG_RST) == TCP_FLAG_RST;
}

sub packetToBytes {
    my $pkt = shift or return undef;

    if (ref($pkt) eq "ARRAY") {
	return $pkt;
    }
    elsif (blessed $pkt && $pkt->isa("OFPacketInPB")) {
	$pkt = $pkt->packetData;
    }
    my @bytes = unpack("C*", $pkt);
    return \@bytes;
}

sub putPacketByte {
    my $byte = shift;
    my $pkt = packetToBytes(shift) or return undef;
    my $off = shift;
    $off < scalar @$pkt or return undef;

    $pkt->[$off] = $byte & 0xff;
}

sub putPacketInt {
    my $int = shift;
    my $pkt = packetToBytes(shift) or return undef;
    my $off = shift;
    $off < (scalar @$pkt) - 3 or return undef;

    $pkt->[$off] = ($int >> 24) & 0xff;
    $pkt->[$off + 1] = ($int >> 16) & 0xff;
    $pkt->[$off + 2] = ($int >> 8) & 0xff;
    $pkt->[$off + 3] = $int & 0xff;
}

sub putPacketShort {
    my $short = shift;
    my $pkt = packetToBytes(shift) or return undef;
    my $off = shift;
    $off < (scalar @$pkt) - 1 or return undef;

    $pkt->[$off] = ($short >> 8) & 0xff;
    $pkt->[$off + 1] = $short & 0xff;
}

sub _verifyChecksum {
    my $data = shift;
    my $off = shift;
    my $len = shift;
    my $pfx = shift;

    return computeChecksum($data, $off, $len, $pfx) == 0;
}

sub _verifyIPChecksum {
    my $data = shift;
    my $off = shift;

    return _verifyChecksum($data, $off, IPV4_MIN_HDR_LEN);
}

sub _verifyTCPChecksum {
    my $data = shift;
    my $off = shift;
    my $pfx = shift;

    return _verifyChecksum($data, $off, TCP_MIN_HDR_LEN, $pfx);
}

1;
