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

package OpenFlow::NBAPI::ControllerContext;

BEGIN {
    our $VERSION = "0.1";
}

use threads;
use threads::shared;

use base qw(OpenFlow::NBAPI::Base::Shared Exporter);
use fields qw(
    addrCacheTTL arpSenderIP arpSenderMAC
    autoRestore clientID contextID host port status
    xidCacheSize xidCacheTTL
    _addrNotifyMap _arpRegMap _arpTimeMap _clientMsgQueue
    _cookieMSB _cookieLSB _cookieMutex _ctlCapMap _ctlExtMap
    _hostTrackActual _hostTrackCB _hostTrackMatch _hostTrackMutex _hostTrackTarget
    _ipAddrCache _macAddrCache _macReqTimeMap
    _matchFilters _noopCB _passThruCB _pbIn
    _protoEngine _receiveMessageTypes _requests
    _socketFD _spcnReplyCB _spcnRequestMap
    _switchStatusCallbacks _switchStatusLockRef _switchStatusMap
    _switchTrackActual _switchTrackTarget _welcomeRef _xidCache
);
use strict;

our @EXPORT_CONST = qw(
    CTX_VERSION_NB
    CTX_VERSION_SB
    CTX_STATUS
    EXT_CTL_SUPPORT
    HOSTS_NONE
    HOSTS_MATCHING
    HOSTS_ALL
    SWITCH_NONE
    SWITCH_SWITCH
    SWITCH_PORT
);
our @EXPORT_OK = (@EXPORT_CONST);
our %EXPORT_TAGS = (
    all => \@EXPORT_OK,
    constants => \@EXPORT_CONST,
    );

use constant CTX_VERSION_NB  => 1;
use constant CTX_VERSION_SB  => 1;
use constant CTX_STATUS      => __PACKAGE__ . "::Status";
use constant EXT_CTL_SUPPORT  => "ControllerSupport";

use constant HOSTS_NONE      => 0;
use constant HOSTS_MATCHING  => 1;
use constant HOSTS_ALL       => 2;
use constant HOSTS_TRACK     => {
    HOSTS_NONE()     => "none",
    HOSTS_MATCHING() => "filtered",
    HOSTS_ALL()      => "unfiltered"
};

use constant SWITCH_NONE     => 0;
use constant SWITCH_SWITCH   => 1;
use constant SWITCH_PORT     => 2;
use constant SWITCH_TRACK    => {
    SWITCH_NONE()   => "none",
    SWITCH_SWITCH() => "switch add/remove",
    SWITCH_PORT()   => "port change"
};

use Carp;
use IO::Socket::INET;
use Scalar::Util qw(blessed looks_like_number);

use OpenFlow::NBAPI::AddrInfo;
use OpenFlow::NBAPI::MessageEvent;
use OpenFlow::NBAPI::PBQueue;
use OpenFlow::NBAPI::LowLevel::NBOFMatchList;
use OpenFlow::NBAPI::LowLevel::ProtocolEngine qw(:all);
use OpenFlow::NBAPI::LowLevel::RefList;
use OpenFlow::NBAPI::LowLevel::PB::NBCtlServicesPB;
use OpenFlow::NBAPI::LowLevel::PB::NBExtensionsPB;
use OpenFlow::NBAPI::LowLevel::PB::SBOFMessagesPB;
use OpenFlow::NBAPI::LowLevel::PB::NorthboundAPIPB;
use OpenFlow::NBAPI::Util::ARP qw(:all);
use OpenFlow::NBAPI::Util::Conversion qw(:all);
use OpenFlow::NBAPI::Util::Extension qw(:all);
use OpenFlow::NBAPI::Util::IOUtil qw(:all);
use OpenFlow::NBAPI::Util::Logger qw(:all);
use OpenFlow::NBAPI::Util::Message qw(:all);
use OpenFlow::NBAPI::Util::Module qw(:all);
use OpenFlow::NBAPI::Util::OFAction qw(:all);
use OpenFlow::NBAPI::Util::OFMatch qw(:all);
use OpenFlow::NBAPI::Util::OFMessage qw(:all);
use OpenFlow::NBAPI::Util::PBMessage qw(:all);
use OpenFlow::NBAPI::Util::Thread qw(:all);
use OpenFlow::NBAPI::Util::Time qw(:all);
use OpenFlow::NBAPI::Util::Value qw(:all);


use constant _EXTCTL          => "OpenFlow::NBAPI::Extension::Controller";

use constant _NBAPI           => "OpenFlow::NBAPI";
use constant _LOWLEVEL        => _NBAPI . "::LowLevel";

use constant _ADDRINFO        => _NBAPI . "::AddrInfo";
use constant _CALLBACK        => __PACKAGE__ . "::Callback";
use constant _MATCHLIST       => _LOWLEVEL . "::NBOFMatchList";
use constant _MFAUX           => __PACKAGE__ . "::MatchFilterAux";
use constant _MSGEVENT        => _NBAPI . "::MessageEvent";
use constant _PBQUEUE         => _NBAPI . "::PBQueue";
use constant _PE              => _LOWLEVEL . "::ProtocolEngine";
use constant _RECVMSGTYPE     => __PACKAGE__ . "::ReceiveMessageType";
use constant _REFLIST         => _LOWLEVEL . "::RefList";
use constant _REQINFO         => __PACKAGE__ . "::RequestInfo";
use constant _REQUEST         => __PACKAGE__ . "::Request";
use constant _SWITCHSTATUS    => __PACKAGE__ . "::SwitchStatus";

use constant _SWITCH_PB       => "OFSwitchStatusPB::SwitchStatusPB";
use constant _PORT_PB         => "OFSwitchStatusPB::PortChangeTypePB";

# Minimum time (in seconds) between ARP requests (findIPAddrInfo)
use constant _MIN_ARP_IVAL    => 5;

# Default time to live (in seconds) for address cache entries
use constant _ADDR_CACHE_TTL_DEFAULT => 1200; # 20 minutes

# Defaults for transaction ID cache (per datapath)
use constant _XID_CACHE_SIZE_DEFAULT => 100;   # max. # of xids to request
use constant _XID_CACHE_TTL_DEFAULT  => 86400; # seconds

use constant _DEFAULT_LOG_LEVEL => TRACE;

use constant _CTL_FN => {
    "ReceiveMessage" => {},
    "IgnoreMessage" => {},
    "SynchMessages" => {},
    "AddMatchFilters" => {},
    "RemoveMatchFilters" => {},
    "SwitchStatus" => {}
    };

use constant _ARP_MATCH      => "arpMatch";
use constant _ARP_MATCH_CB   => "arpMatchCB";
use constant _ARP_MSG_CB     => "arpMsgCB";

__PACKAGE__->_create_accessors();

our $_class :shared = __PACKAGE__;
our $_classRef :shared = \$_class;
our $_numContexts :shared = 0;

sub init {
    my $self = shift;

    $self->SUPER::init(@_) or return undef;
    {
	lock $_classRef;
	$self->{contextID} = ++$_numContexts;
    }
    $self->_arpRegMap(&share({}));
    $self->_arpTimeMap(&share({}));
    $self->_clientMsgQueue(undef);
    my $cookieMutex: shared;
    $self->_cookieMutex(\$cookieMutex);
#    $self->_cookieMSB(int(rand 0x1000) << 52);
    $self->_cookieMSB(0);
    $self->_cookieLSB(0);
    $self->_ctlCapMap(&share({}));
    $self->_ctlExtMap(&share({}));
    $self->_pbIn(_PBQUEUE->new());
    $self->_protoEngine(undef);
    $self->_receiveMessageTypes(&share({}));
    $self->_requests(&share({}));
    $self->_ipAddrCache(&share({}));
    $self->_macAddrCache(&share({}));
    $self->_macReqTimeMap(&share({}));
    $self->_addrNotifyMap(&share({}));
    my $hostTrackMutex :shared;
    $self->_hostTrackMutex(\$hostTrackMutex);
    $self->_hostTrackCB(undef);
    $self->_hostTrackMatch(undef);
    $self->{_hostTrackActual} = HOSTS_NONE;
    $self->_hostTrackTarget(HOSTS_MATCHING);
    $self->_matchFilters(_MATCHLIST->new());
    $self->_noopCB($self->newCallback('_noop'));
    $self->_passThruCB($self->newCallback('_passThrough'));
    $self->_spcnReplyCB($self->newCallback('_spcnReply'));
    $self->_spcnRequestMap(&share({}));
    $self->_switchStatusCallbacks(_REFLIST->new());
    $self->_switchStatusMap(&share({}));
    my $switchStatusLock :shared = 0;
    $self->_switchStatusLockRef(\$switchStatusLock);
    $self->_switchTrackActual(SWITCH_NONE);
    $self->_switchTrackTarget(SWITCH_PORT);
    my $welcome :shared = 0;
    $self->_welcomeRef(\$welcome);
    $self->_xidCache(&share({}));
    $self->addrCacheTTL(_ADDR_CACHE_TTL_DEFAULT);
    $self->arpSenderIP(DEFAULT_ARP_SENDER_IP);
    $self->arpSenderMAC(DEFAULT_ARP_SENDER_MAC);
    $self->autoRestore(0);
    $self->clientID('');
    $self->host('');
    $self->port(0);
    $self->status(CTX_STATUS->DISCONNECTED);
    $self->trackHosts(HOSTS_MATCHING);
    $self->xidCacheSize(_XID_CACHE_SIZE_DEFAULT);
    $self->xidCacheTTL(_XID_CACHE_TTL_DEFAULT);
    return 1;
}

sub _log {
    my $invocant = shift;
    my $msg = shift;
    my $level = shift || _DEFAULT_LOG_LEVEL;
    my $id = ref $invocant ? " " . $invocant->contextID : "";
    writeLog($level, "ControllerContext${id}: $msg");
}

sub addIPAddrNotify {
    my $self = shift;
    my $cbRef = shift or return undef;
    my $dpid = shift or return undef;
    my $ipAddr = parseIPv4(shift) or return undef;

    my $ipMap = $self->_ipAddrNotifyMap($dpid) or return undef;
    return $self->_addNotifyCB($cbRef, $ipMap, $ipAddr);
}

sub addMACAddrNotify {
    my $self = shift;
    my $cbRef = shift or return undef;
    my $dpid = shift or return undef;
    my $macAddr = macToUint64(shift) or return undef;

    # MAC address notification is linked to host tracking
    # (passive learning via no-match packet-in messages),
    # and changes in one must be mutually exclusive with
    # changes in the other.
    my $mutex = $self->_hostTrackMutex;
    lock $mutex;
    my $macMap = $self->_macAddrNotifyMap($dpid) or return undef;
    my $result = $self->_addNotifyCB($cbRef, $macMap, $macAddr);
    # Enable switch-port change notification for the dpid/MAC
    $self->_enableSwPortChangeNotify($dpid, $macAddr);
    return $result;
}

sub addSwitchStatusCallback {
    my $self = shift;
    my $cbRef = shift or return undef;

    my $cbRefList = $self->_switchStatusCallbacks;
    lock $cbRefList;
    return $cbRefList->add($cbRef);
}

sub autoRestore {
    my $self = shift;

    if (@_) {
	$self->{autoRestore} = shift;
	$self->_log("autoRestore: " . ($self->{autoRestore} ? "enabled" : "disabled"));
    }
    return $self->{autoRestore};
}

sub connect {
    my $self = shift;

    lock $self;
    my $contextID = $self->contextID;

    if (defined $self->_socketFD) {
	carp "Existing or stale connection detected; must disconnect() first";
	return 0;
    }
    $self->host or do {
	carp "Cannot connect: host not set";
	return 0;
    };
    $self->port or do {
	carp "Cannot connect: port not set";
	return 0;
    };

    my $socket = IO::Socket::INET->new(
	PeerAddr => $self->host,
	PeerPort => $self->port,
	Proto => "tcp",
	Type => SOCK_STREAM
	) or do {
	    $self->_log("connection to " . $self->host . ":" . $self->port . " failed: $!", ERROR);
	    return 0;
        };
    $self->_socketFD(fileno($socket));
    $self->_log("connected to " . $self->host . ":" . $self->port, TRACE);

    my $pe = _PE->new($contextID);
    $pe->clientID($self->clientID);
    $pe->pbqIn($self->_pbIn);
    $pe->mode(PE_MODE_CLIENT);
    $self->_log("starting ProtocolEngine", DEBUG);
    $pe->start($socket, $socket) or do {
	$self->_log("failed to start NB protocol with controller", ERROR);
	$self->disconnect();
	return 0;
    };
    $self->{_protoEngine} = $pe;

    $self->_startPBQueueMonitor() or do {
	$self->_log("failed to start message queue monitor: $!", ERROR);
	$self->disconnect();
	return 0;
    };

    my $welcomeMsg = $self->_waitForWelcome();
    $self->status(CTX_STATUS->CONNECTED);
    $self->_resetCtlCapabilities();
    $self->_setCtlCapabilities($welcomeMsg->ctlCapabilities);
    $self->_resetCtlExtensions();
    $self->_setCtlExtensions($welcomeMsg->controllerExtensionIDs);

    $self->_spcnRequestMap(&share({}));
    $self->trackHosts($self->_hostTrackTarget);

    $self->_switchStatusMap(&share({}));
    $self->switchStatus($self->_switchTrackTarget);

    if ($self->autoRestore) {
	$self->_restoreMatchFilters();
	$self->_restoreRMT();
    }
    else {
	$self->_resetMatchFilters();
	$self->_resetRMT();
    }
    
    return 1;
}

sub disconnect {
    my $self = shift;

    lock $self;

    $self->isConnected() or do {
	$self->_log("disconnect: not connected", WARN);
	return 1;
    };

    $self->_log("disconnecting", TRACE);

    $self->{_protoEngine}->stop();
    $self->waitForTermination();

    my $contextID = $self->contextID;
    my $socketFD = $self->_socketFD;
    if (defined $socketFD) {
	fdclose($socketFD);
    }

    $self->_resetWelcome();
    $self->_hostTrackActual(HOSTS_NONE);
    $self->_switchTrackActual(SWITCH_NONE);
    $self->status(CTX_STATUS->DISCONNECTED);
    return 1;
}

sub findIPAddrInfo {
    my $self = shift;

    return $self->_findIPAddrInfo(undef, @_);
}

sub findIPAddrInfoAsync {
    my $self = shift;
    my $timeout = shift || 0;

    return $self->_findIPAddrInfo(absTime($timeout), @_);
}

sub findMACAddrInfo {
    my $self = shift;

    return $self->_findMACAddrInfo(undef, @_);
}

sub findMACAddrInfoAsync {
    my $self = shift;
    my $timeout = shift || 0;

    return $self->_findMACAddrInfo(absTime($timeout), @_);
}

sub getDatapaths {
    my $self = shift;

    my $dpidList = &share([]);
    my $ssMap = $self->_switchStatusMap;
    lock $ssMap;
    for my $dpid (keys %$ssMap) {
	push @$dpidList, $dpid;
    }
    return $dpidList;
}

sub getDatapathPortInfo {
    my $self = shift;
    my $dpid = shift or return undef;
    my $portNumber = shift or return undef;

    my $ssMap = $self->_switchStatusMap;
    lock $ssMap;
    my $ssEntry = $ssMap->{$dpid} or return undef;
    my $portMap = $ssEntry->portMap or return undef;
    return $portMap->{$portNumber};
}

sub getDatapathPorts {
    my $self = shift;
    my $dpid = shift or return undef;

    my $ssMap = $self->_switchStatusMap;
    lock $ssMap;
    my $ssEntry = $ssMap->{$dpid} or return undef;
    my $portMap = $ssEntry->portMap or return undef;
    my $ports = &share([]);
    for my $portNumber (sort _byNumber keys %$portMap) {
	push @$ports, $portMap->{$portNumber};
    }
    return $ports;
}

sub getLocalIPAddrInfo {
    my $self = shift;

    if (@_) {
	my ($ipV4Addr, $_mask) = parseIPv4(shift);
	return $self->_getLocalIPAddrInfo($ipV4Addr, @_);
    }
    else {
	return $self->_getLocalIPAddrInfo();
    }
}

sub getLocalMACAddrInfo {
    my $self = shift;

    if (@_) {
	my $mac = macToUint64(shift);
	return $self->_getLocalMACAddrInfo($mac, @_);
    }
    else {
	return $self->_getLocalMACAddrInfo();
    }
}

sub getSwitches {
    my $self = shift;

    return $self->getDatapaths(@_);
}

sub getSwitchPortInfo {
    my $self = shift;

    return $self->getDatapathPortInfo(@_);
}

sub getSwitchPorts {
    my $self = shift;

    return $self->getDatapathPorts(@_);
}

sub hasCtlCapability {
    my $self = shift;
    my $cap = shift or return undef;

    my $map = $self->_ctlCapMap;
    lock $map;
    return $map->{$cap};
}

sub hasCtlExtension {
    my $self = shift;
    my $ext = shift or return undef;
    my $feature = shift;

    my $map = $self->_ctlExtMap;
    my $hasExt = 0;
    my $extModule;
    {
	lock $map;
	if ($hasExt = $map->{$ext}) {
	    # Ensure the extension module is loaded
	    # in the current thread context
	    $extModule = $self->_extModule($ext);
	    loadModule($extModule) and do {
		$self->_log("loaded extension module $extModule", TRACE);
	    };
	}
    }
    if ($hasExt && $feature) {
	$hasExt = $extModule->hasFeature($self, $feature);
    }
    return $hasExt;
}

sub isConnected {
    my $self = shift;

    return $self->status == CTX_STATUS->CONNECTED;
}

sub isDatapathPersistent {
    my $self = shift;
    my $dpid = shift;

    my $ssMap = $self->_switchStatusMap;
    lock $ssMap;
    my $ssEntry = $ssMap->{$dpid} or return undef;
    return $ssEntry->persistent;
}

sub isSwitchPersistent {
    my $self = shift;

    return $self->isDatapathPersistent(@_);
}

sub isTerminated {
    my $self = shift;
    $self->{_protoEngine}->isTerminated(@_);
}

sub messageQueueIn {
    my $self = shift;

    if (@_) {
	my $queue = shift;
	$self->_clientMsgQueue(defined $queue ? shared_clone($queue) : undef);
	$self->_log("incoming message queue " . (defined $queue ? "enabled" : "disabled"), INFO);
    }
    elsif (! $self->_clientMsgQueue) {
	$self->_clientMsgQueue(_PBQUEUE->new());
	$self->_log("incoming message queue enabled", INFO);
    }
    return $self->_clientMsgQueue;
}

sub newCallback {
    my $self = shift;
    my $priority = looks_like_number $_[0] ? shift : 0;
    my $name = shift;

    my $cb = _CALLBACK->new();
    $cb->name(shared_clone($name));
    $cb->priority($priority);
    if (@_) {
	my $args = &share([]);
	for (@_) {
	    push @$args, shared_clone($_);
	}
	$cb->args($args);
    }
    return $cb;
}

sub nextCookie {
    my $self = shift;

    my $mutex = $self->_cookieMutex;
    lock $mutex;
    my $lsb = $self->_cookieLSB;
    $lsb = 0 if ($lsb >= 0xffffffff);
    $self->_cookieLSB(++$lsb);
    return ($self->_cookieMSB | $lsb);
}

sub nextXID {
    my $self = shift;
    my $dpid = shift;

    my $dpidStr = dpidToString($dpid);
    my $dpidCache;
    {
	my $xidCache = $self->_xidCache;
	lock $xidCache;
	unless ($dpidCache = $xidCache->{$dpid}) {
	    $dpidCache = &share({});
	    $dpidCache->{'last'} = 0;
	    $dpidCache->{'time'} = 0;
	    $dpidCache->{'xids'} = &share([]);
	    $xidCache->{$dpid} = $dpidCache;
	}
    }
    {
	lock $dpidCache;
	my $size = $self->xidCacheSize;
	my $time = $dpidCache->{'time'};
	my $xids = $dpidCache->{'xids'};
	unless (($time + $self->xidCacheTTL >= time()) && @$xids) {
	    # cache is expired or empty; refill
	    if ($self->hasCtlExtension(EXT_CTL_SUPPORT, "NextTransactionID")) {
		my $newXIDs = $self->NextTransactionID($dpid, $size);
		if ($newXIDs && @$newXIDs) {
		    push @$xids, $_ foreach @$newXIDs;
		}
		else {
		    $self->_log("Failed to obtain transaction IDs for datapath $dpidStr", ERROR);
		    return undef;
		}
	    }
	    else {
		my $xid = $dpidCache->{'last'};
		push @$xids, ++$xid while $size--;
	    }
	    $dpidCache->{'time'} = time();
	}
	my $xid = shift @$xids;
	$dpidCache->{'last'} = $xid;
	return $xid;
    }
}

sub ping {
    my $self = shift;
    my $timeout = shift;

    $self->isConnected() or do {
	$self->_log("cannot ping; no controller connection", ERROR);
	return undef;
    };
    my $requestTime = timeMS();
    my $request = $self->_sendRequest(undef, "sendPingRequest", 0, "ping") or do {
	$self->_log("failed to send ping request", ERROR);
	return undef;
    };
    $request->waitForCompletion($timeout) or do {
	$self->_log("ping request timed out", WARN);
	return undef;
    };
    return (timeMS() - $requestTime);
}

sub removeIPAddrNotify {
    my $self = shift;
    my $cbRef = shift or return undef;
    my $dpid = shift or return undef;
    my $ipAddr = parseIPv4(shift) or return undef;

    my $ipMap = $self->_ipAddrNotifyMap($dpid) or return undef;
    return $self->_removeNotifyCB($cbRef, $ipMap, $ipAddr);
}

sub removeMACAddrNotify {
    my $self = shift;
    my $cbRef = shift or return undef;
    my $dpid = shift or return undef;
    my $macAddr = macToUint64(shift) or return undef;

    # MAC address notification is linked to host tracking
    # (passive learning via no-match packet-in messages),
    # and changes in one must be mutually exclusive with
    # changes in the other.
    my $mutex = $self->_hostTrackMutex;
    lock $mutex;
    my $macMap = $self->_macAddrNotifyMap($dpid) or return undef;
    my $result = $self->_removeNotifyCB($cbRef, $macMap, $macAddr);
    # Disable switch-port change notification if the dpid/MAC no longer registered
    $self->_disableSwPortChangeNotify($dpid, $macAddr) if $result == 0;
    return $result;
}

sub removeSwitchStatusCallback {
    my $self = shift;
    my $cbRef = shift or return undef;

    my $cbRefList = $self->_switchStatusCallbacks;
    lock $cbRefList;
    return $cbRefList->remove($cbRef);
}

sub setDatapathPersistent {
    my $self = shift;
    my $dpid = shift;
    my $persistent = shift;

    return $self->_updateSwitchStatus($dpid, undef, $persistent);
}

sub setSwitchPersistent {
    my $self = shift;

    return $self->setDatapathPersistent(@_);
}

sub trackHosts {
    my $self = shift;

    my $mutex = $self->_hostTrackMutex;
    lock $mutex;

    my $actual = $self->_hostTrackActual;
    if (@_) {
	my $level = shift;
	if ($level < HOSTS_NONE || $level > HOSTS_ALL) {
	    carp "trackHosts: invalid tracking level $level";
	    return $actual;
	}
	$self->_hostTrackTarget($level);
    }
    else {
	return $actual;
    }

    my $target = $self->_hostTrackTarget;
    return $actual if $actual == $target;

    if ($actual == HOSTS_ALL || $target == HOSTS_ALL) {
	if ($self->isConnected) {
	    my $match = $self->_hostTrackMatch ||
		$self->_hostTrackMatch(newNBOFMatch(newOFMatch(), undef, OFPacketInReasonPB->NO_MATCH));
	    my $cbRef = $self->_hostTrackCB ||
		$self->_hostTrackCB($self->newCallback('_noop'));
	    if ($target == HOSTS_ALL) {
		$self->addMatchFilters($cbRef, $match) or do {
		    $self->_log("trackHosts: failed to add match filter", WARN);
		    $target = HOSTS_MATCHING;
		};
		$self->receiveMessage($cbRef, OF->PACKET_IN) or do {
		    $self->_log("trackHosts: failed to enable message receipt", WARN);
		    $target = HOSTS_MATCHING;
		};
	    }
	    else {
		$self->removeMatchFilters($cbRef, $match) or do {
		    $self->_log("trackHosts: failed to remove match filter", WARN);
		};
		$self->ignoreMessage($cbRef, OF->PACKET_IN) or do {
		    $self->_log("trackHosts: failed to disable message receipt", WARN);
		};
	    }
	}
	elsif ($target == HOSTS_ALL) {
	    $self->_log("trackHosts: controller request pending", INFO);
	    return $actual;
	}
    }

    $self->_log("passive host tracking level $target (" . HOSTS_TRACK->{$target} . ")", INFO);
    return $self->_hostTrackActual($target);
}

sub waitForDatapaths {
    my $self = shift;
    my $timeout = shift || 0;

    my $dpidList;
    my $absTimeout = absTime($timeout) if $timeout;

    my $ssMap = $self->_switchStatusMap;
    lock $ssMap;
    until (@{$dpidList = $self->getDatapaths()}) {
	if ($absTimeout) {
	    last unless cond_timedwait $ssMap, $absTimeout;
	}
	else {
	    cond_wait $ssMap;
	}
    }
    return $dpidList;
}

sub waitForSwitches {
    my $self = shift;

    return $self->waitForDatapaths(@_);
}

sub waitForTermination {
    my $self = shift;

    $self->_log("waiting for ProtocolEngine termination", TRACE);
    my $status = $self->{_protoEngine}->waitForTermination(@_);
    if ($status) {
	$self->_log("ProtocolEngine terminated", TRACE);
    }
    else {
	$self->_log("timed out waiting for ProtocolEngine termination", TRACE);
    }
    return $status;
}

# CtlService requests
sub addMatchFilters {
    my $self = shift;

    return $self->_addMatchFilters(undef, @_);
}

sub addMatchFiltersAsync {
    my $self = shift;
    my $timeout = shift || 0;

    return $self->_addMatchFilters(absTime($timeout), @_);
}

sub ignoreMessage {
    my $self = shift;

    return $self->_ignoreMessage(undef, @_);
}

sub ignoreMessageAsync {
    my $self = shift;
    my $timeout = shift || 0;

    return $self->_ignoreMessage(absTime($timeout), @_);
}

sub receiveMessage {
    my $self = shift;

    return $self->_receiveMessage(undef, @_);
}

sub receiveMessageAsync {
    my $self = shift;
    my $timeout = shift || 0;

    return $self->_receiveMessage(absTime($timeout), @_);
}

sub removeMatchFilters {
    my $self = shift;

    return $self->_removeMatchFilters(undef, @_);
}

sub removeMatchFiltersAsync {
    my $self = shift;
    my $timeout = shift || 0;

    return $self->_removeMatchFilters(absTime($timeout), @_);
}

sub switchStatus {
    my $self = shift;

    return $self->_switchStatus(undef, @_);
}

sub switchStatusAsync {
    my $self = shift;
    my $timeout = shift || 0;

    return $self->_switchStatus(absTime($timeout), @_);
}

sub synchMessages {
    my $self = shift;

    return $self->_synchMessages(undef, @_);
}

sub synchMessagesAsync {
    my $self = shift;
    my $timeout = shift || 0;

    return $self->_synchMessages(absTime($timeout), @_);
}

# Low-level messaging methods
sub sendOFMessage {
    my $self = shift;
    my $ofMsg = shift or return 0;
    my $datapathID = shift || 0;

    $self->isConnected() or do {
	$self->_log("sendOFMessage: no controller connection", ERROR);
	return undef;
    };

    my $nbMsg = &share(SBOFMessagePB->new());
    $nbMsg->datapathID(shared_clone($datapathID));
    $nbMsg->ofMessage(shared_clone($ofMsg));

    $self->_log("sending OF message", DEBUG);
    return $self->{_protoEngine}->sendOpenFlowMsg($nbMsg);
}

sub sendCtlServiceRequest {
    my $self = shift;

    my $request = $self->_sendCtlServiceRequest(undef, @_) or return undef;
    $request->waitForCompletion();
    return $request->replyValue;
}

sub sendCtlServiceRequestAsync {
    my $self = shift;
    my $timeout = shift || 0;

    my $request = $self->_sendCtlServiceRequest(undef, @_) or return undef;
    $request->waitForCompletion($timeout);
    return $request;
}

sub sendExtensionRequest {
    my $self = shift;

    my $request = $self->_sendExtensionRequest(undef, @_) or return undef;
    $request->waitForCompletion();
    return $request->replyValue;
}

sub sendExtensionRequestAsync {
    my $self = shift;
    my $timeout = shift || 0;

    my $request = $self->_sendExtensionRequest(undef, @_) or return undef;
    $request->waitForCompletion($timeout);
    return $request;
}


# Private methods

sub _addNotifyCB {
    my $self = shift;
    my $cbRef = shift;
    my $map = shift;
    my $key = shift;

    lock $map;
    my $refList;
    $refList = $map->{$key} or do {
	$refList = _REFLIST->new();
	$map->{$key} = $refList;
    };
    return $refList->add($cbRef);
}

sub _byNumber { $a <=> $b }

sub _byPriority { $b->priority <=> $a->priority }

sub _findIPAddrInfo {
    my $self = shift;
    my $absTimeout = shift;
    my $host = shift;
    my ($ipV4Addr, $_mask) = parseIPv4($host);
    my $arpMS = shift || 0;
    my $dpid = shift;
    my $reqPort = shift;
    my $exclPort = shift;

    if (! defined $dpid && (defined $reqPort || defined $exclPort)) {
	carp "findIPAddrInfo: cannot specify a switch port without datapath ID";
	return undef;
    }
    if (defined $reqPort && defined $exclPort) {
	carp "findIPAddrInfo: cannot specify both request port and exclusion port";
	return undef;
    }
    if (defined $reqPort && ($reqPort < 1 || $reqPort > OFPortPB->OFPP_MAX)) {
	carp "findIPAddrInfo: invalid request port";
	return undef;
    }
    if (defined $exclPort && ($exclPort < 1 || $exclPort > OFPortPB->OFPP_MAX)) {
	carp "findIPAddrInfo: invalid exclusion port";
	return undef;
    }

    #
    # Request-suppression logic:
    #   We want to avoid making too many repeated controller requests
    # (when the extension is supported) or ARP requests (when it is not).
    # Hence, a minimum interval (_MIN_ARP_IVAL) is imposed between repeated
    # requests, where "repeated" is defined as being for the same IP address,
    # datapath (switch) ID, and switch port.  This logic is complicated by
    # the following additional considerations:
    #
    # - If the caller does not specify a datapath ID, the request applies
    #   to all known datapath IDs.  We cannot safely assume that locally
    #   maintained datapath information is complete, so requests to the
    #   controller will not be suppressed when no datapath ID is specified
    #   (because the controller DOES have complete datapath information).
    #   On the other hand, locally generated ARP requests (used when the
    #   controller extension is not supported) must specify a datapath ID,
    #   and the local datapath ID set (which is maintained from information
    #   supplied by the controller and/or the caller) is all we have, so it
    #   must be used even if it is not known to be complete.
    #
    # - If the caller does not want an ARP request ($arp == 0), the call
    #   effectively becomes a cache lookup, either on the controller
    #   (when the extension is supported) or locally (when it is not),
    #   and these we never want to suppress.  However, since the caller
    #   has no control over whether the extension is supported, a separate
    #   method for querying the local cache is provided (in case the caller
    #   wants only to query the local cache and not ask the controller).
    #
    # Note that switch port information is all or nothing: if we have a
    # port list for a datapath ID, it is complete (having come from
    # the controller).
    #
    my $now = time();
    if ($self->hasCtlExtension(EXT_CTL_SUPPORT, "GetIPAddrInfo")) {
	my ($arpPort, $lastARP) =
	    ($arpMS && defined $dpid) ? $self->_lastARPTime($ipV4Addr, $dpid, $reqPort, $exclPort) : ($reqPort, 0);
	if ($now - $lastARP >= _MIN_ARP_IVAL) {
	    my $failure = "";
	    # Make controller request; result processed by internal callback
	    my $replyCB = $self->newCallback("_ipAddrInfoReply", $ipV4Addr);
	    if (my $result = $self->_GetIPAddrInfo($replyCB, $absTimeout, $ipV4Addr, $arpMS, $dpid, $arpPort, $exclPort)) {
		if (blessed $result && $result->isa(_REQUEST)) {
		    my $request = $result;
		    if ($request->completed) {
			$failure = "returned ERROR" if errorStatus($request->replyMessage);
		    }
		    else {
			$failure = "timed out";
		    }
		}
	    }
	    else {
		$failure = "failed" unless defined($result);
	    }
	    $self->_log("findIPAddrInfo: controller request $failure; information may be incomplete or out of date", WARN) if $failure;
	    $self->_updateARPTime($now, $ipV4Addr, $dpid, $reqPort, $exclPort);
	}
    }
    elsif ($arpMS > 0) {
	my @dpidList;
	if (defined $dpid) {
	    @dpidList = ($dpid);
	}
	else {
	    my $ssMap = $self->_switchStatusMap;
	    lock $ssMap;
	    @dpidList = keys %$ssMap;
	}
	@dpidList or do {
	    $self->_log("findIPAddrInfo: no datapath IDs available", WARN);
	    return undef;
	};
	my $arpSec = int(($arpMS - 1) / 1000) + 1; # round up to nearest second
	my $waitSec = 0;
	for my $_dpid (@dpidList) {
	    my ($arpPort, $lastARP) = $self->_lastARPTime($ipV4Addr, $_dpid, $reqPort, $exclPort);
	    if ($now - $lastARP >= _MIN_ARP_IVAL) {
		$self->_enableReceiveARPReplies($absTimeout) or do {
		    $self->_log("findIPAddrInfo: failed to enable receipt of ARP replies; information may be incomplete or out of date", WARN);
		};
		$self->_sendARPRequest($ipV4Addr, $_dpid, $arpPort, $exclPort) or do {
		    $self->_log("findIPAddrInfo: failed to send ARP request; information may be incomplete or out of date", WARN);
		};
		$self->_updateARPTime($now, $ipV4Addr, $_dpid, $arpPort, $exclPort);
		$lastARP = $now;
	    }
	    my $arpWait = ($lastARP - $now) + $arpSec;
	    $waitSec = $arpWait if ($arpWait > $waitSec);
	}
	threadSleep($waitSec);
    }
    return $self->_getLocalIPAddrInfo($ipV4Addr, $dpid, $reqPort, $exclPort);
}

sub _findMACAddrInfo {
    my $self = shift;
    my $absTimeout = shift;
    my $macAddr = macToUint64(shift);
    my $dpid = shift;
    my $arpMS = shift || 0;

    (defined $macAddr && defined $dpid) or do {
	carp "findMACAddrInfo: MAC address and datapath ID must be specified.";
	return undef;
    };

    #
    # Request-suppression logic:
    #   We want to avoid making too many repeated controller requests
    # (when the extension is supported).  Hence, a minimum interval
    # (_MIN_ARP_IVAL) is imposed between repeated requests, where
    # "repeated" is defined as being for the same MAC address and
    # datapath (switch) ID.
    #
    # Note: if the caller does not want a controller request ($arp == 0), the
    # call effectively becomes a cache lookup.  For symmetry with IP address lookup,
    # a separate method is also provided for querying the local MAC cache directly.
    #
    my $now = time();
    if ($self->hasCtlExtension(EXT_CTL_SUPPORT, "SwitchPortForMACAddr")) {
	my $lastReq = $arpMS ? $self->_lastMACReqTime($macAddr, $dpid) : 0;
	if ($now - $lastReq >= _MIN_ARP_IVAL) {
	    my $failure = "";
	    # Make controller request; result processed by internal callback
	    my $replyCB = $self->newCallback("_macAddrInfoReply", $macAddr, $dpid);
	    if (my $result = $self->_SwitchPortForMACAddr($replyCB, $absTimeout, $macAddr, $dpid)) {
		if (blessed $result && $result->isa(_REQUEST)) {
		    my $request = $result;
		    if ($request->completed) {
			$failure = "returned ERROR" if errorStatus($request->replyMessage);
		    }
		    else {
			$failure = "timed out";
		    }
		}
	    }
	    else {
		$failure = "failed" unless defined($result);
	    }
	    $self->_log("findMACAddrInfo: controller request $failure; information may be incomplete or out of date", WARN) if $failure;
	    $self->_updateMACReqTime($now, $macAddr, $dpid);
	}
    }
    return $self->_getLocalMACAddrInfo($macAddr, $dpid);
}

sub _dpidAddrNotifyMap {
    my $self = shift;
    my $dpid = shift;
    my $addrType = shift;

    my $dpidMap;
    {
	my $addrNotifyMap = $self->_addrNotifyMap;
	lock $addrNotifyMap;
	$dpidMap = $addrNotifyMap->{$dpid} or do {
	    $dpidMap = &share({});
	    $addrNotifyMap->{$dpid} = $dpidMap;
	};
    }
    my $addrTypeMap;
    {
	lock $dpidMap;
	$addrTypeMap = $dpidMap->{$addrType} or do {
	    $addrTypeMap = &share({});
	    $dpidMap->{$addrType} = $addrTypeMap;
	};
    }
    return $addrTypeMap;
}

sub _disableSwPortChangeNotify {
    my $self = shift;
    my $dpid = shift;
    my $macAddr = shift;

    return undef unless $self->isConnected();
    return 0 unless $self->hasCtlExtension(EXT_CTL_SUPPORT, "SwPortChangeNotify");

    my $mutex = $self->_hostTrackMutex;
    lock $mutex;

    my $reqMap = $self->_spcnRequestMap;
    lock $reqMap;

    my @dpidList = ();
    if (defined $dpid) {
	push @dpidList, $dpid;
    }
    else {
	push @dpidList, keys %$reqMap;
    }

    my $numRequests = 0;
    for my $_dpid (@dpidList) {
	my $dpidMap = $reqMap->{$_dpid} or next;
	lock $dpidMap;
	my @macList = ();
	if (defined $macAddr) {
	    push @macList, $macAddr;
	}
	else {
	    push @macList, keys %$dpidMap;
	}
	for my $_macAddr (@macList) {
	    my $spcnRequest = $self->_spcnRequest($_dpid, $_macAddr) or next;
	    unless ($spcnRequest->completed) {
		$self->_SwPortChangeNotify(undef, 0, $_macAddr, $_dpid, 0) or next;
		++$numRequests;
	    }
	    $self->_spcnRequest($_dpid, $_macAddr, undef);
	}
    }
    return $numRequests;
}

sub _enableSwPortChangeNotify {
    my $self = shift;
    my $dpid = shift;
    my $macAddr = shift;

    return undef unless $self->isConnected();

    unless ($self->hasCtlExtension(EXT_CTL_SUPPORT, "SwPortChangeNotify")) {
	if ($self->_hostTrackActual != HOSTS_ALL) {
	    $self->_log("controller extension 'SwPortChangeNotify' not supported; consider use of 'trackHosts(HOSTS_ALL)' to compensate", WARN);
	}
	return 0;
    }

    my $mutex = $self->_hostTrackMutex;
    lock $mutex;

    # Don't enable SwPortChangeNotify if full passive host tracking in effect
    return 0 if $self->_hostTrackActual == HOSTS_ALL;

    my @dpidList = ();
    if (defined $dpid) {
	push @dpidList, $dpid;
    }
    else {
	my $addrNotifyMap = $self->_addrNotifyMap;
	lock $addrNotifyMap;
	push @dpidList, keys %$addrNotifyMap;
    }

    my $numRequests = 0;
    for my $_dpid (@dpidList) {
	my $macNotifyMap = $self->_dpidAddrNotifyMap($_dpid, 'MAC');
	lock $macNotifyMap;
	my @macList = ();
	if (defined $macAddr) {
	    push @macList, $macAddr;
	}
	else {
	    push @macList, keys %$macNotifyMap;
	}
	for my $_macAddr (@macList) {
	    my $refList = $macNotifyMap->{$_macAddr} or next;
	    $refList->length > 0 or next;
	    my $spcnRequest = $self->_spcnRequest($_dpid, $_macAddr);
	    unless ($spcnRequest && ! $spcnRequest->completed) {
		my $request = $self->_SwPortChangeNotify($self->_spcnReplyCB, 0, $_macAddr, $_dpid, 1) or next;
		$self->_spcnRequest($_dpid, $_macAddr, $request);
		++$numRequests;
	    }
	}
    }
    return $numRequests;
}

sub _spcnRequest {
    my $self = shift;
    my $dpid = shift;
    my $macAddr = shift;

    my $result = undef;
    my $dpidMap;
    {
	my $reqMap = $self->_spcnRequestMap;
	lock $reqMap;
	$dpidMap = $reqMap->{$dpid} or do {
	    $dpidMap = &share({});
	    $reqMap->{$dpid} = $dpidMap;
	};
    }
    {
	lock $dpidMap;
	if (@_) {
	    if (my $request = shift) {
		$dpidMap->{$macAddr} = $request;
	    }
	    else {
		delete $dpidMap->{$macAddr};
	    }
	}
	$result = $dpidMap->{$macAddr};
    }
    return $result;
}

sub _hostTrackActual {
    my $self = shift;

    my $mutex = $self->_hostTrackMutex;
    lock $mutex;
    if (@_) {
	my $newLevel = shift;
	my $oldLevel = $self->{_hostTrackActual};
	if ($newLevel != $oldLevel) {
	    $self->{_hostTrackActual} = $newLevel;
	    # Enable or disable switch-port change notification, as necessary
	    # and appropriate, for all registered MACs and datapaths.
	    if ($oldLevel == HOSTS_ALL) {
		$self->_enableSwPortChangeNotify();
	    }
	    elsif ($newLevel == HOSTS_ALL) {
		$self->_disableSwPortChangeNotify();
	    } 
	}
    }
    return $self->{_hostTrackActual};
}

sub _ipAddrNotifyMap {
    my $self = shift;
    my $dpid = shift;

    return $self->_dpidAddrNotifyMap($dpid, 'IPv4');
}

sub _macAddrNotifyMap {
    my $self = shift;
    my $dpid = shift;

    return $self->_dpidAddrNotifyMap($dpid, 'MAC');
}

sub _notifyAddrCB {
    my $self = shift;
    my $addrInfo = shift;
    my $map = shift;
    my $key = shift;

    my @cbList = ();
    {
	lock $map;
	if (my $refList = $map->{$key}) {
	    push @cbList, @{$refList->getList()};
	}
    }
    for my $cbRef (sort _byPriority @cbList) {
	my $cbName = $cbRef->name;
	my @cbArgs = ($addrInfo);
	push @cbArgs, @{$cbRef->args} if $cbRef->args;
	$self->_log("notifyAddr callback: $cbName", DEBUG);
	eval {
	    no strict 'refs';
	    &$cbName(@cbArgs);
	};
	$self->_log($@, ERROR) if $@;
    }
}

sub _notifyIPAddrInfo {
    my $self = shift;
    my $addrInfo = shift or return undef;

    my $dpid = $addrInfo->{datapathID};
    defined $dpid or return undef;

    if (defined (my $ipAddr = $addrInfo->ipV4Addr)) {
	my $ipMap = $self->_ipAddrNotifyMap($dpid);
	$self->_notifyAddrCB($addrInfo, $ipMap, $ipAddr);
    }
    return 1;
}

sub _notifyMACAddrInfo {
    my $self = shift;
    my $addrInfo = shift or return undef;

    my $dpid = $addrInfo->{datapathID};
    defined $dpid or return undef;

    if (defined (my $macAddr = $addrInfo->macAddr)) {
	my $macMap = $self->_macAddrNotifyMap($dpid);
	$self->_notifyAddrCB($addrInfo, $macMap, $macAddr);
    }
    return 1;
}

sub _removeNotifyCB {
    my $self = shift;
    my $cbRef = shift;
    my $map = shift;
    my $key = shift;

    lock $map;
    my $refList;
    $refList = $map->{$key} or return 0;
    return $refList->remove($cbRef);
}

sub _resetRMT {
    my $self = shift;

    my $rmtMap = $self->_receiveMessageTypes;
    lock $rmtMap;
    %$rmtMap = ();
    return 1;
}

sub _restoreRMT {
    my $self = shift;

    my $retval = 0;
    my $rmtMap = $self->_receiveMessageTypes;
    lock $rmtMap;
    my @receiveList = keys %$rmtMap;
    if (my $request = $self->_sendReceiveMessage(undef, @receiveList)) {
	$request->waitForCompletion();
	$retval = $request->replyValue;
    }
    $retval or do {
	$self->_log("failed to restore received message types", ERROR);
	$self->_resetRMT();
    };
    return $retval;
}

sub _newRequest {
    my $self = shift;

    my $request = _REQUEST->new();
    $request->_ctlCtx($self);
    return $request;
}

sub _requestResult {
    my $self = shift;
    my $request = shift;
    my $absTimeout = shift;
    my $defaultResult = shift;

    unless ($request) {
	# Create a "non-request" object to ensure consistent return type
	$request = $self->_newRequest();
	$request->_replyValue($defaultResult);
	$request->_completed(1);
    }
    $request->waitForCompletionUntil($absTimeout);
    my $replyValue = $request->replyValue;
    $replyValue = $defaultResult unless defined $replyValue;
    my $rv = defined $absTimeout ? $request : $replyValue;
    return $rv;
}

sub _receiveMessage {
    my $self = shift;
    my $absTimeout = shift;
    my $cbRef = shift if (@_ && ref($_[0]));

    @_ or do {
	carp "No OpenFlow message type(s) specified.";
	return 0;
    };

    my $addCBRef = $cbRef;
    $addCBRef or do {
	$addCBRef = $self->_passThruCB;
	$self->_clientMsgQueue or do {
	    $self->_log("receiveMessage: no callback specified and message queue not enabled", WARN);
	};
    };
    my $rmtMap = $self->_receiveMessageTypes;
    my $request;
    my @receiveList = ();
    my @rmtModList = ();
    my $failed = 0;

    # Collect message types for controller request and wait for any pending requests
    TYPE: for my $type (@_) {
	$self->_isValidOFType($type) or do {
	    $self->_log("receiveMessage: invalid OF message type $type (skipped)", WARN);
	    next TYPE;
	};
	my $rmt;
	{
	    lock $rmtMap;
	    $rmt = $rmtMap->{$type} or do {
		$rmt = $rmtMap->{$type} = _RECVMSGTYPE->new();
	    };
	}
	{
	    lock $rmt;
	    next TYPE if $rmt->refList->contains($addCBRef); # no changes for this type; skip
	    $self->_log("receiveMessage: holding for pending request on type $type", DEBUG) if $rmt->pending;
	    $rmt->waitForPendingUntil($absTimeout) or do {
		$self->_log("receiveMessage: timed out waiting for pending request on type $type", ERROR);
		$failed = 1;
		last TYPE;
	    };
	    $rmt->pending(-1); # pre-request hold
	    push @rmtModList, $rmt;
	    push @receiveList, $type if $rmt->refList->isEmpty;
	}
    }
    # Issue the controller request, if required
    if (@receiveList && ! $failed) {
	my $replyCB = $self->newCallback("_receiveMessageReply", "ReceiveMessage", @rmtModList);
	$request = $self->_sendReceiveMessage($replyCB, @receiveList) or $failed = 1;
	# TODO Check this: (disabled) Make sure the message queue is enabled if no callback was specified
	#$self->messageQueueIn unless $cbRef || $failed;
    }
    # Update message-type callbacks (if successful) and pending markings
    my $pending = $request ? $request->id : undef;
    for my $rmt (@rmtModList) {
	lock $rmt;
	$rmt->refList->add($addCBRef) unless $failed;
	$rmt->pending($pending);
    }
    return $failed ? undef : $self->_requestResult($request, $absTimeout, 1);
}

sub _ignoreMessage {
    my $self = shift;
    my $absTimeout = shift;
    my $cbRef = (@_ && ref($_[0]) ? shift : $self->_passThruCB);

    @_ or do {
	carp "No OpenFlow message type(s) specified.";
	return 0;
    };

    my $rmtMap = $self->_receiveMessageTypes;
    my $request;
    my @ignoreList = ();
    my @rmtModList = ();
    my $failed = 0;

    # Collect message types for controller request and wait for any pending requests
    TYPE: for my $type (@_) {
	$self->_isValidOFType($type) or do {
	    $self->_log("ignoreMessage: invalid OF message type $type (skipped)", WARN);
	    next TYPE;
	};
	my $rmt;
	{
	    lock $rmtMap;
	    $rmt = $rmtMap->{$type} or next TYPE;
	}
	{
	    lock $rmt;
	    $rmt->refList->contains($cbRef) or next TYPE;
	    $self->_log("ignoreMessage: holding for pending request on type $type", DEBUG) if $rmt->pending;
	    $rmt->waitForPendingUntil($absTimeout) or do {
		$self->_log("ignoreMessage: timed out waiting for pending request on type $type", ERROR);
		$failed = 1;
		last TYPE;
	    };
	    $rmt->pending(-1); # pre-request hold
	    push @rmtModList, $rmt;
	    push @ignoreList, $type if ($rmt->refList->length == 1);
	}
    }
    # Issue the controller request, if required
    if (@ignoreList && ! $failed) {
	my $replyCB = $self->newCallback("_receiveMessageReply", "IgnoreMessage", @rmtModList);
	$request = $self->_sendIgnoreMessage($replyCB, @ignoreList) or $failed = 1;
    }
    # Update message-type callbacks (if successful) and pending markings
    my $pending = $request ? $request->id : undef;
    for my $rmt (@rmtModList) {
	lock $rmt;
	$rmt->refList->remove($cbRef) unless $failed;
	$rmt->pending($pending);
    }
    return $failed ? undef : $self->_requestResult($request, $absTimeout, 1);
}

sub _receiveMessageReply {
    my $request = shift;
    my $reqType = shift;

    my $ctx = $request->ctlCtx;
    my $requestID = $request->id;
    for my $rmt (@_) {
	lock $rmt;
	my $pending = $rmt->pending or next;
	$rmt->pending(undef) if $pending == $requestID;
    }
    $ctx->_log("$reqType request $requestID failed on controller", WARN) unless $request->replyValue;
    return 1;
}

sub _resetMatchFilters {
    my $self = shift;

    $self->_matchFilters->clear();
}

sub _restoreMatchFilters {
    my $self = shift;

    my $retval = 0;
    my $matchFilters = $self->_matchFilters;
    lock $matchFilters;
    my $matchNodes = $matchFilters->find(newNBOFMatch(newOFMatch()), NARROWER);
    my @mfList = ();
    for my $node (@$matchNodes) {
	push @mfList, $node->getMatch();
    }
    if (my $request = $self->_sendAddFilterRequest(undef, @mfList)) {
	$request->waitForCompletion();
	$retval = $request->replyValue;
    }
    $retval or do {
	$self->_log("failed to restore match filters", ERROR);
	$self->_resetMatchFilters();
    };
    return $retval;
}

sub _addMatchFilters {
    my $self = shift;
    my $absTimeout = shift;
    my $cbRef = (@_ && blessed $_[0] && $_[0]->isa(_CALLBACK) ? shift : $self->_noopCB);

    my $matchFilters = $self->_matchFilters;
    my $request;
    my @mfReqList = ();   # match filters to be included in a controller request
    my @newMFList = ();   # match filters newly added
    my @nodeModList = (); # match-list nodes needing modification
    my @mfModList = ();   # match filters for nodes needing modification
    my $failed = 0;

    MF: for my $mf (@_) {
	my $node = $matchFilters->add($mf, sub { shift; }) or next MF;
	{
	    lock $node;
	    my $nodeMF = $node->getMatch();
	    my $nodeAux = $node->getReference();
	    if ($nodeAux && valuesEqual($mf->auxData, $nodeMF->auxData)) {
		# The filter was already present, and there is no change
		# to its auxData, so no controller request is needed.
		next MF if $nodeAux->hasCallback($cbRef); # no change at all to this node
	    }
	    else {
		push @mfReqList, $mf; # new or changed filter; include in controller request
		push @newMFList, $mf unless $nodeAux; # new filter to be removed in case of failure
	    }
	    $self->_log("addMatchFilters: holding for pending request", DEBUG) if $node->pending;
	    $node->waitForPendingUntil($absTimeout) or do {
		$self->_log("addMatchFilters: timed out waiting for pending request", ERROR);
		$failed = 1;
		last MF;
	    };
	    $node->pending(-1); # pre-request hold
	    # Record information for deferred node modifications
	    push @nodeModList, $node;
	    push @mfModList, $mf;
	}
    }
    # Make a controller request if necessary
    if (@mfReqList && ! $failed) {
	my $replyCB = $self->newCallback("_matchFilterReply", "AddMatchFilters", @nodeModList);
	$request = $self->_sendAddFilterRequest($replyCB, @mfReqList) or $failed = 1;
    }
    if ($failed) {
	# Release pre-request holds
	for my $node (@nodeModList) {
	    lock $node;
	    $node->pending(undef);
	}
	# Restore the match filters to their prior state
	for my $newMF (@newMFList) {
	    $matchFilters->remove($newMF, EQUAL);
	}
	return undef;
    }
    # Make necessary node modifications
    my $pending = $request ? $request->id : undef;
    for my $node (@nodeModList) {
	lock $node;
	my $mfMod = shift @mfModList;
	my $mf = $node->getMatch();
	$mf->auxData($mfMod->auxData);
	my $nodeAux = $node->getReference();
	$nodeAux or do {
	    $nodeAux = _MFAUX->new();
	    $node->setReference($nodeAux);
	};
	$nodeAux->addCallback($cbRef);
	$node->pending($pending);
    }
    return $self->_requestResult($request, $absTimeout, 1);
}

sub _removeMatchFilters {
    my $self = shift;
    my $absTimeout = shift;
    my $cbRef = (@_ && blessed $_[0] && $_[0]->isa(_CALLBACK) ? shift : $self->_noopCB);

    my $matchFilters = $self->_matchFilters;
    my $request;
    my @mfReqList = ();   # match filters to be included in a controller request
    my @nodeModList = (); # match-list nodes needing modification
    my $failed = 0;

    MF: for my $mf (@_) {
	my $nodeList = $matchFilters->find($mf, EQUAL);
        NODE: for (@$nodeList) {
	    my $node = $_; # !!! BUG? this works; lock fails withour prior reference to element !!!
	    lock $node;
	    my $nodeAux = $node->getReference() || _MFAUX->new();
	    next NODE unless $nodeAux->hasCallback($cbRef); # no change to this node
	    push @mfReqList, $mf if $nodeAux->numCallbacks() == 1;
	    $self->_log("removeMatchFilters: holding for pending request", DEBUG) if $node->pending;
	    $node->waitForPendingUntil($absTimeout) or do {
		$self->_log("removeMatchFilters: timed out waiting for pending request", ERROR);
		$failed = 1;
		last MF;
	    };
	    $node->pending(-1); # pre-request hold
	    push @nodeModList, $node;
	}
    }
    # Make a controller request if necessary
    if (@mfReqList && ! $failed) {
	my $replyCB = $self->newCallback("_matchFilterReply", "RemoveMatchFilters", @nodeModList);
	$request = $self->_sendRemoveFilterRequest($replyCB, @mfReqList) or $failed = 1;
    }
    # Make necessary node modifications
    my $pending = $request ? $request->id : undef;
    for my $node (@nodeModList) {
	my $mf;
	{
	    lock $node;
	    unless ($failed) {
		my $nodeAux = $node->getReference() || _MFAUX->new();
		$nodeAux->removeCallback($cbRef) or do {
		    # No more callbacks; filter will be removed
		    $mf = $node->getMatch();
		};
	    }
	    $node->pending($pending);
	}
	$matchFilters->remove($mf, EQUAL) if $mf;
    }
    return $failed ? undef : $self->_requestResult($request, $absTimeout, 1);
}

sub _matchFilterReply {
    my $request = shift;
    my $reqType = shift;

    my $ctx = $request->ctlCtx;
    my $requestID = $request->id;
    for my $node (@_) {
	lock $node;
	my $pending = $node->pending or next;
	$node->pending(undef) if $pending == $requestID;
    }
    $ctx->_log("$reqType request $requestID failed on controller", WARN) unless $request->replyValue;
    return 1;
}

sub _sendAddFilterRequest {
    my $self = shift;
    my $replyCB = shift;

    return $self->_sendFilterRequest($replyCB, "AddMatchFilters", @_);
}

sub _sendRemoveFilterRequest {
    my $self = shift;
    my $replyCB = shift;

    return $self->_sendFilterRequest($replyCB, "RemoveMatchFilters", @_);
}

sub _sendFilterRequest {
    my $self = shift;
    my $replyCB = shift;
    my $reqType = shift;

    my $filters = &share([]);
    for (@_) {
	push @$filters, $_;
    }
    return $self->_sendCtlServiceRequest($replyCB, $reqType, undef, $filters);
}

sub _disableReceiveARPReplies {
    my $self = shift;
    my $absTimeout = shift;

    my $arpRegMap = $self->_arpRegMap;
    lock $arpRegMap;

    return 1 unless keys %$arpRegMap;

    my $arpMatch = $arpRegMap->{_ARP_MATCH()};
    my $arpMatchCB = $arpRegMap->{_ARP_MATCH_CB()};
    my $arpMsgCB = $arpRegMap->{_ARP_MSG_CB()};
    # If the following requests are made asynchronously (defined $absTimeout),
    # their success/failure may not be known until later, and there's little
    # to be done about it at that point, so as long as they don't immediately fail,
    # we assume success.
    $self->_removeMatchFilters($absTimeout, $arpMatchCB, $arpMatch) or return undef;
    $self->_ignoreMessage($absTimeout, $arpMsgCB, OF->PACKET_IN) or return undef;

    return 1;
}

sub _enableReceiveARPReplies {
    my $self = shift;
    my $absTimeout = shift;

    my $arpRegMap = $self->_arpRegMap;
    lock $arpRegMap;

    return 1 if keys %$arpRegMap;

    my $arpMatch = newNBOFMatch({
	dataLayerType => DL_TYPE_ARP(),
	dataLayerDestination => $self->arpSenderMAC
        });
    my $arpMatchCB = $self->newCallback('_receiveARP', $arpMatch);
    my $arpMsgCB = $self->newCallback('_noop');
    # If the following requests are made asynchronously (defined $absTimeout),
    # their success/failure may not be known until later, and there's little
    # to be done about it at that point, so as long as they don't immediately fail,
    # we assume success.
    $self->_addMatchFilters($absTimeout, $arpMatchCB, $arpMatch) or return undef;
    $self->_receiveMessage($absTimeout, $arpMsgCB, OF->PACKET_IN) or return undef;

    $arpRegMap->{_ARP_MATCH()} = $arpMatch;
    $arpRegMap->{_ARP_MATCH_CB()} = $arpMatchCB;
    $arpRegMap->{_ARP_MSG_CB()} = $arpMsgCB;

    return 1;
}

sub _ipAddrInfoReply {
    my $request = shift or return undef;
    my $ipV4Addr = shift;

    my $replyValue = $request->replyValue or return undef;
    my $ctx = $request->ctlCtx;
    for my $map (@$replyValue) {
	$ctx->_updateAddressCaches(
	    $map->{dpid},
	    $map->{switchPort},
	    $map->{macAddr},
	    $ipV4Addr,
	    $map->{age}
	    );
    }
    return 1;
}

sub _macAddrInfoReply {
    my $request = shift or return undef;
    my $macAddr = shift;
    my $dpid = shift;

    my $switchPort = $request->replyValue or return undef;
    my $ctx = $request->ctlCtx;
    $ctx->_updateAddressCaches($dpid, $switchPort, $macAddr);
    return 1;
}

sub _spcnReply {
    my $request = shift or return undef;

    my $map = $request->replyValue or return undef;
    my $ctx = $request->ctlCtx;
    if ($map->{switchPort} != OFPP->OFPP_NONE) {
	$ctx->_updateAddressCaches($map->{dpid}, $map->{switchPort}, $map->{macAddr});
    }
    return 1;
}

sub _lastARPTime {
    my $self = shift;
    my $ipV4Addr = shift;
    my $dpid = shift;
    my $reqPort = shift;
    my $exclPort = shift;

    defined $dpid or return (undef, 0);

    my $lastARPTime = 0; # assume 'never'
    my $arpTimeMap = $self->_arpTimeMap;
    my $dpidEntry;
    {
	lock $arpTimeMap;
	$dpidEntry = $arpTimeMap->{$dpid};
    }
    if ($dpidEntry) {
	lock $dpidEntry;
	my @portList = $self->_getARPPortList($dpid, $reqPort, $exclPort);
	if (@portList) {
	    $lastARPTime = time();
	    for my $port (@portList) {
		my $portEntry = $dpidEntry->{$port} or do {
		    $lastARPTime = 0;
		    last;
		};
		my $portTime = $portEntry->{$ipV4Addr} or do {
		    $lastARPTime = 0;
		    last;
		};
		$lastARPTime = $portTime if $portTime < $lastARPTime;
	    }
	}
    }
    return ($reqPort, $lastARPTime);
}

sub _lastMACReqTime {
    my $self = shift;
    my $macAddr = shift;
    my $dpid = shift;

    defined $dpid or return 0;

    my $lastReqTime = 0; # assume 'never'
    my $macReqTimeMap = $self->_macReqTimeMap;
    my $dpidEntry;
    {
	lock $macReqTimeMap;
	$dpidEntry = $macReqTimeMap->{$dpid};
    }
    if ($dpidEntry) {
	lock $dpidEntry;
	my $macEntry = $dpidEntry->{$macAddr};
	$lastReqTime = $macEntry if defined $macEntry;
    }
    return $lastReqTime;
}

sub _sendARPRequest {
    my $self = shift;
    my ($ipV4Addr, $_mask) = parseIPv4(shift);
    my $dpid = shift or return undef;
    my $arpPort = shift;
    my $exclPort = shift;

    my $dpidStr = dpidToString($dpid);
    if (defined $arpPort) {
	if ($arpPort < 1 || $arpPort > OFPortPB->OFPP_MAX) {
	    carp "Invalid switch port ($arpPort) for ARP request";
	    return undef;
	}
	$exclPort = undef;
    }
    else {
	$arpPort = OFPortPB->OFPP_ALL;
    }
    if (defined $exclPort) {
	if ($exclPort < 1 || $exclPort > OFPortPB->OFPP_MAX) {
	    carp "Invalid exclusion port ($exclPort) for ARP request";
	    return undef;
	}
    }
    else {
	$exclPort = OFPortPB->OFPP_NONE;
    }
    my $addr = uint32ToIPv4($ipV4Addr);
    my $arpRequest = genARPRequest($ipV4Addr, $self->arpSenderIP, $self->arpSenderMAC) or do {
	$self->_log("failed to generate ARP request for $addr", ERROR);
	return undef;
    };
    my $actions = newOFActionList(
	newOFAction(OF_ACTION->OUTPUT, {
	    port => $arpPort
	    })
	);
    my $packetOut = newOFMessage(OF->PACKET_OUT, {
	inPort => $exclPort,
	actions => $actions,
	packetData => $arpRequest
        });
    my $outPort = "$arpPort";
    $outPort .= " (excl. $exclPort)" if $exclPort <= OFPortPB->OFPP_MAX;
    if ($self->sendOFMessage($packetOut, $dpid)) {
	$self->_log("sending ARP request to $addr on datapath $dpidStr port $outPort", DEBUG);
    }
    else {
	$self->_log("failed to send ARP request to $addr on datapath $dpidStr port $outPort", ERROR);
	return undef;
    }
    return 1;
}

sub _updateARPTime {
    my $self = shift;
    my $arpTime = shift;
    my $ipV4Addr = shift;
    my $dpid = shift;
    my $reqPort = shift;
    my $exclPort = shift;

    defined $dpid or return 0;

    my $arpTimeMap = $self->_arpTimeMap;
    my $dpidEntry;
    {
	lock $arpTimeMap;
	$dpidEntry = $arpTimeMap->{$dpid} or do {
	    $dpidEntry = $arpTimeMap->{$dpid} = &share({});
	};
    }
    lock $dpidEntry;
    my @portList = $self->_getARPPortList($dpid, $reqPort, $exclPort);
    for my $port (@portList) {
	my $portEntry = $dpidEntry->{$port};
	$portEntry = $dpidEntry->{$port} = &share({}) unless $portEntry;
	$portEntry->{$ipV4Addr} = $arpTime;
    }
    return 1;
}

sub _updateMACReqTime {
    my $self = shift;
    my $reqTime = shift;
    my $macAddr = shift;
    my $dpid = shift;

    defined $dpid or return 0;

    my $macReqTimeMap = $self->_macReqTimeMap;
    my $dpidEntry;
    {
	lock $macReqTimeMap;
	$dpidEntry = $macReqTimeMap->{$dpid} or do {
	    $dpidEntry = $macReqTimeMap->{$dpid} = &share({});
	};
    }
    lock $dpidEntry;
    $dpidEntry->{$macAddr} = $reqTime;
    return 1;
}

sub _getARPPortList {
    my $self = shift;
    my $dpid = shift;
    my $reqPort = shift;
    my $exclPort = shift;

    my @portList = ();
    if (defined $reqPort) {
	push @portList, $reqPort;
    }
    else {
	my $ports = $self->getDatapathPorts($dpid) || [];
	for my $portPB (@$ports) {
	    my $port = $portPB->portNumber;
	    push @portList, $port unless defined $exclPort && $port == $exclPort;
	}
    }
    return @portList;
}

sub _receiveARP {
    my $msgEvent = shift;
    my $arpMatch = shift;

    my $ctx = $msgEvent->{ctlCtx};
    my $pbMsg = $msgEvent->{pbMsg};
    my $ofMsg = pbGetMessage($pbMsg);
    my $ofMatch = $ofMsg->ofMessage->ofPacketIn->ofMatch;
    my $ipV4Addr = $ofMatch->networkSource or return 0;
    my $mac = $ofMatch->dataLayerSource;
    my $port = $ofMatch->inputPort;
    $ctx->_updateAddressCaches($ofMsg->datapathID, $port, $mac, $ipV4Addr);
    return 1;
}

sub _synchMessages {
    my $self = shift;
    my $absTimeout = shift;
    my $datapathID = shift;

    my $value = newValue("anInt64", $datapathID);
    my $request = $self->_sendCtlServiceRequest(undef, "SynchMessages", $value) or return undef;
    return $self->_requestResult($request, $absTimeout);
}

sub _switchStatus {
    my $self = shift;
    my $absTimeout = shift;

    my $lockRef = $self->_switchStatusLockRef;
    {
	lock $lockRef;
	if ($self->_switchStatusLocked) {
	    $self->_log("switchStatus: holding for pending request", DEBUG);
	    $self->_waitForSwitchStatusLock($absTimeout) or do {
		$self->_log("switchStatus: timed out waiting for pending request", DEBUG);
		return undef;
	    };
	}
	$self->_switchStatusLocked(1);
    }

    my $actual = $self->_switchTrackActual;
    if (@_) {
	my $level = shift;
	if ($level < SWITCH_NONE || $level > SWITCH_PORT) {
	    carp "switchStatus: invalid tracking level $level";
	    $self->_switchStatusLocked(0);
	    return $actual;
	}
	$self->_switchTrackTarget($level);
    }
    else {
	$self->_switchStatusLocked(0);
	return $actual;
    }

    my $target = $self->_switchTrackTarget;
    if ($actual == $target) {
	$self->_switchStatusLocked(0);
	return $actual;
    }

    if ($self->isConnected) {
	$self->_sendSwitchStatus($absTimeout, $target) or do {
	    $self->_log("switchStatus: controller request failed", ERROR);
	    $self->_switchStatusLocked(0);
	};
    }
    else {
	$self->_log("switchStatus: controller request pending", TRACE);
	$self->_switchStatusLocked(0);
    }

    return $self->_switchTrackActual;
}

sub _sendSwitchStatus {
    my $self = shift;
    my $absTimeout = shift;
    my $level = shift || SWITCH_NONE;

    my @statusTypes = ();
    push @statusTypes, (_SWITCH_PB->ADDED, _SWITCH_PB->REMOVED) if ($level >= SWITCH_SWITCH && $level <= SWITCH_PORT);
    push @statusTypes, (_SWITCH_PB->PORT_CHANGED) if ($level == SWITCH_PORT);

    my $replyCB = $self->newCallback("_switchStatusReply", $level);
    my $value = newValue("byteArray", pack('C*', @statusTypes));
    my $request = $self->_sendCtlServiceRequest($replyCB, "SwitchStatus", $value) or return undef;
    return $self->_requestResult($request, $absTimeout);
}

sub _switchStatusReply {
    my $request = shift;
    my $newLevel = shift;

    my $newLabel = SWITCH_TRACK->{$newLevel};
    my $ctx = $request->ctlCtx;
    unless ($request->replyValue) {
	$ctx->_log("switchStatus: request to set notification level '$newLabel' failed", ERROR);
	return undef;
    }

    my $oldLevel;
    my $lockRef = $ctx->_switchStatusLockRef;
    {
	lock $lockRef;
	$oldLevel = $ctx->_switchTrackActual;
	$ctx->_switchTrackActual($newLevel);
	$ctx->_switchTrackTarget($newLevel);
	$ctx->_switchStatusLocked(0);
    }
    my $oldLabel = SWITCH_TRACK->{$oldLevel};
    my $msg = "switchStatus notification: current = '$newLabel'; previous = '$oldLabel'";
    $ctx->_log($msg, INFO);
    return 1;
}

sub _setCtlCapabilities {
    my $self = shift;
    my $capList = shift or return 0;

    my $map = $self->_ctlCapMap;
    lock $map;
    for my $cap (@$capList) {
	$map->{$cap} = 1;
    }
    return scalar(@$capList);
}

sub _resetCtlCapabilities {
    my $self = shift;
    my $map = $self->_ctlCapMap;
    lock $map;
    %$map = ();
}

sub _setCtlExtensions {
    my $self = shift;
    my $extList = shift or return 0;

    my $numExt = 0;
    my $map = $self->_ctlExtMap;
    lock $map;
    for my $ext (@$extList) {
	$map->{$ext} = 1;
    }
    return $numExt;
}

sub _extModule {
    my $self = shift;
    my $ext = shift;

    return _EXTCTL . "::$ext";
}

sub _resetCtlExtensions {
    my $self = shift;
    my $map = $self->_ctlExtMap;
    lock $map;
    %$map = ();
}

sub _sendCtlServiceRequest {
    my $self = shift;
    my $replyCB = shift;
    my $reqType = shift or return undef;
    my $value = shift;
    my $matchFilters = shift;

    $self->isConnected() or do {
	$self->_log("sendCtlServiceRequest: no controller connection", ERROR);
	return undef;
    };

    $self->hasCtlCapability($reqType) or do {
	carp "Unsupported CtlService function: " . $reqType;
	return undef;
    };

    my $ctlMsg = &share(NBCtlServicePB->new());
    my $req = &share(FunctionRequestPB->new());
    $req->requestType(shared_clone($reqType));
    $req->value(shared_clone($value)) if $value;
    $req->matchFilter(shared_clone($matchFilters)) if $matchFilters;
    my $ctlType :shared = NBCtlServicePB::ServiceMsgType->FunctionRequest;
    $ctlMsg->msgType($ctlType);
    $ctlMsg->functionRequest($req);
    my $replyValueType = _CTL_FN->{$reqType}->{"reply"};

    return $self->_sendRequest($ctlMsg, "sendCtlServiceMsg", $replyValueType, "CtlService", $replyCB);
}

sub _sendExtensionRequest {
    my $self = shift;
    my $replyCB = shift;
    my $extMsg = shift or return undef;
    my $hasReplyValue = shift;
    my $persistenceCheck = shift;

    $self->isConnected() or do {
	$self->_log("sendExtensionRequest: no controller connection", ERROR);
	return undef;
    };

    my $extType = $extMsg->extensionType;
    $self->hasCtlExtension($extType) or do {
	carp "Unsupported controller extension $extType";
	return undef;
    };

    return $self->_sendRequest($extMsg, "sendExtensionMsg", $hasReplyValue, "$extType extension", $replyCB, $persistenceCheck);
}

sub _getRequest {
    my $self = shift;
    my $requestID = shift;

    my $requests = $self->_requests;
    lock $requests;
    return $requests->{$requestID};
}

sub _deleteRequest {
    my $self = shift;
    my $requestID = shift;

    my $requests = $self->_requests;
    lock $requests;
    delete $requests->{$requestID};
}

sub _sendRequest {
    my $self = shift;
    my $reqMsg = shift;
    my $protoSender = shift;
    my $replyValueType = shift;
    my $type = shift || "unspecified";
    my $replyCB = shift;
    my $persistenceCheck = shift;

    $self->_log("sending $type request", DEBUG);

    # Issuing and recording a request must be an atomic operation
    my $requests = $self->_requests;
    lock $requests;

    # Send the request message
    my $requestID = $self->{_protoEngine}->$protoSender($reqMsg) or do {
	$self->_log("failed to send $type request", ERROR);
	return undef;
    };

    # Create a request/reply object for the request
    my $request = $self->_newRequest();
    $request->_id($requestID);
    $request->_requestMessage($reqMsg);

    # Track the request
    my $reqInfo = _REQINFO->new();
    $reqInfo->persistenceCheck($persistenceCheck);
    $reqInfo->request($request);
    $reqInfo->replyCB($replyCB);
    $reqInfo->replyValueType($replyValueType);
    $requests->{$requestID} = $reqInfo;

    return $request;
}

sub _resetWelcome {
    my $self = shift;

    return $self->_setWelcome(0);
}

sub _switchStatusLocked {
    my $self = shift;

    my $lockRef = $self->_switchStatusLockRef;
    lock $lockRef;
    if (@_) {
	$$lockRef = shift;
	cond_broadcast $lockRef;
    }
    return $$lockRef;
}

sub _waitForSwitchStatusLock {
    my $self = shift;
    my $absTimeout = shift;

    my $lockRef = $self->_switchStatusLockRef;
    {
	lock $lockRef;
	while ($$lockRef) {
	    if (defined $absTimeout) {
		cond_timedwait $lockRef, $absTimeout or return 0;
	    }
	    else {
		cond_wait $lockRef;
	    }
	}
    }
    return 1;
}

sub _setWelcome {
    my $self = shift;
    my $value = shift;

    my $welcomeRef = $self->_welcomeRef;
    {
	lock $welcomeRef;
	$$welcomeRef = $value;
	cond_broadcast $welcomeRef;
    }
    return $value;
}

sub _waitForWelcome {
    my $self = shift;

    $self->_log("waiting for controller welcome message", DEBUG);
    my $welcomeRef = $self->_welcomeRef;
    my $welcomeMsg;
    {
	lock $welcomeRef;
	cond_wait $welcomeRef until $$welcomeRef;
	$welcomeMsg = $$welcomeRef;
    }
    $self->_log("controller welcome message received", DEBUG);
    return $welcomeMsg;
}

sub _getLocalAddrInfo {
    my $self = shift;
    my $addrCache = shift;
    my $searchAddr = shift;
    my $dpid = shift;
    my $reqPort = shift;
    my $exclPort = shift;

    my $returnInfoList = &share([]);
    lock $addrCache;
    my @addrList = ();
    if (defined $searchAddr) {
	push @addrList, $searchAddr;
    }
    else {
	push @addrList, sort keys %$addrCache;
    }
    for my $addr (@addrList) {
	my $oldInfoList = $addrCache->{$addr} or next;
	my $newInfoList = &share([]);
	my @matchList = ();
	for my $info (@$oldInfoList) {
	    next if $info->expired;
	    push @$newInfoList, $info;
	    next if defined $dpid && $info->datapathID != $dpid;
	    next if defined $reqPort && $info->port != $reqPort;
	    next if defined $exclPort && $info->port == $exclPort;
	    push @matchList, $info;
	}
	$addrCache->{$addr} = $newInfoList;
	my @sorted = sort { $b->timestamp <=> $a->timestamp } @matchList;
	if (defined $searchAddr) {
	    # return all information
	    push @$returnInfoList, @sorted;
	}
	else {
	    # return only the latest information
	    push @$returnInfoList, $sorted[0] if @sorted;
	}
    }
    return $returnInfoList;
}

sub _getLocalIPAddrInfo {
    my $self = shift;

    my $infoList = $self->_getLocalAddrInfo($self->_ipAddrCache, @_);
    return $infoList;
}

sub _getLocalMACAddrInfo {
    my $self = shift;

    my $infoList = $self->_getLocalAddrInfo($self->_macAddrCache, @_);
    return $infoList;
}

sub _updateAddressCaches {
    my $self = shift;
    my $dpid = shift;
    my $port = shift;
    my $mac = lc shift;
    my ($ipV4Addr, $_mask) = parseIPv4(shift);
    my $ageMS = shift || 0;

    # IP updates require valid port, MAC, and IP address.
    # MAC updates require valid port and MAC.

    return 0 unless isValidHostSwitchPort($port);
    return 0 unless isValidHostMAC($mac);
    $ipV4Addr = undef unless isValidHostIP($ipV4Addr);
    my $ttlMS = $self->addrCacheTTL * 1000;

    my $newInfo = _ADDRINFO->new();
    $newInfo->expiration($ttlMS > 0 ? time() + int($ttlMS / 1000) : 0);
    $newInfo->ipV4Addr($ipV4Addr);
    $newInfo->ctlCtx($self);
    $newInfo->datapathID($dpid);
    $newInfo->port($port);
    $newInfo->macAddr($mac);
    $newInfo->timestamp(timeMS() - $ageMS);

    my $updated = 0;
    $updated += $self->_updateIPAddrCache($newInfo) if defined $ipV4Addr;
    $updated += $self->_updateMACAddrCache($newInfo);
    return $updated;
}

sub _updateIPAddrCache {
    my $self = shift;
    my $addrInfo = shift or return 0;

    my $ipStr = $addrInfo->ipV4AddrStr;
    my $ipV4Addr = $addrInfo->ipV4Addr;
    my $dpid = $addrInfo->datapathID;
    my $dpidStr = dpidToString($dpid);
    my $port = $addrInfo->port;
    my $macStr = $addrInfo->macAddrStr;
    $self->_log("updating $ipStr ($ipV4Addr) in address cache: datapathID $dpidStr; port $port; MAC $macStr", DEBUG);
    return $self->_updateAddrCache($self->_ipAddrCache, $ipV4Addr, $addrInfo, "_notifyIPAddrInfo");
}

sub _updateMACAddrCache {
    my $self = shift;
    my $addrInfo = shift or return 0;

    my $ipStr = $addrInfo->ipV4AddrStr || "<undef>";
    my $dpid = $addrInfo->datapathID;
    my $dpidStr = dpidToString($dpid);
    my $port = $addrInfo->port;
    my $macAddr = $addrInfo->macAddr;
    my $macStr = $addrInfo->macAddrStr;
    $self->_log("updating $macStr ($macAddr) in address cache: datapathID $dpidStr; port $port; IP $ipStr", DEBUG);
    return $self->_updateAddrCache($self->_macAddrCache, $macAddr, $addrInfo, "_notifyMACAddrInfo");
}

sub _updateAddrCache {
    my $self = shift;
    my $addrCache = shift;
    my $key = shift;
    my $newInfo = shift;
    my $notifier = shift;

    my $mostRecentInfo = undef;
    {
	lock $addrCache;
	my $oldInfoList = $addrCache->{$key} || [];
	my $newInfoList = &share([]);
	push @$newInfoList, $newInfo;
	for my $info (@$oldInfoList) {
	    if ($mostRecentInfo) {
		$mostRecentInfo = $info if $info->timestamp > $mostRecentInfo->timestamp;
	    }
	    else {
		$mostRecentInfo = $info;
	    }
	    next if $info->expired;
	    if ($info->equals($newInfo)) {
		$newInfo->expiration($info->expiration) if $info->expiration > $newInfo->expiration;
		next;
	    }
	    push @$newInfoList, $info;
	}
	$addrCache->{$key} = $newInfoList;
	cond_broadcast $addrCache;
    }

    if ($notifier) {
	# Check whether the info has changed from the most recent info
	# and, if so, notify any registered callbacks.
	unless ($newInfo->equals($mostRecentInfo)) {
	    my $mostRecentTS = $mostRecentInfo ? $mostRecentInfo->timestamp : 0;
	    if ($newInfo->timestamp > $mostRecentTS) {
		$self->$notifier($newInfo);
	    }
	}
    }

    return 1;
}

sub _startPBQueueMonitor {
    my $self = shift;

    my $thread = threads->create('_monitorPBQueueIn', $self) or return 0;
    $thread->detach();
    return 1;
}

sub _monitorPBQueueIn {
    my $self = shift;

    $self->_log("queue monitor thread started", TRACE);
    until ($self->{_protoEngine}->isTerminated()) {
	my $pbIn = $self->{_pbIn};
	lock $pbIn;
	$self->_log("waiting for queue or status event", VERBOSE);
	cond_wait $pbIn until ($pbIn->peek() || $self->{_protoEngine}->isTerminated());
	$self->_log("processing queue or status event", VERBOSE);
	$self->_processPBMsgIn($pbIn->dequeue()) if $pbIn->peek();
    }
    $self->_notifyClientMsgQueue();
    $self->_log("queue monitor thread terminated", TRACE);
    return 1;
}

sub _notifyClientMsgQueue {
    my $self = shift;
    my $msgQueue = $self->_clientMsgQueue or return;
    lock $msgQueue;
    cond_broadcast $msgQueue;
}

sub _processPBMsgIn {
    my $self = shift;
    my $pbMsg = shift or return 0;

    my $type = pbMessageType($pbMsg);
    my $subtype = pbMessageSubtype($pbMsg);
    $self->_log("received message type $type($subtype)", DEBUG);

    $type == PB_OF_TYPE and return $self->_processOFMsgIn($pbMsg);
    $type == PB_CTL_TYPE and return $self->_processCtlMsgIn($pbMsg);
    $type == PB_INT_TYPE and return $self->_processIntMsgIn($pbMsg);
    $type == PB_EXT_TYPE and return $self->_processExtMsgIn($pbMsg);

    $self->_log("unknown message type: $type", ERROR);
    return 0;
}

sub _processOFMsgIn {
    my $self = shift;
    my $pbMsg = shift;
    my $ofType = pbMessageSubtype($pbMsg);

    return $self->_processSwitchStatus($pbMsg) if $ofType == OF->SWITCH_STATUS;

    my @cbList = ();

    {
	my $rmt = $self->_receiveMessageTypes;
	lock $rmt;
	if (my $refs = $rmt->{$ofType}->refList) {
	    push @cbList, @{$refs->getList()};
	}
    }

    if ($ofType == OF->PACKET_IN) {
	my $ofMsg = pbGetMessage($pbMsg);
	my $pktIn = $ofMsg->ofMessage->ofPacketIn;
	$self->_trackHost($ofMsg->datapathID, $pktIn) if $self->_hostTrackTarget != HOSTS_NONE;
	my $nbOFMatch = newNBOFMatch($pktIn->ofMatch, $ofMsg->datapathID, $pktIn->reason);
	my $matchFilters = $self->_matchFilters;
	lock $matchFilters;
	for my $aux (@{$matchFilters->getReferences($nbOFMatch, WIDER)}) {
	    push @cbList, @{$aux->getCallbacks()};
	}
    }

    if (@cbList) {
	my $msgEvent = _MSGEVENT->new();
	$msgEvent->{ctlCtx} = $self;
	$msgEvent->{pbMsg} = $pbMsg;
	for my $cbRef (sort _byPriority @cbList) {
	    my $cbName = $cbRef->name;
	    my @cbArgs = ($msgEvent);
	    push @cbArgs, @{$cbRef->args} if $cbRef->args;
	    $self->_log("OFMessage callback: $cbName", DEBUG);
	    eval {
		no strict 'refs';
		&$cbName(@cbArgs);
	    };
	    $self->_log($@, ERROR) if $@;
	}
    }

    return 1;
}

sub _processCtlMsgIn {
    my $self = shift;
    my $pbMsg = shift;
    return $self->_processReply($pbMsg, pbGetMessage($pbMsg)->requestID);
}

sub _processIntMsgIn {
    my $self = shift;
    my $pbMsg = shift;

    my $intType = pbMessageSubtype($pbMsg);

    if ($intType == PB_INT->Welcome) {
	my $welcomeMsg = pbGetMessage($pbMsg)->welcomeMessage;
	$self->_setWelcome($welcomeMsg);
    }
    elsif ($intType == PB_INT->Ping) {
	my $pingMsg = pbGetMessage($pbMsg)->pingMessage;
	if ($pingMsg->pingType == PingMessagePB::PingType->PING_REPLY) {
	    return $self->_processReply($pbMsg, $pingMsg->requestID);
	}
    }

    return 1;
}

sub _processExtMsgIn {
    my $self = shift;
    my $pbMsg = shift;
    return $self->_processReply($pbMsg, pbGetMessage($pbMsg)->requestID);
}

sub _processReply {
    my $self = shift;
    my $pbMsg = shift;
    my $requestID = shift;

    my $reqInfo = $self->_getRequest($requestID) or do {
	$self->_log("received reply for untracked request $requestID", TRACE);
	return $self->_pbPassThrough($pbMsg);
    };

    my $replyCB;
    my $request;
    my $replyValueType;
    my $persistenceCheck;
    {
	lock $reqInfo;
	$replyCB = $reqInfo->replyCB;
	$request = $reqInfo->request;
	$replyValueType = $reqInfo->replyValueType;
	$persistenceCheck = $reqInfo->persistenceCheck;
    }

    # Update the request with reply message and return value (if any).
    # Note: the reply callback (if any) may depend on this having been done.
    my $persistent = 0;
    {
	lock $request;
	$request->_replyMessage($pbMsg);
	my $replyValue = undef;
	my $errorStatusReply = errorStatus($pbMsg);
	if ($replyValueType) {
	    my $reply = pbGetMessage($pbMsg);
	    my $msgType = pbMessageType($pbMsg);
	    if ($msgType == PB_CTL_TYPE) {
		if (my $fnReply = $reply->functionReply) {
		    if (my $value = $fnReply->value) {
			$replyValue = extractValue($value, $replyValueType);
		    }
		}
	    }
	    elsif ($msgType == PB_EXT_TYPE) {
		$replyValue = getExtensionValue($reply);
	    }
	    else {
		$self->_log("unexpected reply message type $msgType for request $requestID", ERROR);
	    }
	    # Some request types (e.g., ControllerSupport.SwPortChangeNotify)
	    # may continue to return replies; if so, they must provide a
	    # persistence-check function to determine from the reply whether or not
	    # further replies are possible.
	    if ($persistenceCheck) {
		loadModule($persistenceCheck);
		eval {
		    $persistent = $persistenceCheck->persistenceCheck($reply);
		};
		$self->_log("error in persistence check: $@", ERROR) if $@;
	    }
	}
	else {
	    # Indicate success for successful requests that return no value
	    $replyValue = 1 unless $errorStatusReply;
	}
	$request->_replyValue($replyValue);
	if ($errorStatusReply) {
	    if (my $msg = statusReplyMessage($errorStatusReply)) {
		$self->_log("request $requestID returned error message: $msg", ERROR);
	    }
	}
    }

    # Execute reply callback, if any
    if ($replyCB) {
	my $cbName = $replyCB->name;
	my @cbArgs = ($request);
	push @cbArgs, @{$replyCB->args} if $replyCB->args;
	$self->_log("reply callback for request ID $requestID: $cbName", DEBUG);
	eval {
	    no strict 'refs';
	    &$cbName(@cbArgs);
	};
	$self->_log($@, ERROR) if $@;
    }
    
    # Remove and mark non-persistent requests as completed.
    # This is done last to ensure dependencies are satisfied;
    # for example, any thread waiting for request completion may also
    # depend on the completion of the reply callback.
    unless ($persistent) {
	$request->_completed(1);
	$self->_deleteRequest($requestID);
    }

    return 1;
}

sub _processSwitchStatus {
    my $self = shift;
    my $pbMsg = shift;

    if ($self->_switchTrackTarget > SWITCH_NONE) {
	my $sbOFMsg = pbGetMessage($pbMsg);
	my $dpid = $sbOFMsg->datapathID;
	my $ssMsg = $sbOFMsg->ofMessage->ofSwitchStatus;
	$self->_updateSwitchStatus($dpid, $ssMsg);
    }

    my @cbList = ();
    push @cbList, @{$self->_switchStatusCallbacks->getList()};
    if (@cbList) {
	my $msgEvent = _MSGEVENT->new();
	$msgEvent->{ctlCtx} = $self;
	$msgEvent->{pbMsg} = $pbMsg;
	for my $cbRef (sort _byPriority @cbList) {
	    my $cbName = $cbRef->name;
	    my @cbArgs = ($msgEvent);
	    push @cbArgs, @{$cbRef->args} if $cbRef->args;
	    $self->_log("SwitchStatus callback: $cbName", DEBUG);
	    eval {
		no strict 'refs';
		&$cbName(@cbArgs);
	    };
	    $self->_log($@, ERROR) if $@;
	}
    }

    return 0;
}

sub _trackHost {
    my $self = shift;
    my $dpid = shift;
    my $pktIn = shift;

    my $ofMatch = $pktIn->ofMatch;
#    my $dlType = $ofMatch->dataLayerType;
#    return 0 unless $dlType == DL_TYPE_IPV4 || $dlType == DL_TYPE_ARP;

    my $ipV4Addr = $ofMatch->networkSource;
    my $macAddr = $ofMatch->dataLayerSource;
    my $switchPort = $ofMatch->inputPort;
    return $self->_updateAddressCaches($dpid, $switchPort, $macAddr, $ipV4Addr);
}

sub _updateSwitchStatus {
    my $self = shift;
    my $dpid = shift;
    defined $dpid or return undef;
    my $ssMsg = shift;
    my $persistent = shift;

    my $dpidStr = dpidToString($dpid);
    my $retval = 1;
    my $logMsg;
    my $logLevel = TRACE;
    my $ssMap = $self->_switchStatusMap;
    {
	lock $ssMap;

	my $ssEntry = $ssMap->{$dpid};
	$ssEntry or do {
	    $ssEntry = _SWITCHSTATUS->new();
	    $ssMap->{$dpid} = $ssEntry;
	};

	$ssEntry->persistent($persistent) if defined $persistent;
	$ssEntry->status($ssMsg->status) if defined $ssMsg;
	$ssEntry->lastUpdated(time());

	$persistent = $ssEntry->persistent;
	my $status = $ssEntry->status;
	defined $status or $status = _SWITCH_PB->REMOVED;
	if ($status == _SWITCH_PB->REMOVED && ! $persistent) {
	    delete $ssMap->{$dpid};
	    $logMsg = "Datapath ID $dpidStr removed";
	    $retval = 0;
	}
	else {
	    if (defined $ssMsg) {
		# Update port status
		my $portMap = $ssEntry->portMap;
		my $ports = $ssMsg->ports;
		my $portChange = $ssMsg->portChangeType;
		defined $portChange or $portChange = _PORT_PB->ADD;
		for my $port (@$ports) {
		    my $portNumber = $port->portNumber;
		    if ($portChange == _PORT_PB->DELETE) {
			delete $portMap->{$portNumber};
		    }
		    else {
			$portMap->{$portNumber} = $port;
		    }
		}
	    }
	    my $numPorts = scalar keys %{$ssEntry->portMap};
	    $logMsg = "Datapath ID $dpidStr updated: status=$status, persistent=$persistent; numPorts=$numPorts";
	}
	cond_broadcast $ssMap;
    }
    $self->_log($logMsg, $logLevel) if $logMsg;
    return $retval;
}

sub _passThrough {
    my $msgEvent = shift or return 0;

    my $ctx = $msgEvent->{ctlCtx};
    my $pbMsg = $msgEvent->{pbMsg};
    return $ctx->_pbPassThrough($pbMsg);
}

sub _pbPassThrough {
    my $self = shift;
    my $pbMsg = shift or return 0;

    my $msgQueue = $self->_clientMsgQueue or do {
	$self->_log("_pbPassThrough: no client message queue", VERBOSE);
	return 0;
    };
    $msgQueue->enqueue($pbMsg);
    return 1;
}

sub _isValidOFType {
    my $self = shift;

    defined(my $type = shift) or return 0;
    return ($type >= 0 && $type <= 255);
}

sub _sendReceiveMessage {
    my $self = shift;
    my $replyCB = shift;

    return $self->_sendCtlRequestOF($replyCB, "ReceiveMessage", @_);
}

sub _sendIgnoreMessage {
    my $self = shift;
    my $replyCB = shift;

    return $self->_sendCtlRequestOF($replyCB, "IgnoreMessage", @_);
}

sub _sendCtlRequestOF {
    my $self = shift;
    my $replyCB = shift;
    my $reqType = shift;

    return 0 unless @_;

    my @types = ();
    for (@_) {
	push @types, $_ if $self->_isValidOFType($_);
    }
    return 0 unless @types;

    my $value = newValue("byteArray", pack('C*', @types));
    return $self->_sendCtlServiceRequest($replyCB, $reqType, $value);
}

sub _noop {}


### Callback class
package OpenFlow::NBAPI::ControllerContext::Callback;

use threads::shared;
use strict;

use base qw(OpenFlow::NBAPI::Util::Callback);
use fields qw(priority);

__PACKAGE__->_create_accessors();

sub init {
    my $self = shift;
    lock $self;

    $self->SUPER::init(@_) or return undef;
    $self->priority(0);
    return 1;
}


### MatchFilterAux class
package OpenFlow::NBAPI::ControllerContext::MatchFilterAux;

use threads::shared;
use strict;

use base qw(OpenFlow::NBAPI::Base::Shared);
use fields qw(callbacks);

__PACKAGE__->_create_accessors();

use Carp;

use OpenFlow::NBAPI::LowLevel::RefList;

use constant _LOWLEVEL => "OpenFlow::NBAPI::LowLevel";
use constant _REFLIST  => _LOWLEVEL . "::RefList";

sub init {
    my $self = shift;
    lock $self;

    $self->SUPER::init(@_) or return undef;
    $self->callbacks(_REFLIST->new());
    return 1;
}

sub copy {
    my $self = shift or return undef;

    my $copy = __PACKAGE__->new();
    $copy->callbacks($self->callbacks->copy());
    return $copy;
}

sub addCallback {
    my $self = shift;
    my $cbRef = shift or return 0;

    lock $self;
    return $self->callbacks->add($cbRef);
}

sub getCallbacks {
    my $self = shift;

    lock $self;
    return $self->callbacks->getList();
}

sub hasCallback {
    my $self = shift;
    my $cbRef = shift or return 0;

    lock $self;
    return $self->callbacks->contains($cbRef);
}

sub numCallbacks {
    my $self = shift;

    lock $self;
    return $self->callbacks->length();
}

sub removeCallback {
    my $self = shift;
    my $cbRef = shift or return 0;

    lock $self;
    return $self->callbacks->remove($cbRef);
}


### ReceiveMessageType class
package OpenFlow::NBAPI::ControllerContext::ReceiveMessageType;

use threads::shared;
use strict;

use base qw(OpenFlow::NBAPI::Base::Shared);
use fields qw(pending refList);

__PACKAGE__->_create_accessors();

use OpenFlow::NBAPI::LowLevel::RefList;

use constant _LOWLEVEL => "OpenFlow::NBAPI::LowLevel";
use constant _REFLIST  => _LOWLEVEL . "::RefList";

sub init {
    my $self = shift;

    lock $self;
    $self->SUPER::init(@_) or return undef;
    $self->pending(undef);
    $self->refList(_REFLIST->new());
    return 1;
}

sub pending {
    my $self = shift;

    lock $self;
    if (@_) {
	$self->{pending} = shift;
	cond_broadcast $self;
    }
    return $self->{pending};
}

sub waitForPending {
    my $self = shift;
    my $timeout = shift;

    my $absTimeout = absTime($timeout) if defined $timeout;
    return $self->waitForPendingUntil($absTimeout);
}

sub waitForPendingUntil {
    my $self = shift;
    my $absTimeout = shift;

    lock $self;
    while ($self->pending) {
	if (defined $absTimeout) {
	    cond_timedwait $self, $absTimeout or return 0;
	}
	else {
	    cond_wait $self;
	}
    }
    return 1;
}


### Request class
package OpenFlow::NBAPI::ControllerContext::Request;

use threads::shared;
use strict;

use base qw(OpenFlow::NBAPI::Base::Shared);
use fields qw(_completed _ctlCtx _hasReply _id _requestMessage _replyMessage _replyValue);

__PACKAGE__->_create_accessors();

use OpenFlow::NBAPI::Util::Thread qw(:all);

sub init {
    my $self = shift;

    $self->SUPER::init(@_) or return undef;
    $self->_completed(0);
    $self->_ctlCtx(undef);
    $self->_id(undef);
    $self->clearReply();
    return 1;
}

sub clearReply {
    my $self = shift;

    lock $self;
    $self->{_replyMessage} = undef;
    $self->{_replyValue} = undef;
    $self->{_hasReply} = 0;
    return 1;
}

sub completed {
    my $self = shift;

    lock $self;
    return $self->_completed;
}

sub _completed {
    my $self = shift;

    lock $self;
    if (@_) {
	$self->{_completed} = shared_clone(shift);
	cond_broadcast $self if $self->{_completed};
    }
    return $self->{_completed};
}

sub ctlCtx {
    my $self = shift;

    lock $self;
    return $self->_ctlCtx;
}

sub id {
    my $self = shift;

    lock $self;
    return $self->_id;
}

sub requestMessage {
    my $self = shift;

    lock $self;
    return $self->_requestMessage;
}

sub replyMessage {
    my $self = shift;

    lock $self;
    return $self->_replyMessage;
}

sub replyValue {
    my $self = shift;

    lock $self;
    return $self->_replyValue;
}

sub _replyValue {
    my $self = shift;

    lock $self;
    if (@_) {
	$self->{_replyValue} = shared_clone(shift);
	$self->_hasReply(1);
	cond_broadcast $self;
    }
    return $self->{_replyValue};
}

sub waitForCompletion {
    my $self = shift;
    my $delta = shift;

    my $absTime = absTime($delta) if defined $delta;
    return $self->waitForCompletionUntil($absTime);
}

sub waitForCompletionUntil {
    my $self = shift;
    my $absTime = shift;

    lock $self;
    until ($self->completed) {
	if (defined $absTime) {
	    cond_timedwait $self, $absTime or last;
	}
	else {
	    cond_wait $self;
	}
    }
    return $self->completed;
}

sub waitForReply {
    my $self = shift;
    my $delta = shift;

    my $absTime = absTime($delta) if defined $delta;
    return $self->waitForReplyUntil($absTime);
}

sub waitForReplyUntil {
    my $self = shift;
    my $absTime = shift;

    lock $self;
    until ($self->_hasReply) {
	if (defined $absTime) {
	    cond_timedwait $self, $absTime or last;
	}
	else {
	    cond_wait $self;
	}
    }
    return $self->replyValue;
}


### RequestInfo class
package OpenFlow::NBAPI::ControllerContext::RequestInfo;

use threads::shared;
use strict;

use base qw(OpenFlow::NBAPI::Base::Shared);
use fields qw(persistenceCheck request replyCB replyValueType);

__PACKAGE__->_create_accessors();

sub init {
    my $self = shift;
    lock $self;

    $self->SUPER::init(@_) or return undef;
    $self->persistenceCheck(undef);
    $self->request(undef);
    $self->replyCB(undef);
    $self->replyValueType(undef);
    return 1;
}


### Status class
package OpenFlow::NBAPI::ControllerContext::Status;

use threads::shared;
use strict;

use constant DISCONNECTED => 0;
use constant CONNECTED    => 1;


### SwitchStatus class
package OpenFlow::NBAPI::ControllerContext::SwitchStatus;

use threads::shared;
use strict;

use base qw(OpenFlow::NBAPI::Base::Shared);
use fields qw(lastUpdated persistent portMap status);

__PACKAGE__->_create_accessors();

use OpenFlow::NBAPI::LowLevel::PB::SBOFMessagesPB;

sub init {
    my $self = shift;

    lock $self;
    $self->SUPER::init(@_) or return undef;
    $self->lastUpdated(0);
    $self->persistent(0);
    $self->portMap(&share({}));
    $self->status(undef);
    return 1;
}


1;
