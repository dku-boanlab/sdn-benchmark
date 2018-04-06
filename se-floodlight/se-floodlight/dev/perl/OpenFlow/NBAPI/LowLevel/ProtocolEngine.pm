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

package OpenFlow::NBAPI::LowLevel::ProtocolEngine;

BEGIN {
    our $VERSION = "0.1"; # package version
}

use threads;
use threads::shared;

use base qw(Exporter);
use fields qw(
    clientID engineID mode pbqIn status
    messagesReceived messagesSent messagesDropped messagesFiltered
    maxEncodedLength
    _maxShift _priorStatus _outQueue _handlerMapIn _requestID
    _sendInternalOnly _isStopping _intExtMap _welcomeReceived
);
use strict;

our @EXPORT_MODES = qw(
    PE_MODE_CLIENT PE_MODE_SERVER
    );

our @EXPORT_STATUS = qw(
    PE_STATUS_INIT PE_STATUS_SUSPENDED
    PE_STATUS_PROCESSING PE_STATUS_RECV_ONLY PE_STATUS_SEND_ONLY
    PE_STATUS_DROPPING
    PE_STATUS_TERMINATED
    PE_STATUS_ERROR_UNKNOWN PE_STATUS_ERROR_INTERNAL
    PE_STATUS_ERROR_RECV PE_STATUS_ERROR_SEND
    PE_STATUS_ERROR_REMOTE
    );

our @EXPORT_VERSION = qw(
    PE_VERSION_NB PE_VERSION_SB
    );

our @EXPORT_OK = (@EXPORT_MODES, @EXPORT_STATUS, @EXPORT_VERSION);
our %EXPORT_TAGS = (
    all => \@EXPORT_OK,
    modes => \@EXPORT_MODES,
    status => \@EXPORT_STATUS,
    version => \@EXPORT_VERSION
    );

use constant PE_VERSION_NB            => 0;
use constant PE_VERSION_SB            => 0;

use constant PE_DEFAULT_MAX_ENCODED => 0xffffff;

use constant PE_MODE_CLIENT           => 1;
use constant PE_MODE_SERVER           => 2;

#
# All status values between PE_STATUS_TERMINATED (inclusive)
# and PE_STATUS_ERROR_UNKNOWN (exclusive) indicate
# successful termination.
#
# All status values at or above PE_STATUS_ERROR_UNKNOWN
# indicate fatal errors (abnormal termination).
#
use constant PE_STATUS_INIT           => 0;
use constant PE_STATUS_SUSPENDED      => 100;
use constant PE_STATUS_PROCESSING     => 200;
use constant PE_STATUS_RECV_ONLY      => 201;
use constant PE_STATUS_SEND_ONLY      => 202;
use constant PE_STATUS_DROPPING       => 300;
use constant PE_STATUS_TERMINATED     => 1000;
use constant PE_STATUS_ERROR_UNKNOWN  => 2000;
use constant PE_STATUS_ERROR_INTERNAL => 2001;
use constant PE_STATUS_ERROR_RECV     => 2002;
use constant PE_STATUS_ERROR_SEND     => 2003;
use constant PE_STATUS_ERROR_REMOTE   => 2004;

use Carp;

use OpenFlow::NBAPI::PBQueue;
use OpenFlow::NBAPI::LowLevel::PriorityQueue;
use OpenFlow::NBAPI::LowLevel::PB::NorthboundAPIPB;
use OpenFlow::NBAPI::LowLevel::PB::SBOFMessagesPB;
use OpenFlow::NBAPI::LowLevel::PB::NBCtlServicesPB;
use OpenFlow::NBAPI::LowLevel::PB::NBInternalPB;
use OpenFlow::NBAPI::Util::Logger qw(:all);
use OpenFlow::NBAPI::Util::PBMessage qw(:all);

use constant _DEFAULT_LOG_LEVEL => TRACE;

use constant _NBAPI         => "OpenFlow::NBAPI";
use constant _LOWLEVEL      => _NBAPI . "::LowLevel";
use constant _PBQUEUE       => _NBAPI . "::PBQueue";
use constant _PRIOQUEUE     => _LOWLEVEL . "::PriorityQueue";
use constant _HANDLERMAP    => _LOWLEVEL . "::HandlerMap";

use constant _PRIO_INTERNAL   => 1;
use constant _PRIO_CTLSERVICE => 100;
use constant _PRIO_OPENFLOW   => 100;
use constant _PRIO_EXTENSION  => 100;
use constant _PRIO_MAP        => {
    PB_INT_TYPE => _PRIO_INTERNAL,
    PB_CTL_TYPE => _PRIO_CTLSERVICE,
    PB_OF_TYPE  => _PRIO_OPENFLOW,
    PB_EXT_TYPE => _PRIO_EXTENSION
};

sub _log {
    my $invocant = shift;
    my $msg = shift;
    my $level = shift || _DEFAULT_LOG_LEVEL;
    my $id = ref $invocant ? " " . $invocant->engineID : "";
    writeLog($level, "ProtocolEngine${id}: $msg");
}

sub new {
    my $class = shift;
    my $self = &share(fields::new(ref $class || $class));
    $self->init(@_) or return undef;
    return $self;
}

sub init {
    my $self = shift;
    my $id = shift || 0;

    lock $self;
    $self->{engineID} = $id;
    $self->{mode} = 0;
    $self->{pbqIn} = undef;
    my $outQueue = _PRIOQUEUE->new();
    $self->{_outQueue} = $outQueue;
    $self->{messagesReceived} = 0;
    $self->{messagesSent} = 0;
    $self->{status} = PE_STATUS_INIT;
    $self->maxEncodedLength(PE_DEFAULT_MAX_ENCODED);
    my $handlerMapIn = _HANDLERMAP->new();
    $handlerMapIn->defaultHandler('_protocolError');
    $self->{_handlerMapIn} = $handlerMapIn;
    $self->{_requestID} = 1;
    $self->{_isStopping} = 0;
    $self->{_intExtMap} = &share({});
    $self->{_welcomeReceived} = 0;
    $self->_sendInternalOnly(1);
    return 1;
}

sub clientID {
    my $self = shift;
    lock $self;
    $self->{clientID} = shift if @_;
    return $self->{clientID};
}

sub engineID {
    my $self = shift;
    lock $self;
    return $self->{engineID};
}

sub hasIntExtension {
    my $self = shift;
    my $ext = shift or return undef;

    my $map = $self->{_intExtMap};
    lock $map;
    return $map->{$ext};
}

sub mode {
    my $self = shift;
    lock $self;
    if (@_) {
	if ($self->{mode}) {
	    warn "Protocol mode cannot be changed.";
	}
	else {
	    my $mode = shift;
	    if ($mode < PE_MODE_CLIENT || $mode > PE_MODE_SERVER) {
		carp "Invalid mode $mode";
	    }
	    else {
		$self->{mode} = $mode;
		$self->_log("mode set to " . $self->modeStr($mode), DEBUG);
	    }
	}
    }
    return $self->{mode} || ($self->{mode} = PE_MODE_CLIENT);
}

sub modeStr {
    my $self = shift;
    my $mode = shift || $self->mode;
    $mode == PE_MODE_CLIENT and return "client";
    $mode == PE_MODE_SERVER and return "server";
    return "UNKNOWN";
}

sub pbqIn {
    my $self = shift;
    lock $self;
    if (@_) {
	my $pbq = shift;
	$self->{pbqIn} = shared_clone($pbq);
	$self->_log("pbqIn (re)set", VERBOSE);
    }
    return $self->{pbqIn} || ($self->{pbqIn} = shared_clone(_PBQUEUE->new()));
}

sub status {
    my $self = shift;
    warn "Status is immutable." if @_;
    lock $self;
    return $self->{status};
}

sub maxEncodedLength {
    my $self = shift;
    lock $self;
    if (@_) {
	my $len = shift;
	if ($len < 0) {
	    warn "Maximum encoded length cannot be negative.";
	}
	else {
	    $self->{maxEncodedLength} = $len;
	    $self->{_maxShift} = int(log($len)/log(2));
	    $self->_log("maxEncodedLength set to $len", VERBOSE);
	}
    }
    return $self->{maxEncodedLength};
}

sub nextRequestID {
    my $self = shift;
    lock $self;
    return $self->{_requestID}++;
}

sub _setStatus {
    my $self = shift;

    my $oldStatus;
    my $changed = 0;
    {
	lock $self;
	$oldStatus = $self->{status};
	$self->{status} = shift;
	if ($self->{status} != $oldStatus) {
	    $changed = 1;
	    cond_broadcast $self;
	}
    }
    if ($changed) {
	$self->_notifyReceiver();
	$self->_notifySender();
	$self->_log("status changed from $oldStatus to " . $self->{status}, DEBUG);
    }
    return $self->{status};
}

sub _notifyReceiver {
    my $self = shift;
    my $pbqIn = $self->pbqIn or return 0;
    lock $pbqIn;
    cond_broadcast $pbqIn;
}

sub _notifySender {
    my $self = shift;
    my $outQueue = $self->{_outQueue};
    lock $outQueue;
    cond_broadcast $outQueue;
}

sub messagesReceived {
    my $self = shift;
    lock $self;
    warn "Received-message count is immutable." if @_;
    return $self->{messagesReceived};
}

sub _incrMessagesReceived {
    my $self = shift;
    lock $self;
    return ++$self->{messagesReceived};
}

sub messagesSent {
    my $self = shift;
    lock $self;
    warn "Sent-message count is immutable." if @_;
    return $self->{messagesSent};
}

sub _incrMessagesSent {
    my $self = shift;
    lock $self;
    return ++$self->{messagesSent};
}

sub messagesDropped {
    my $self = shift;
    lock $self;
    warn "Dropped-message count is immutable." if @_;
    return $self->{messagesDropped};
}

sub _incrMessagesDropped {
    my $self = shift;
    lock $self;
    return ++$self->{messagesDropped};
}

sub messagesFiltered {
    my $self = shift;
    lock $self;
    warn "Filtered-message count is immutable." if @_;
    return $self->{messagesFiltered};
}

sub _incrMessagesFiltered {
    my $self = shift;
    lock $self;
    return ++$self->{messagesFiltered};
}

sub _setIntExtensions {
    my $self = shift;
    my $extList = shift or return 0;

    my $map = $self->{_intExtMap};
    lock $map;
    for my $ext (@$extList) {
	$map->{$ext} = 1;
    }
    return scalar(@$extList);
}

sub _resetIntExtensions {
    my $self = shift;
    my $map = $self->{_intExtMap};
    lock $map;
    %$map = ();
}

sub _sendInternalOnly {
    my $self = shift;
    my $value = shift;

    if (defined $value) {
	{
	    lock $self;
	    $self->{_sendInternalOnly} = $value;
	}
	$self->_notifySender();
	$self->_log(($value ? "set" : "cleared") . " internal-only send", VERBOSE);
    }
    return $self->{_sendInternalOnly};
}

sub start {
    my $self = shift;
    lock $self;

    my $fhIn = shift;
    my $fhOut = shift;

    my $status = $self->status;

    if ($status != PE_STATUS_INIT) {
	warn "Cannot start: status is $status";
	return 0;
    }

    binmode $fhIn;
    binmode $fhOut;
    autoflush $fhOut 1;

    my $version = __PACKAGE__->VERSION;
    $self->_log("version $version starting in " . $self->modeStr() . " mode", TRACE);

    if ($self->mode == PE_MODE_CLIENT) {
	return $self->_startClient($fhIn, $fhOut);
    }
    else {
	return $self->_startServer($fhIn, $fhOut);
    }
}

sub _suspend {
    my $self = shift;
    lock $self;

    my $newStatus = shift;
    my $status = $self->status;
    if ($status >= PE_STATUS_SUSPENDED && $status < PE_STATUS_TERMINATED) {
	$self->{_priorStatus} = $status if ($status >= PE_STATUS_PROCESSING);
	return $self->_setStatus($newStatus);
    }
    return $status;
}

sub suspend {
    my $self = shift;
    lock $self;

    $self->_log("suspending message processing", DEBUG);
    return $self->_suspend(PE_STATUS_SUSPENDED);
}

sub suspendRecv {
    my $self = shift;
    lock $self;

    $self->_log("suspending message receiving", DEBUG);
    return $self->_suspend(PE_STATUS_SEND_ONLY);
}

sub suspendSend {
    my $self = shift;
    lock $self;

    $self->_log("suspending message sending", DEBUG);
    return $self->_suspend(PE_STATUS_RECV_ONLY);
}

sub resume {
    my $self = shift;
    lock $self;

    my $status = $self->status;
    if ($status >= PE_STATUS_SUSPENDED && $status < PE_STATUS_TERMINATED) {
	$self->_log("resuming message processing", DEBUG);
	my $priorStatus = $self->{_priorStatus} || PE_STATUS_PROCESSING;
	return $self->_setStatus($priorStatus);
    }
    return $status;
}

sub resumeRecv {
    my $self = shift;
    lock $self;

    my $newStatus = undef;
    my $status = $self->status;
    {
	$status == PE_STATUS_SUSPENDED and do {
	    $newStatus = PE_STATUS_RECV_ONLY;
	    last;
	};

	$status == PE_STATUS_SEND_ONLY and do {
	    $newStatus = PE_STATUS_PROCESSING;
	    last;
	};
    }
    if (defined($newStatus)) {
	$self->_log("resuming message receiving", DEBUG);
	$self->_setStatus($newStatus);
    }
    return $self->status;
}

sub resumeSend {
    my $self = shift;
    lock $self;

    my $newStatus = undef;
    my $status = $self->status;
    {
	$status == PE_STATUS_SUSPENDED and do {
	    $newStatus = PE_STATUS_SEND_ONLY;
	    last;
	};

	$status == PE_STATUS_SEND_ONLY and do {
	    $newStatus = PE_STATUS_PROCESSING;
	    last;
	};
    }
    if (defined($newStatus)) {
	$self->_log("resuming message sending", DEBUG);
	$self->_setStatus($newStatus);
    }
    return $self->status;
}

sub stop { # ([goodbyeReason])
    my $self = shift;

    {
	lock $self;
	if ($self->isTerminated()) {
	    $self->_log("stopped", TRACE);
	    return 1;
	}
	if ($self->{_isStopping}) {
	    $self->_log("stop in progress", TRACE);
	    return 1;
	}
	$self->{_isStopping} = 1;
    }

    $self->_log("stopping", TRACE);
    $self->_sendGoodbye(PE_STATUS_TERMINATED, @_);
}

sub waitWhileSuspended {
    my $self = shift;
    lock $self;
    cond_wait $self until $self->status != PE_STATUS_SUSPENDED;
}

sub waitWhileSuspendedRecv {
    my $self = shift;
    lock $self;
    cond_wait $self until
	($self->status != PE_STATUS_SUSPENDED && $self->status != PE_STATUS_SEND_ONLY);
}

sub waitWhileSuspendedSend {
    my $self = shift;
    lock $self;
    cond_wait $self until
	($self->status != PE_STATUS_SUSPENDED && $self->status != PE_STATUS_RECV_ONLY);
}

sub waitForTermination {
    my $self = shift;
    my $timeout = shift;

    my $absTimeout = time() + $timeout if defined $timeout;
    return $self->waitForTerminationUntil($absTimeout);
}

sub waitForTerminationUntil {
    my $self = shift;
    my $absTimeout = shift;

    lock $self;
    until ($self->status >= PE_STATUS_TERMINATED) {
	if (defined $absTimeout) {
	    cond_timedwait $self, $absTimeout or last;
	}
	else {
	    cond_wait $self;
	}
    }
    return $self->status >= PE_STATUS_TERMINATED;
}

sub isRunning {
    my $self = shift;
    lock $self;
    my $status = $self->status;
    return ($status >= PE_STATUS_PROCESSING && $status < PE_STATUS_TERMINATED);
}

sub isDropping {
    my $self = shift;
    lock $self;
    return $self->status == PE_STATUS_DROPPING;
}

sub isTerminated {
    my $self = shift;
    lock $self;
    return $self->status >= PE_STATUS_TERMINATED;
}

sub hasError {
    my $self = shift;
    lock $self;
    return $self->status >= PE_STATUS_ERROR_UNKNOWN;
}

sub sendCtlServiceMsg {
    my $self = shift;
    return $self->_sendCtlService(@_);
}

sub sendOpenFlowMsg {
    my $self = shift;
    return $self->_sendOpenFlow(@_);
}

sub sendOFMsg {
    my $self = shift;
    return $self->sendOpenFlowMsg(@_);
}

sub sendExtensionMsg {
    my $self = shift;
    return $self->_sendExtension(@_);
}

sub sendPingRequest {
    my $self = shift;

    $self->{_welcomeReceived} or do {
	$self->_log("illegal ping request", ERROR);
	return undef;
    };
    return $self->_sendPing(PingMessagePB::PingType->PING_REQUEST);
}

sub _internalError {
    my $self = shift;
    my $msg = shift || "Unknown internal error";
    $self->_log($msg, ERROR);
    $self->_setStatus(PE_STATUS_ERROR_INTERNAL);
}

sub _logPBMessage {
    my $self = shift;
    # no lock
    my $level = shift;

    my $pbMsg = shift;
    my $action = shift || "";

    my $type = pbMessageType($pbMsg);
    my $subtype = pbMessageSubtype($pbMsg);
    $self->_log("message type $type($subtype) $action", $level);
}

sub _startClient {
    my $self = shift;
    lock $self;

    my $fhIn = shift;
    my $fhOut = shift;

    $self->clientID or do {
	carp "clientID not set";
	return 0;
    };

    $self->_setStatus(PE_STATUS_PROCESSING);

    my $reader = threads->create('_clientRead', $self, $fhIn) or do {
	$self->_internalError("Failed to create reader thread: $!");
	return 0;
    };
    $reader->detach();

    my $writer = threads->create('_clientWrite', $self, $fhOut) or do {
	$self->_internalError("Failed to create writer thread: $!");
	return 0;
    };
    $writer->detach();

    # Nothing expected from the server initially
    $self->{_handlerMapIn}->clearHandler();

    $self->_sendHello();

    return 1;
}

sub _clientRead {
    my $self = shift;
    my $fh = shift;

    $self->_log("reader thread started", TRACE);
    until ($self->isTerminated) {
	$self->_log("check read suspended", VERBOSE);
	$self->waitWhileSuspendedRecv();
	$self->_log("read not suspended", VERBOSE);
	while ($self->isRunning) {
	    my $pbMsg = undef;
	    $pbMsg = $self->_readMessagePB($fh) or do {
		$self->_log("(read) message receive failure: " . ($@ ? $@ : defined($pbMsg) ? "unexpected EOF" : "read error: $!"), ERROR);
		$self->_setStatus(PE_STATUS_ERROR_RECV);
		next;
	    };
	    $self->_log("(read) received a message", DEBUG);
	    if (logLevel() <= DEBUG) {
		use Data::Dumper;
		$Data::Dumper::Indent = 0;
		$Data::Dumper::Terse = 1;
		$self->_log("(read) " . Dumper($pbMsg), DEBUG);
	    }
	    $self->_logPBMessage(DEBUG, $pbMsg, "received");
	    $self->_incrMessagesReceived();
	    if ($self->isDropping) {
		$self->_incrMessagesDropped();
		$self->_log("(read) received message dropped", DEBUG);
		next;
	    }
	    $self->_processMessageIn($pbMsg);
	}
    }
    $self->_log("reader thread terminated", TRACE);
}

sub _readMessagePB {
    my $self = shift;
    my $fh = shift;

    local $/; # undefine Perl's record separator, as a precaution

    my $read;

    # Read varint-encoded message length
    my $byte = 0;
    my $len = 0;
    my $shift = 0;
    do {
	$read = read($fh, my $char, 1) or return $read;
	$byte = unpack("C", $char);
	$len |= ($byte & 0x7f) << $shift;
	$shift += 7;
	if ($len > $self->maxEncodedLength || $shift > $self->{_maxShift}) {
	    $self->_log("(read) encoded message length will exceed maximum (" . $self->maxEncodedLength . ")", ERROR);
	    return undef;
	}
    } while ($byte & 0x80);
    $self->_log("(read) encoded message is $len bytes", VERBOSE);

    if ($len <= 0) {
	$self->_log("(read) invalid message length $len", ERROR);
	return undef;
    }

    # Read encoded message bytes
    my $buf = '';
    my $off = 0;
    while ($len > 0) {
	$read = read($fh, $buf, $len, $off) or return $read;
	$off += $read;
	$len -= $read;
    }
    if (logLevel() <= DEBUG) {
	my @bytes = unpack("C*", $buf);
	$self->_log("[" . join(" ", @bytes) . "]", VERBOSE);
    }

    # Decode message, catching any exception
    return eval {
	MessagePB->decode($buf);
    };
}

sub _processMessageIn {
    my $self = shift;
    my $pbMsg = shift;

    $self->waitWhileSuspendedRecv();

    my $handler;
    {
	lock $self;
       	$handler = $self->{_handlerMapIn}->getHandler($pbMsg) or do {
	    $self->_internalError("No handler for received message");
	    return undef;
	};
    }

    my $retval = $self->$handler($pbMsg);

    if ($retval) {
	$self->pbqIn->enqueue($pbMsg);
	$self->_log("received message added to queue", DEBUG);
    }
    else {
	$self->_incrMessagesFiltered();
	$self->_log("received message filtered", DEBUG);
    }
    return $retval;
}

sub _clientWrite {
    my $self = shift;
    my $fh = shift;

    $self->_log("writer thread started", TRACE);
    until ($self->isTerminated) {
	$self->_log("check write suspended", VERBOSE);
	$self->waitWhileSuspendedSend();
	$self->_log("write not suspended", VERBOSE);
	while ($self->isRunning) {
	    my $outQueue = $self->{_outQueue};
	    my $msgStruct = undef;
	    my $priority = undef;
	    my $pbMsg = undef;
	    $self->_log("(write) waiting for message to send", DEBUG);
	    {
		lock $outQueue;
		cond_wait $outQueue until ($self->_isReadyToSend() || ! $self->isRunning);
	    }
	    next unless $self->isRunning;
	    ($msgStruct, $priority) = $outQueue->dequeue();
	    $self->_log("(write) got a message to send", DEBUG);
	    $pbMsg = $msgStruct->{pbMsg} or do {
		$self->_log("(write) message structure contains no message", ERROR);
		next;
	    };
	    if (logLevel() <= DEBUG) {
		use Data::Dumper;
		$Data::Dumper::Indent = 0;
		$Data::Dumper::Terse = 1;
		$self->_log("(write) " . Dumper($msgStruct), DEBUG);
	    }
	    $self->_writeMessagePB($pbMsg, $fh) or do {
		$self->_log("(write) message send failure: " . ($@ ? $@ : "write error: $!"), ERROR);
		$self->_setStatus(PE_STATUS_ERROR_SEND);
		next;
	    };
	    $self->_logPBMessage(DEBUG, $pbMsg, "sent");
	    if (my $sentCB = $msgStruct->{sentCB}) {
		my @sentCBArgs = $msgStruct->{sentCBArgs} || ();
		$self->$sentCB(@sentCBArgs);
	    };
	}
    }
    $self->_log("writer thread terminated", TRACE);
}

sub _isReadyToSend {
    my $self = shift;

    my $outQueue = $self->{_outQueue};
    lock $outQueue;
    if ($outQueue->pending() > 0) {
	return 1 unless $self->_sendInternalOnly;
	$self->_log("(write) checking for internal message", VERBOSE);
	my ($msgStruct, $priority) = $outQueue->peek();
	my $pbMsg = $msgStruct->{pbMsg} or do {
	    $outQueue->extract(); # discard the bad entry
	    $self->_log("(write) message structure contains no message", ERROR);
	};
	return 1 if pbMessageType($pbMsg) == PB_INT_TYPE;
    }
    return 0;
}

sub _writeMessagePB {
    my $self = shift;
    my $pbMsg = shift;
    my $fh = shift;

    local $/; # undefine Perl's record separator, as a precaution

    my $encoded = undef;
    # Encode the message, catching any exception
    eval {
	$encoded = $pbMsg->encode();
    } or return undef;

    my $len = length($encoded);
    ($len > 0 && $len <= $self->maxEncodedLength) or do {
	$@ = "(write) invalid encoded message length ($len); valid range 1 <= length <= " . $self->maxEncodedLength;
	return undef;
    };
    $self->_log("(write) encoded message is $len bytes", VERBOSE);
    my $varlen = "";
    my $byte = $len & 0x7f;
    while ($len >>= 7) {
	$varlen .= pack("C", 0x80 | $byte);
	$byte = $len & 0x7f;
    }
    $varlen .= pack("C", $byte);
    my $retval = print $fh ($varlen, $encoded);
    $self->_log("(write) wrote " . (length($varlen) + length($encoded)) . " bytes", VERBOSE);
    if (logLevel() <= DEBUG) {
	my @bytes = unpack("C*", $varlen . $encoded);
	$self->_log("[" . join(" ", @bytes) . "]", VERBOSE);
    }
    return $retval;
}

sub _protocolError { # ([offendingMessage [, protoErrType]])
    my $self = shift;

    my $errorMsg = &share(ErrorMessagePB->new());
    $errorMsg->errorType(ErrorMessagePB::ErrorType::PROTOCOL_ERROR());

    my $protoErrType = ProtocolErrorInfoPB::ProtocolErrorType->STREAM_DECODE_FAILURE; # assumed default

    if (my $pbMsg = shift) {
	if (defined(my $errType = shift)) {
	    # protocol error type was given
	    $protoErrType = $errType;
	}
	else {
	    if (defined(pbMessageSubtype($pbMsg))) {
		$protoErrType = ProtocolErrorInfoPB::ProtocolErrorType->UNEXPECTED_MESSAGE;
	    }
	    else {
		$protoErrType = ProtocolErrorInfoPB::ProtocolErrorType->BAD_MESSAGE;
	    }
	}
    }

    my $protoErrInfo = &share(ProtocolErrorInfoPB->new());
    $protoErrInfo->protocolErrorType($protoErrType);
    $errorMsg->protocolErrorInfo($protoErrInfo);

    $self->_sendGoodbye(PE_STATUS_ERROR_REMOTE, GoodbyeMessagePB::Reason::ERROR(), $errorMsg);
    return 0;
}

sub _sendHello {
    my $self = shift;

    $self->_log("_sendHello called", DEBUG);

    my $helloMsg = &share(HelloMessagePB->new());
    $helloMsg->{versionNB} = PE_VERSION_NB;
    $helloMsg->{versionSB} = PE_VERSION_SB;
    $helloMsg->{clientID} = shared_clone($self->clientID);

    my $msg = $self->_newInternalMsg(PB_INT->Hello, $helloMsg);

    # Hold incoming messages until handlers are set for Hello reply (_sentHello)
    $self->suspendRecv();

    $self->_sendInternal($msg, '_sentHello');
}

sub _sendGoodbye {
    my $self = shift;

    $self->_log("_sendGoodbye called", DEBUG);

    # ignore anything further from the server
    $self->_setStatus(PE_STATUS_DROPPING);

    my $finalStatus = shift if @_;
    $finalStatus = PE_STATUS_TERMINATED unless defined($finalStatus);

    my $reason = shift if @_;
    $reason = GoodbyeMessagePB::Reason::NONE() unless defined($reason);
    my $goodbyeMsg = &share(GoodbyeMessagePB->new());
    $goodbyeMsg->reason($reason);

    my $msg = $self->_newInternalMsg(PB_INT->Goodbye, $goodbyeMsg);
    {
	$reason == GoodbyeMessagePB::Reason::ERROR() and do {
	    my $errorMsg = shift if @_;
	    $msg->errorMessage($errorMsg);
	    last;
	}
    }

    $self->_sendInternal($msg, '_shutdown', $finalStatus);
}

sub _sendPing {
    my $self = shift;
    my $pingType = shift;
    my $requestID = shift || $self->nextRequestID();

    $self->_log("_sendPing called", DEBUG);

    my $pingMsg = &share(PingMessagePB->new());
    $pingMsg->pingType(shared_clone($pingType));
    $pingMsg->requestID(shared_clone($requestID));

    my $msg = $self->_newInternalMsg(PB_INT->Ping, $pingMsg);
    $self->_sendInternal($msg);
    return $requestID;
}

sub _newInternalMsg {
    my $self = shift;

    my $subtype = shift if @_;
    my $subMsg = shift if @_;

    my $msg = &share(NBInternalMsgPB->new());

    defined($subtype) or return $msg;

    my $field = pbInternalTypeField($subtype) or do {
	carp "Unknown internal message type $subtype";
	return undef;
    };

    $msg->msgType($subtype);
    $msg->$field($subMsg) if $subMsg;
    return $msg;
}

sub _getInternalMsg {
    my $self = shift;

    my $pbMsg = shift;
    return pbGetMessage($pbMsg) or
	_internalError("Unable to parse internal message");
}

sub _sentHello {
    my $self = shift;
    lock $self;

    $self->_log("_sentHello called", DEBUG);

    my $handlerMap = $self->{_handlerMapIn};
    $handlerMap->clearHandler();
    $handlerMap->setHandler('_receivedWelcome', PB_INT_TYPE, PB_INT->Welcome);
    $handlerMap->setHandler('_receivedAuthenRequest', PB_INT_TYPE, PB_INT->AuthenRequest);
    $handlerMap->setHandler('_receivedGoodbye', PB_INT_TYPE, PB_INT->Goodbye);
    $handlerMap->setHandler('_receivedError', PB_INT_TYPE, PB_INT->Error);

    # Resume processing of incoming messages (suspended in _sendHello)
    $self->resumeRecv();
}

sub _receivedWelcome {
    my $self = shift;
    my $pbMsg = shift;

    lock $self;

    $self->_log("_receivedWelcome called", DEBUG);

    my $welcomeMsg = pbGetMessage($pbMsg)->welcomeMessage;
    $self->_resetIntExtensions();
    $self->_setIntExtensions($welcomeMsg->internalExtensionIDs);

    # Enable output of non-internal messages
    $self->_sendInternalOnly(0);

    $self->{_welcomeReceived} = 1;

    my $handlerMap = $self->{_handlerMapIn};
    $handlerMap->clearHandler();
    $handlerMap->setHandler('_receivedGoodbye', PB_INT_TYPE, PB_INT->Goodbye);
    $handlerMap->setHandler('_receivedError', PB_INT_TYPE, PB_INT->Error);
    $handlerMap->setHandler('_receivedPing', PB_INT_TYPE, PB_INT->Ping);
    $handlerMap->setHandler('_receivedWelcome', PB_INT_TYPE, PB_INT->Welcome);
    $handlerMap->setHandler('_receivedOF', PB_OF_TYPE);
    $handlerMap->setHandler('_receivedCtl', PB_CTL_TYPE);
    $handlerMap->setHandler('_receivedExt', PB_EXT_TYPE);

    return 1;
}

sub _receivedAuthenRequest {
    my $self = shift;

    $self->_log("_receivedAuthenRequest called", DEBUG);

    # TODO _receivedAuthenRequest
    return 1;
}

sub _receivedGoodbye {
    my $self = shift;

    $self->_log("_receivedGoodbye called", DEBUG);

    $self->_setStatus(PE_STATUS_DROPPING);

    my $pbMsg = shift;
    my $internalMsg = $self->_getInternalMsg($pbMsg);
    my $goodbyeMsg = $internalMsg->goodbyeMessage;
    my $reason =$goodbyeMsg->reason;
    my $finalStatus = PE_STATUS_TERMINATED;
    {
	$reason == GoodbyeMessagePB::Reason->ERROR and do {
	    $self->_handleError($internalMsg->errorMessage);
	    $finalStatus = PE_STATUS_ERROR_UNKNOWN; # TODO
	    last;
	};
    }
    $self->_shutdown($finalStatus);
    return 1;
}

sub _receivedError {
    my $self = shift;

    $self->_log("_receivedError called", DEBUG);

    my $pbMsg = shift;
    my $internalMsg = $self->_getInternalMsg($pbMsg);
    return $self->_handleError($internalMsg->errorMessage);
}

sub _receivedPing {
    my $self = shift;

    $self->_log("_receivedPing called", DEBUG);

    my $pbMsg = shift;
    my $pingMsg = $self->_getInternalMsg($pbMsg)->pingMessage;
    my $pingType = $pingMsg->pingType;
    if ($pingType == PingMessagePB::PingType->PING_REPLY) {
	# pass it through to the queue
	return 1;
    }
    elsif ($pingType == PingMessagePB::PingType->PING_REQUEST) {
	# send a reply
	$self->_sendPing(PingMessagePB::PingType->PING_REPLY, $pingMsg->requestID);
    }
    else {
	# drop it
	$self->_log("malformed ping message received (ignored)", WARN);
    }
    return 0;
}

sub _receivedOF {
    return 1;
}

sub _receivedCtl {
    return 1;
}

sub _receivedExt {
    return 1;
}

sub _handleError {
    my $self = shift;

    my $errorMsg = shift;
    my $errorType = $errorMsg->errorType;
    $self->_log("received error: $errorType", ERROR);
}

sub _shutdown {
    my $self = shift;

    my $status = shift if @_;
    $status = PE_STATUS_TERMINATED unless defined($status);

    $self->_setStatus($status);
}

sub _startServer {
    my $self = shift;

    $self->_internalError("Server mode not implemented.");
    return 0;
}

sub _sendInternal {
    my $self = shift;

    my $internalMsg = shift or do {
	carp "No internal message to send";
	return undef;
    };
    $self->_sendMessage(PB_INT_TYPE, $internalMsg, @_);
}

sub _sendOpenFlow {
    my $self = shift;

    my $ofMsg = shift or do {
	carp "No OpenFlow message to send";
	return undef;
    };
    $self->_sendMessage(PB_OF_TYPE, $ofMsg, @_);
}

sub _sendCtlService {
    my $self = shift;

    my $ctlMsg = shift or do {
	carp "No control service message to send";
	return undef;
    };
    my $requestID = $self->nextRequestID();
    $ctlMsg->requestID($requestID);
    $self->_sendMessage(PB_CTL_TYPE, $ctlMsg, @_);
    return $requestID;
}

sub _sendExtension {
    my $self = shift;

    my $extMsg = shift or do {
	carp "No extension message to send";
	return undef;
    };
    my $requestID = $self->nextRequestID();
    $extMsg->requestID($requestID);
    $self->_sendMessage(PB_EXT_TYPE, $extMsg, @_);
    return $requestID;
}

sub _sendMessage {
    my $self = shift;

    defined(my $type = shift) or do {
	carp "Message type not specified";
	return undef;
    };
    my $msg = shift or do {
	carp "No message to send";
	return undef;
    };

    my $pbMsg = &share(MessagePB->new());
    my $field = pbMessageTypeField($type) or do {
	carp "Unknown message type $type";
	return undef;
    };
    $pbMsg->messageType($type);
    $pbMsg->$field(shared_clone($msg));
    my $priority = _PRIO_MAP->{$type};

    my %msgStruct;
    share(%msgStruct);
    $msgStruct{pbMsg} = $pbMsg;
    $msgStruct{sentCB} = shift if @_;
    $msgStruct{sentCBArgs} = shared_clone(@_) if @_;

    my $retval = 0;
    my $outQueue = $self->{_outQueue};
    {
	lock $outQueue;
	$retval = $self->{_outQueue}->enqueue(\%msgStruct, $priority);
	$self->_log("_outQueue pending: " . $outQueue->pending(), VERBOSE);
    }
    return $retval;
}


package OpenFlow::NBAPI::LowLevel::HandlerMap;

use threads::shared;

use base qw(Exporter);
use fields qw(
    _defaultHandler _typeMap
    );

use strict;

use Carp;

use OpenFlow::NBAPI::Util::PBMessage qw(:all);

sub new {
    my $class = shift;
    my $self = &share(fields::new(ref $class || $class));
    $self->init() or return undef;
    return $self;
}

sub init {
    my $self = shift;
    lock $self;
    $self->defaultHandler('noop');
    $self->clearHandler();
    return 1;
}

sub clearHandler { # ([type [, subtype [, ...]]])
    my $self = shift;
    lock $self;

    # Clear the entire handler map
    my $type = shift or do {
	$self->{_typeMap} = &share({});
	return 1;
    };

    my $types = $self->{_typeMap};

    # Clear just the listed subtypes of a type
    if (@_ && $types->{$type}) {
	while (my $subtype = shift) {
	    $types->{$type}->{$subtype} = undef;
	}
	return 1;
    }

    # Clear an entire type
    $types->{$type} = &share({});
    return 1;
}

sub defaultHandler { # ([handlerName])
    # Handler must be specified by name (string),
    # since threads::shared does not (yet?) support
    # subroutine references.
    my $self = shift;
    lock $self;
    $self->{_defaultHandler} = shift if @_;
    return $self->{_defaultHandler};
}

sub getHandler { # (message)
    my $self = shift;
    lock $self;

    my $handler = $self->defaultHandler;

    {
	my $pbMsg = shift or last;
	defined(my $msgType = pbMessageType($pbMsg)) or last;
	my $types = $self->{_typeMap} or last;
	my $subtypes = $types->{$msgType} or last;
	defined(my $subtype = pbMessageSubtype($pbMsg)) or last;
	$handler = $subtypes->{$subtype};
    }

    return $handler;
}

sub setHandler { # (handler, type [, subtype [,...]])
    my $self = shift;
    lock $self;

    my $handler = shift or do {
	carp "Must specify a handler";
	return undef;
    };

    my $type = shift or do {
	carp "Must specify a message type";
	return undef;
    };

    my $types = $self->{_typeMap};
    $types->{$type} = &share({}) unless $types->{$type};
    my $subtypes = $types->{$type};

    # Set just the listed subtypes
    if (@_) {
	while (defined(my $subtype = shift)) {
	    $subtypes->{$subtype} = $handler;
	}
	return $handler;
    }

    # Set all the subtypes
    foreach my $subtype (pbMessageSubtypeValues($type)) {
	$subtypes->{$subtype} = $handler;
    }
    return $handler;
}

sub _noop {
}


1;
