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

package OpenFlow::NBAPI::Util::Timer;

use threads;
use threads::shared;
use strict;

use base qw(OpenFlow::NBAPI::Base::Shared Exporter);
use fields qw(_heap _heapNotify _heapSize _id _isRunning _nodeCount _tid);

our @EXPORT_CONST = qw();
our @EXPORT_OK = (@EXPORT_CONST);
our %EXPORT_TAGS = (
    all => \@EXPORT_OK,
    constants => \@EXPORT_CONST,
    );

__PACKAGE__->_create_accessors();

use Scalar::Util qw(looks_like_number);

use OpenFlow::NBAPI::Util::Logger qw(:all);

use constant _DEFAULT_LOG_LEVEL => TRACE;
use constant _INITIAL_HEAP_SIZE => 16;
use constant _CALLBACK          => __PACKAGE__ . "::Callback";

our $_class :shared = __PACKAGE__;
our $_classRef :shared = \$_class;
our $_numTimers :shared = 0;
our $_timerMap :shared = &share({});

sub init {
    my $self = shift;

    $self->SUPER::init(@_) or return undef;
    my $id;
    {
	lock $_classRef;
	$id = ++$_numTimers;
	$self->id($id);
	$_timerMap->{$id} = $self;
    }
    $self->_heap(&share([]));
    $self->_heapNotify(0);
    $self->_heapSize(_INITIAL_HEAP_SIZE);
    $self->_heapExpand();
    $self->_isRunning(0);
    $self->_nodeCount(0);
    $self->_start() or do {
	lock $_classRef;
	delete $_timerMap->{$id};
	return undef;
    };
    return 1;
}

sub cancelCallback {
    my $self = shift;
    my $cb = shift or return undef;

    (defined($cb->_timerID) && $cb->_timerID == $self->id) or do {
	$self->_log("callback not scheduled with this timer; cannot cancel", ERROR);
	return undef;
    };

    my $node = $cb->_node or do {
	$self->_log("callback already canceled", DEBUG);
	return 0;
    };

    $node->{idx} >= 0 or do {
	$self->_log("callback already executed", DEBUG);
	return 0;
    };
    
    {
	my $heap = $self->_heap;
	lock $heap;
	return 0 unless $self->_isRunning;
	$self->_heapRemove($node) or do {
	    my $name = $cb->name || "<unknown>";
	    $self->_log("failed to cancel callback: $name", ERROR);
	    return undef;
	};
    }
    $cb->_node(undef);
    return 1;
}

sub getTimer {
    my $invocant = shift;
    my $id = shift or return undef;

    {
	lock $_classRef;
	return $_timerMap->{$id};
    }
}

sub id {
    my $self = shift;

    if (@_) {
	$self->_id(shift) unless defined $self->_id;
    }
    return $self->_id;
}

sub purge {
    my $self = shift;

    my $heap = $self->_heap;
    lock $heap;
    my $size = $self->_heapSize;
    for (my $i = 0; $i < $size; $i++) {
	$heap->[$i] = undef;
    }
    $self->_notifyHeap();
    return 1;
}

sub scheduleCallback {
    my $self = shift;
    my $time = shift;
    my $interval = looks_like_number $_[0] ? shift : 0;
    my $name = shift;

    my $cb = _CALLBACK->new();
    $cb->name(shared_clone($name));
    if (@_) {
	my $args = &share([]);
	for (@_) {
	    push @$args, shared_clone($_);
	}
	$cb->args($args);
    }
    $cb->_timerID($self->id);
    my $node = $self->_newNode($time, $interval, $cb);
    $cb->_node($node);
    $self->_heapAdd($node) or do {
	$self->_log("failed to schedule callback '$name'; time=$time, interval=$interval", ERROR);
	return undef;
    };
    return $cb;
}

sub stop {
    my $self = shift;

    {
	my $heap = $self->_heap;
	lock $heap;
	$self->_isRunning(0);
	$self->_notifyHeap();
    }
    {
	lock $_classRef;
	delete $_timerMap->{$self->id};
    }
    return 1;
}

# Adds the specified node.
# Returns a true value on success, or a false value on failure.
sub _heapAdd {
    my $self = shift;
    my $node = shift or return undef;

    my $heap = $self->_heap;
    lock $heap;
    my $i = $self->_nodeCount;
    if ($i >= $self->_heapSize) {
	$self->_heapExpand();
    }
    $self->_heapSetNode($i, $node);
    while ($i > 0) {
	my $i_p = int(($i - 1) / 2);
	my $parent = $heap->[$i_p];
	last if $node->{time} >= $parent->{time};
	$self->_heapSetNode($i, $parent);
	$self->_heapSetNode($i_p, $node);
	$i = $i_p;
    }
    ++$self->{_nodeCount};
    $self->_notifyHeap(1);
    return 1;
}

sub _heapExpand {
    my $self = shift;

    my $heap = $self->_heap;
    lock $heap;
    push @$heap, (undef) x $self->_heapSize;
    $self->_heapSize(scalar @$heap);
}

# Removes the specified node or the top node, if none specified.
# Returns the deleted node or undef on error.
sub _heapRemove {
    my $self = shift;
    my $node = shift;

    my $heap = $self->_heap;
    lock $heap;
    $self->_nodeCount > 0 or return undef;
    $node or $node = $heap->[0];
    my $i = $node->{idx};
    $node->{idx} = -1;
    my $count = --$self->{_nodeCount};
    my $last = $count > 0 ? $heap->[$count] : undef;
    $self->_heapSetNode($i, $last);
    $self->_heapSetNode($count, undef) if $count > 0;
    while ($i < $count - 1) {
	my $i_min = $i;
	my $i_l = (2 * $i) + 1;
	my $i_r = (2 * $i) + 2;
	$i_min = $i_l if ($i_l < $count && $heap->[$i_l]->{time} <= $heap->[$i_min]->{time});
	$i_min = $i_r if ($i_r < $count && $heap->[$i_r]->{time} <= $heap->[$i_min]->{time});
	last if $i_min == $i;
	my $node_i = $heap->[$i];
	my $node_i_min = $heap->[$i_min];
	$self->_heapSetNode($i, $node_i_min);
	$self->_heapSetNode($i_min, $node_i);
	$i = $i_min;
    }
    $self->_notifyHeap(1);
    return $node;
}

sub _heapSetNode {
    my $self = shift;
    my $i = shift;
    my $node = shift;

    my $heap = $self->_heap;
    lock $heap;
    $heap->[$i] = $node;
    $node->{idx} = $i if $node;
    $self->_heapNotify(1) if ($i == 0);
}

# Returns the top node.
sub _heapTop {
    my $self = shift;

    my $heap = $self->_heap;
    lock $heap;
    return $heap->[0];
}

sub _log {
    my $invocant = shift;
    my $msg = shift;
    my $level = shift || _DEFAULT_LOG_LEVEL;
    my $id = ref $invocant ? " " . $invocant->id : "";
    writeLog($level, "Timer${id}: $msg");
}

sub _newNode {
    my $self = shift;
    my $time = shift or return undef;
    my $interval = shift;
    my $cbRef = shift;

    my $node = &share({});
    $node->{idx} = -1;
    $node->{time} = $time;
    $node->{ival} = $interval;
    $node->{cb} = shared_clone($cbRef);
    return $node;
}

sub _notifyHeap {
    my $self = shift;
    my $conditional = shift;

    return if $conditional && ! $self->_heapNotify;

    my $heap = $self->_heap;
    lock $heap;
    cond_signal $heap;
    $self->_heapNotify(0);
}

sub _start {
    my $self = shift;

    my $heap = $self->_heap;
    lock $heap;
    return 1 if $self->_isRunning;
    $self->_isRunning(1);
    my $thread = threads->new(\&_timer, $self) or do {
	$self->_isRunning(0);
	$self->_log("failed to start timer thread: $!", ERROR);
	return undef;
    };
    $self->_tid($thread->tid());
    $thread->detach();
    return 1;
}

sub _timer {
    my $self = shift;

    $self->_log("starting timer thread");
    RUN: while ($self->_isRunning) {
	# Wait for the next scheduled event or other significant event
	# (such as a change in the heap top, or shutdown of the timer)
	{
	    my $heap = $self->_heap;
	    lock $heap;
	    last RUN unless $self->_isRunning; # avoid race with stop()
	    if (my $node = $self->_heapTop()) {
		my $time = $node->{time};
		$self->_log("next scheduled event at " . $time, DEBUG);
		# Note: cond_timedwait may time out slightly before the specified time;
		# add one second to ensure that the event is not early
		cond_timedwait $heap, ($time + 1);
	    }
	    else {
		$self->_log("no scheduled events", DEBUG);
		cond_wait $heap;
	    }
	}
	# Process all elapsed timer events
	while (my $node = $self->_heapTop()) {
	    last RUN unless $self->_isRunning;
	    my $now = time();
	    last if $node->{time} > $now;
	    $self->_heapRemove($node);
	    if ((my $ival = $node->{ival}) > 0) {
		# Schedule repeated event
		$self->_log("scheduling event to repeat in $ival seconds", DEBUG);
		$node->{time} = $now + $ival;
		$self->_heapAdd($node);
	    }
	    my $cbRef = $node->{cb};
	    my $cbName = $cbRef->name;
	    my $cbArgs = $cbRef->args;
	    $self->_log("scheduled callback: $cbName", DEBUG);
	    eval {
		no strict 'refs';
		&$cbName(@$cbArgs);
	    };
	    $self->_log("error in scheduled callback $cbName: $@", ERROR) if $@;
	}
    }
    $self->_log("timer thread terminated");
}


package OpenFlow::NBAPI::Util::Timer::Callback;

use threads::shared;
use strict;

use base qw(OpenFlow::NBAPI::Util::Callback);
use fields qw(_node _timerID);

__PACKAGE__->_create_accessors();

use constant _TIMER => "OpenFlow::NBAPI::Util::Timer";

# override
sub init {
    my $self = shift;

    $self->SUPER::init(@_) or return undef;
    $self->_node(undef);
    $self->_timerID(undef);
    return 1;
}

sub cancel {
    my $self = shift;

    my $timerID = $self->_timerID or return 0;
    my $timer = _TIMER->getTimer($timerID) or return 0;
    return $timer->cancelCallback($self);
}


1;
