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

package OpenFlow::NBAPI::LowLevel::PriorityQueue;

BEGIN {
    our $VERSION = "0.1";
}

use threads::shared;
use Thread::Queue;

use fields qw(
    highest lowest default
    _queue
    );
use strict;

use Carp;

sub new {
    my $class = shift;
    my $self = &share(fields::new(ref $class || $class));
    $self->init() or return undef;
    return $self;
}

sub init {
    my $self = shift;
    lock $self;

    $self->{_queue} = shared_clone(Thread::Queue->new());
    return 1;
}

sub highest {
    my $self = shift;
    lock $self;

    $self->{highest} = shift if @_;
    return ($self->{highest} || 1);
}

sub lowest {
    my $self = shift;
    lock $self;

    $self->{lowest} = shift if @_;
    return ($self->{lowest} || 999999);
}

sub default {
    my $self = shift;
    lock $self;

    $self->{default} = shift if @_;
    return ($self->{default} || $self->highest);
}

sub enqueue {
    my $self = shift;
    lock $self;

    my $obj = shift or do {
	carp "No object to enqueue";
	return 0;
    };
    my $priority = shift || $self->default;
    $priority = $self->highest if ($priority < $self->highest);
    $priority = $self->lowest if ($priority > $self->lowest);

    my $queue = $self->{_queue};
    lock $queue;
    my $pending = $queue->pending();
    my $index;
    for ($index = $pending - 1; $index >= 0; $index--) {
	my ($qobj, $qpri) = @{$queue->peek($index)};
	last if ($priority >= $qpri);
    }
    $index++;
    my $entry = [$obj, $priority];
    $queue->insert($index, $entry);
    cond_signal $self;
    return @$entry;
}

sub dequeue {
    my $self = shift;
    lock $self;

    my $queue = $self->{_queue};
    my @entry = @{$queue->dequeue()};
    cond_signal $self if ($self->pending() > 0);
    return @entry;
}

sub peek {
    my $self = shift;
    lock $self;

    my $queue = $self->{_queue};
    return @{$queue->peek(@_)};
}

sub pending {
    my $self = shift;
    lock $self;

    return $self->{_queue}->pending();
}


1;
