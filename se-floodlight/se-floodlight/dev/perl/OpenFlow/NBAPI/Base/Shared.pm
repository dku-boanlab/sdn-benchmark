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

package OpenFlow::NBAPI::Base::Shared;

BEGIN {
    our $VERSION = "0.1";
}

use threads::shared;

use Carp;
use fields qw(__fieldMutex);
use strict;

our %FIELDS;

sub new {
    my $type = shift;
    my $self = &share(fields::new(ref $type || $type));
    my $fieldMutex :shared;
    $self->{__fieldMutex} = \$fieldMutex;
    $self->init(@_) or return undef;
    return $self;
}

sub __fieldMutex {
    my $self = shift;
    return $self->{__fieldMutex};
}

sub init {
    return 1;
}

sub _create_accessors {
    my $class = shift;

    no strict "refs";
    for my $field (keys %{$class . "::FIELDS"}) {
	# Don't redefine existing accessor methods
	unless ($class->can($field)) {
	    my $slot = $class . "::$field";
	    *$slot = sub {
		my $self = shift;
		my $mutex = $self->{__fieldMutex};
		lock $mutex;
		$self->{$field} = shared_clone(shift) if (@_);
		return $self->{$field};
	    }
	}
    }
}

__PACKAGE__->_create_accessors();

1;
