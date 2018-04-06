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

package OpenFlow::NBAPI::LowLevel::RefList;

BEGIN {
    our $VERSION = "0.1";
}

use threads::shared;

use base qw(OpenFlow::NBAPI::Base::Shared);
use fields qw(_refList);

use strict;

use Carp;
use Scalar::Util qw(refaddr);

__PACKAGE__->_create_accessors();

sub init {
    my $self = shift;

    $self->SUPER::init() or return undef;
    $self->_refList(&share([]));
    return 1;
}

# add
#   Adds a reference to the list, if not already present
#
# Returns
#   1, if reference newly added
#   0 otherwise
sub add {
    my $self = shift;
    my $ref = shift or return 0;

    lock $self;
    my $refs = $self->_refList;
    for (@$refs) {
	return 0 if (_isRefEqual($ref, $_));
    }
    push @$refs, $ref;
    return 1;
}

# copy
#   Returns a new copy of the list.
sub copy {
    my $self = shift;

    my $copy = __PACKAGE__->new();
    my $selfRefs = $self->_refList;
    my $copyRefs = $copy->_refList;
    for (@$selfRefs) {
	push @$copyRefs, $_;
    }
    return $copy;
}

# remove
#   Removes a reference from the list, if present
#
# Returns the length of the list after the removal.
sub remove {
    my $self = shift;
    my $ref = shift or return 0;

    lock $self;
    my $refs = $self->_refList;
    my $newRefs = &share([]);
    for (@$refs) {
	push @$newRefs, $_ if (! _isRefEqual($ref, $_));
    }
    $self->_refList($newRefs);
    return $self->length();
}

# Returns a copy of the reference list
sub getList {
    my $self = shift;

    lock $self;
    my $refs = $self->_refList;
    my $copyRefs = &share([]);
    for (@$refs) {
	push @$copyRefs, $_;
    }
    return $copyRefs;
}

# Tests whether a reference is in the list
sub contains {
    my $self = shift;
    my $ref = shift or return 0;

    lock $self;
    my $refs = $self->_refList;
    for (@$refs) {
	return 1 if (_isRefEqual($ref, $_));
    }
    return 0;
}

# Tests whether the reference list is empty
sub isEmpty {
    my $self = shift;

    return $self->length == 0;
}

# Return the number of references in the list
sub length {
    my $self = shift;

    lock $self;
    return scalar(@{$self->_refList});
}

sub _isRefEqual {
    my $ref1 = shift;
    my $ref2 = shift;

    my $addr1 = is_shared($ref1) || refaddr($ref1);
    my $addr2 = is_shared($ref2) || refaddr($ref2);

    return $addr1 == $addr2;
}


1;
