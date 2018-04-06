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

package OpenFlow::NBAPI::LowLevel::NBOFMatchList;

BEGIN {
    our $VERSION = "0.1";
}

use threads::shared;

use base qw(OpenFlow::NBAPI::Base::Shared);
use fields qw(_rootNode _nodeCount);

use strict;

use Carp;

use OpenFlow::NBAPI::Util::Logger qw(:all);
use OpenFlow::NBAPI::Util::OFMatch qw(:all);

__PACKAGE__->_create_accessors();

use constant _LOWLEVEL          => "OpenFlow::NBAPI::LowLevel";
use constant _NODE              => _LOWLEVEL . "::NBOFMatchNode";

use constant _DEFAULT_LOG_LEVEL => TRACE;

sub init {
    my $self = shift;

    $self->SUPER::init() or return undef;
    $self->_reset();
    return 1;
}

sub _log {
    my $invocant = shift;
    my $msg = shift;
    my $level = shift || _DEFAULT_LOG_LEVEL;
    writeLog($level, "NBOFMatchList: $msg");
}

sub _reset {
    my $self = shift;

    lock $self;
    $self->_rootNode(undef);
    $self->_nodeCount(0);
}

# add
#   Finds a match in the list, adding it if not found,
#   optionally executes a callback function on the found/added
#   match node, and returns the result of the callback function.
#   If no callback function is provided, the return value
#   is 1 if the match was newly added, 0 otherwise.
sub add {
    my $self = shift;
    my $nbOFMatch = shift or return 0;
    my $nodeCB = shift;

    lock $self;
    my $nodeRef;
    for ($nodeRef = \$self->{_rootNode}; my $node = $$nodeRef; $nodeRef = \$node->{_next}) {
	my $compare = matchCompare($node->_nbOFMatch, $nbOFMatch);
	if (isEqual($compare)) {
	    return $nodeCB ? &$nodeCB($node) : 0;
	}
    }
    my $newNode = $self->_newNode($nbOFMatch);
    $$nodeRef = $newNode;
    return $nodeCB ? &$nodeCB($newNode) : 1;
}

# clear
#   Removes all matches from the list, effectively resetting it
#   to its initial state.
sub clear {
    my $self = shift;

    $self->_reset();
}

# find
#   Finds all matches of the specified match, optionally executing
#   a callback function on each matching node.  If a callback function
#   is provided, a list of the results of applying the function to
#   the matching nodes is returned (similar to map); otherwise, a list
#   of matching nodes is returned.
#   By default, matching is exact (EQUAL); NARROWER (WIDER)
#   can be specified to return all matches more specific than
#   (more general than) the specified match.
sub find {
    my $self = shift;
    my $nbOFMatch = shift or return 0;
    my $condition = shift || EQUAL;
    my $nodeCB = shift || \&_identity;

    return $self->_findAllMatches($nbOFMatch, $condition, $nodeCB, 0);
}

# getMatches
#   Returns all matches in the list for a given match.
#   By default, matching is exact (EQUAL); NARROWER (WIDER)
#   can be specified to return all matches more specific than
#   (more general than) the specified match.
sub getMatches {
    my $self = shift;
    my $nbOFMatch = shift;
    my $condition = shift || EQUAL;

    return $self->find($nbOFMatch, $condition, \&_getMatch);
}

# getReferences
#   Returns a list of references for matches of the specified match.
#   By default, matching is exact (EQUAL); NARROWER (WIDER)
#   can be specified to return also the references of all matches
#   more specific than (more general than) the specified match.
#   Returns an empty list if no matches of the specified match are found.
sub getReferences {
    my $self = shift;
    my $nbOFMatch = shift;
    my $condition = shift || EQUAL;

    return $self->find($nbOFMatch, $condition, \&_getReference);
}

# remove
#   Finds all matches of the specified match, optionally
#   executes a callback function on each matching node, removing
#   the node from the list if the callback function returns a non-zero value,
#   and returns a list of the non-zero results.
#   If no callback function is supplied, all matching nodes are removed,
#   and a list of the removed nodes is returned.
#   By default, matching is exact (EQUAL); NARROWER (WIDER)
#   can be specified to include matches  more specific than
#   (more general than) the specified match.
sub remove {
    my $self = shift;
    my $nbOFMatch = shift or return undef;
    my $condition = shift || EQUAL;
    my $nodeCB = shift || \&_identity;

    return $self->_findAllMatches($nbOFMatch, $condition, $nodeCB, 1);
}

# size
#   Returns the number of match nodes in the list
sub size {
    my $self = shift;
    lock $self;
    return $self->_nodeCount;
}

sub _findAllMatches {
    my $self = shift;
    my $inMatch = shift;
    my $condition = shift;
    my $nodeCB = shift || \&_identity;
    my $delete = shift || 0;

    lock $self;
    my $resultList = &share([]);
    for (my $nodeRef = \$self->{_rootNode}; my $node = $$nodeRef; $nodeRef = \$node->{_next}) {
	my $compare = matchCompare($node->_nbOFMatch, $inMatch);
	next unless isCondition($compare, $condition) || isEqual($compare);
	my $cbResult = &$nodeCB($node);
	push @$resultList, $cbResult if (! $delete || $cbResult);
	$self->_deleteNode($nodeRef) if ($delete && $cbResult);
    }
    return $resultList;
}

sub _decrNodeCount {
    my $self = shift;
    lock $self;
    --$self->{_nodeCount};
}

sub _incrNodeCount {
    my $self = shift;
    lock $self;
    ++$self->{_nodeCount};
}

sub _deleteNode {
    my $self = shift;
    my $nodeRef = shift;

    lock $self;
    my $node = $$nodeRef;
    $$nodeRef = $node->_next;
    $self->_decrNodeCount();
}

sub _newNode {
    my $self = shift;
    my $nbOFMatch = shift;

    # Make a copy of nbOFMatch, excluding auxData, in part to prevent
    # possible changes to nbOFMatch from breaking the match semantics
    # of the list, and to enable separate tracking of changes to auxData.
    my $nodeMatch = newNBOFMatch($nbOFMatch->sbOFMatch, $nbOFMatch->datapathID, $nbOFMatch->pInReason);
    my $node = _NODE->new();
    $node->_nbOFMatch($nodeMatch);
    $self->_incrNodeCount();

    return $node;
}

sub _identity { shift; }

sub _getMatch { $_[0]->getMatch(); }

sub _getReference { $_[0]->getReference(); }


package OpenFlow::NBAPI::LowLevel::NBOFMatchNode;

use threads::shared;

use base qw(OpenFlow::NBAPI::Base::Shared);
use fields qw(
    pending _nbOFMatch _reference _next
    );

__PACKAGE__->_create_accessors();

sub init {
    my $self = shift;

    $self->SUPER::init() or return undef;
    $self->pending(undef);
    $self->_nbOFMatch(undef);
    $self->_reference(undef);
    $self->_next(undef);
    return 1;
}

sub getMatch {
    my $self = shift;

    lock $self;
    return $self->_nbOFMatch;
}

sub getReference {
    my $self = shift;

    lock $self;
    return $self->_reference;
}

sub setReference {
    my $self = shift;
    my $ref = shift;

    lock $self;
    $self->_reference($ref);
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

    my $absTimeout = time() + $timeout if defined $timeout;
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


1;
