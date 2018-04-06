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

package OpenFlow::NBAPI::Extension::Controller::ControllerSupport;

use threads::shared;
use strict;

use OpenFlow::NBAPI::Extension::Controller::ControllerSupport::Request qw(:all);
use OpenFlow::NBAPI::Util::Extension qw(:all);
use OpenFlow::NBAPI::Util::Logger qw(:all);
use OpenFlow::NBAPI::Util::Module qw(:all);
use OpenFlow::NBAPI::Util::Value qw(:all);

use constant _FNLIST    => "<FunctionList>";
use constant _PCHECK    => "persistenceCheck";
use constant _REQUEST   => __PACKAGE__ . "::Request";

our $_ctxMap = &share({});

sub genRequest {
    my $invocant = shift;
    my $ctx = shift;
    my $fn = shift;

    $invocant->hasFeature($ctx, $fn) or do {
	$ctx->_log(EXTENSION . " function $fn not supported by controller", ERROR);
	return undef;
    };
    my $request = _REQUEST->new($fn);
    my $fnModule = $invocant->_fnModule($fn);
    $fnModule->parseRequest($request, @_) or return undef;
    my $extMsg = $request->genExtensionMsg() or return undef;
    my $hasReturnValue = $request->hasReturnValue;
    my $defaultReturnValue = $request->defaultReturnValue;
    my $persistenceCheck = $fnModule->can(_PCHECK) ? $fnModule : undef;
    return ($extMsg, $hasReturnValue, $defaultReturnValue, $persistenceCheck);
}

sub hasFeature {
    my $invocant = shift;
    my $ctx = shift;
    my $feature = shift or return 0;

    my $ctxID = $ctx->contextID;
    my $fnMap;
    {
	lock $_ctxMap;
	$fnMap = $_ctxMap->{$ctxID} or do {
	    # Synchronous controller request for list of supported functions
	    my $extRequest = _REQUEST->new(_FNLIST);
	    my $request = $ctx->_sendExtensionRequest(undef, $extRequest->genExtensionMsg(), 1) or do {
		$ctx->_log("failed to retrieve function list for extension " . EXTENSION, ERROR);
		return undef;
	    };
	    my $fnList = $ctx->_requestResult($request);
	    $fnMap = &share({});
	    for my $fn (@$fnList) {
		$fnMap->{$fn} = 1;
	    }
	    $_ctxMap->{$ctxID} = $fnMap;
	};
	# Ensure the requested feature module is loaded, if supported
	my $fn = $feature;
	$fnMap->{$fn} or return 0;
	my $fnModule = $invocant->_fnModule($fn);
	my $newlyLoaded = loadModule($fnModule);
	defined $newlyLoaded or return undef;
	$invocant->_createSubs($ctx, $fn) if $newlyLoaded;
    }
    return 1;
}

# Adds methods to the controller context that provide
# access to ControllerSupport extension functions.
#
# Three methods are added for each function:
#   1. _<function>     - a "private" method for use by the context
#   2. <function>      - a public API method for synchronous calls
#   3. <function>Async - a public API method for asynchronous (timed) calls
# where <function> is the name of the extension function.
#
# Note: the public methods do not support reply callbacks;
# only the context may specify a reply callback (via the private method).
sub _createSubs {
    my $invocant = shift;
    my $ctx = shift;
    my $fn = shift;

    my $ctxClass = ref $ctx;
    my $fnName = $fn;
    my $fnPriv = "_" . $fnName;
    my $fnSync = $fnName;
    my $fnAsync = $fnName . "Async";
    
    no strict "refs";
    unless ($ctxClass->can($fnPriv)) {
	# Define "private" method _<function>
	my $slot = $ctxClass . "::$fnPriv";
	*$slot = sub {
	    my $self = shift;
	    my $replyCB = shift;
	    my $absTimeout = shift;

	    my ($extRequest, $hasReply, $defaultReply, $pCheck) = $invocant->genRequest($self, $fn, @_) or return undef;
	    my $request = $self->_sendExtensionRequest($replyCB, $extRequest, $hasReply, $pCheck) or return undef;
	    return $self->_requestResult($request, $absTimeout, $defaultReply);
	};
    }
    unless ($ctxClass->can($fnSync)) {
	# Define public method <function>
	my $slot = $ctxClass . "::$fnSync";
	*$slot = sub {
	    my $self = shift;

	    return $self->$fnPriv(undef, undef, @_);
	};
    }
    unless ($ctxClass->can($fnAsync)) {
	# Define public method <function>Async
	my $slot = $ctxClass . "::$fnAsync";
	*$slot = sub {
	    my $self = shift;
	    my $timeout = shift || 0;

	    return $self->$fnPriv(undef, absTime($timeout), @_);
	};
    }
    return 1;
}

sub _fnModule {
    my $invocant = shift;
    my $fn = shift;

    return __PACKAGE__ . "::$fn";
}


1;
