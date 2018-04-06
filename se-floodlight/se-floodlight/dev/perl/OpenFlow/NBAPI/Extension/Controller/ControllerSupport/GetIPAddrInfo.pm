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

package OpenFlow::NBAPI::Extension::Controller::ControllerSupport::GetIPAddrInfo;

use threads::shared;
use strict;

use OpenFlow::NBAPI::Util::Conversion qw(:all);
use OpenFlow::NBAPI::Util::Logger qw(:all);

sub parseRequest {
    my $invocant = shift;
    my $request = shift or return undef;
    my ($ipV4Addr, $_mask) = parseIPv4(shift);
    my $arpMS = shift;
    my $dpid = shift;
    my $switchPort = shift;
    my $exPort = shift;

    $request->addRequiredArg("ipV4Addr", "anInt32", $ipV4Addr) or return undef;
    $request->addOptionalArg("ARP", "anInt32", $arpMS) or return undef;
    $request->addOptionalArg("dpid", "anInt64", $dpid) or return undef;
    $request->addOptionalArg("switchPort", "anInt32", $switchPort) or return undef;
    $request->addOptionalArg("exPort", "anInt32", $exPort) or return undef;
    $request->hasReturnValue(1);
    # Hack to cope with the inability of ValuePB to encode an empty list;
    # GetIPAddrInfo will return an empty ValuePB (= null/undef) when it has
    # no info, which would be interpreted as a request failure in ControllerContext.
    # The following causes the null/undef to be replaced by an empty list.
    $request->defaultReturnValue([]);

    return $request;
}


1;
