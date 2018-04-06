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

package OpenFlow::NBAPI::Util::Module;

BEGIN {
    our $VERSION = "0.1";
}

use threads::shared;
use strict;

use base qw(Exporter);

our @EXPORT_CONSTANTS = qw(
    );
our @EXPORT_SUBS = qw(
    loadModule
    );

our @EXPORT_OK = (@EXPORT_CONSTANTS, @EXPORT_SUBS);

our %EXPORT_TAGS = (
    all       => \@EXPORT_OK,
    constants => \@EXPORT_CONSTANTS,
    subs      => \@EXPORT_SUBS
    );

use Module::Load;

use OpenFlow::NBAPI::Util::Logger qw(:all);

# Map of dynamically loaded modules
# This is not shared, since it needs to reflect accurately
# which modules have been loaded into the thread context
# of the requesting thread at the time the request is made.
our $_moduleMap = {};

sub loadModule {
    my $module = shift or return undef;

    my $newlyLoaded = 0;
    unless ($_moduleMap->{$module}) {
	writeLog(DEBUG, "loadModule: loading module $module");
	eval {
	    load $module; # from Module::Load
	};
	if ($@) {
	    writeLog(ERROR, "loadModule: failed to load module $module: $@");
	    return undef;
	}
	$_moduleMap->{$module} = 1;
	$newlyLoaded = 1;
    }
    if ($newlyLoaded && $module->can("init")) {
	writeLog(DEBUG, "loadModule: initializing module $module");
	return $module->init(@_);
    }
    return $newlyLoaded;
}


1;
