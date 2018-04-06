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

package OpenFlow::NBAPI::Util::Logger;

BEGIN {
    our $VERSION = "0.1";
}

use threads;
use threads::shared;

use base qw(Exporter);
use strict;

use Scalar::Util qw(looks_like_number);

our @EXPORT_LEVELS = qw(
    VERBOSE DEBUG TRACE INFO WARN ERROR NONE
    );

our @EXPORT_SUBS = qw(
    verboseLog debugLog traceLog infoLog warnLog errorLog writeLog
    logOutput logLevel levelList levelName
    showDate showTime showTZ showThread showLevel
    );

our @EXPORT_OK = (@EXPORT_LEVELS, @EXPORT_SUBS);

our %EXPORT_TAGS = (
    all => \@EXPORT_OK,
    levels => \@EXPORT_LEVELS,
    subs => \@EXPORT_SUBS
    );

use constant VERBOSE => 1;
use constant DEBUG   => 2;
use constant TRACE   => 3;
use constant INFO    => 4;
use constant WARN    => 5;
use constant ERROR   => 6;
use constant NONE    => 100;

use constant _LEVEL => {
    VERBOSE() => 'VERBOSE',
    DEBUG()   => 'DEBUG',
    TRACE()   => 'TRACE',
    INFO()    => 'INFO',
    WARN()    => 'WARN',
    ERROR()   => 'ERROR',
    NONE()    => 'NONE'
};

use constant _NAME => {
    'VERBOSE' => VERBOSE(),
    'DEBUG'   => DEBUG(),
    'TRACE'   => TRACE(),
    'INFO'    => INFO(),
    'WARN'    => WARN(),
    'ERROR'   => ERROR(),
    'NONE'    => NONE()
};

use constant _MIN_LEVEL     => VERBOSE;
use constant _DEFAULT_LEVEL => WARN;
use constant _MAX_LEVEL     => ERROR;

use Carp;
use POSIX qw(strftime);

our $_output = undef;

our $_mutex :shared = 1;
our $_level :shared = _DEFAULT_LEVEL;
our $_showDate :shared = 1;
our $_showTime :shared = 1;
our $_showTZ   :shared = 1;
our $_showThread :shared = 1;
our $_showLevel :shared = 1;

sub logOutput {
    if (@_ && defined($_output)) {
	carp "Cannot reset log output.";
	return $_output;
    }
    $_output = shift if @_;
    $_output = *STDERR unless defined($_output);
    autoflush $_output 1;
    return $_output;
}

sub logLevel {
    lock $_mutex;

    if (@_) {
	my $level = shift;
	unless (looks_like_number($level)) {
	    $level = _NAME->{$level};
	    defined $level or return undef;
	}
	$_level = $level;
    }
    return $_level;
}

sub levelList {
    return sort { _NAME->{$b} <=> _NAME->{$a} } keys %{_NAME()};
}

sub levelName {
    my $level = shift || logLevel();
    return _LEVEL->{$level} || $level;
}

sub showDate {
    lock $_mutex;

    $_showDate = shift if @_;
    return $_showDate;
}

sub showTime {
    lock $_mutex;

    $_showTime = shift if @_;
    return $_showTime;
}

sub showTZ {
    lock $_mutex;

    $_showTZ = shift if @_;
    return $_showTZ;
}

sub showThread {
    lock $_mutex;

    $_showThread = shift if @_;
    return $_showThread;
}

sub showLevel {
    lock $_mutex;

    $_showLevel = shift if @_;
    return $_showLevel;
}

sub _normalizeLevel {
    my $level = shift;
    $level = _MIN_LEVEL if $level < _MIN_LEVEL;
    $level = _MAX_LEVEL if $level > _MAX_LEVEL;
    return $level;
}

sub writeLog {
    my $level = shift;
    my $thing = shift;

    lock $_mutex;

    $level >= logLevel() or return 0;

    my $msg = "";
    my $tfmt = "";
    $tfmt .= "%F " if showDate();
    $tfmt .= "%T " if showTime();
    $tfmt .= "%Z " if showTZ();
    $msg .= strftime($tfmt, localtime) if $tfmt;
    $msg .= "(tid " . threads->tid() . ") " if showThread();
    $msg .= "[" . levelName($level) . "] " if showLevel();
    $msg .= $thing;
    my $fh = logOutput();
    print $fh "$msg\n";
}

sub verboseLog {
    writeLog(VERBOSE, @_);
}

sub debugLog {
    writeLog(DEBUG, @_);
}

sub traceLog {
    writeLog(TRACE, @_);
}

sub infoLog {
    writeLog(INFO, @_);
}

sub warnLog {
    writeLog(WARN, @_);
}

sub errorLog {
    writeLog(ERROR, @_);
}


1;
