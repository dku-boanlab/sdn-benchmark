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

package OpenFlow::NBAPI::Util::Value;

BEGIN{
    our $VERSION = "0.1";
}

use threads::shared;
use strict;

use base qw(Exporter);

use Carp;
use Scalar::Util qw(blessed);

use OpenFlow::NBAPI::LowLevel::PB::ValuesPB;

our @EXPORT_SUBS = qw(
    boolean
    byteArray
    convertValue
    extractValue
    int32
    int64
    isNullValue
    newValue
    string
    toValue
    valueCompare
    valuesEqual
    );

our @EXPORT_OK = (@EXPORT_SUBS);

our %EXPORT_TAGS = (
    all       => \@EXPORT_OK,
    subs      => \@EXPORT_SUBS
    );

use constant _VALUE_COMP => {
    anInt32 => \&_intCompare,
    anInt64 => \&_intCompare,
    aBool => \&_boolCompare,
    aString => \&_stringCompare,
    byteArray => \&_stringCompare,
    iSockAddr => \&_noCompare,
    hostEnt => \&_noCompare,
    addrInfo => \&_noCompare,
    aValue => \&_valuesCompare,
    dict => \&_dictCompare,
    ofAction => \&_noCompare,
    ofMatch => \&_matchCompare,
};

use constant _VALUE_CONV => {
    anInt32 => \&_ident,
    anInt64 => \&_ident,
    aBool => \&_ident,
    aString => \&_ident,
    byteArray => \&_ident,
    iSockAddr => \&_newInetSockAddr,
    hostEnt => \&_newHostEnt,
    addrInfo => \&_newAddrInfoList,
    aValue => \&_ident,
    dict => \&_newNameValList,
    ofAction => \&_ident,
    ofMatch => \&_ident,
};

sub boolean {
    my $val = shift;

    return newValue('aBool', $val ? 1 : 0);
}

sub byteArray {
    my $val = shift;

    return newValue('byteArray', $val);
}

#
# Converts a ValuePB into a more direct Perl representation
# of the value.
#
# The simple ValuePB types (anInt32, anInt64, aBool, aString,
# byteArray) become scalars.  NameValPB (dict) becomes a
# Perl hash, and ValuePB arrays become arrays of converted
# ValuePB objects.  All other ValuePB types (such as HostEntPB,
# AddrInfoPB, InetSockAddrPB) are left as is; it might make more
# sense to convert these other structured PB types to Perl hashes,
# but that's essentially what they are anyway.
#
sub convertValue {
    defined (my $value = extractValue(shift)) or return undef;

    ref($value) eq "ARRAY" or return $value;

    # Must be one of the "repeated" fields
    my $arrayRef = $value;
    my @values = @$arrayRef;
    $value = shift @values or return undef;

    blessed $value or return undef;

    $value->isa("NameValPB") and do {
	my $dict = {};
	do {
	    my $name = convertValue($value->name);
	    $dict->{$name} = convertValue($value->value);
	} while $value = shift @values;
	return $dict;
    };

    $value->isa("ValuePB") and do {
	my $list = [];
	do {
	    push @$list, convertValue($value);
	} while $value = shift @values;
	return $list;
    };

    # An array of some other type (e.g., AddrInfoPB)
    return $arrayRef;
}

sub extractValue {
    my $valuePB = shift or return undef;
    my $valueType = shift if @_;

    (blessed $valuePB && $valuePB->isa("ValuePB")) or do {
	carp("argument is not a ValuePB; cannot extract value");
	return undef;
    };

    # If a type is specified, return it
    return $valuePB->{$valueType} if $valueType;

    # Otherwise, return any type that has a value
    if (my @keys = keys(%$valuePB)) {
	return $valuePB->{$keys[0]};
    }

    return undef;
}

sub int32 {
    my $val = shift;

    return newValue('anInt32', $val);
}

sub int64 {
    my $val = shift;

    return newValue('anInt32', $val);
}

sub isNullValue {
    my $valuePB = shift or return 0;

    (blessed $valuePB && $valuePB->isa("ValuePB")) or return 0;
    for my $type (keys %{_VALUE_CONV()}) {
	return 0 if defined $valuePB->$type();
    }
    return 1;
}

sub newValue {
    my $type = shift;

    my $valuePB = &share(ValuePB->new());
    $type or return $valuePB;

    my $conv = _VALUE_CONV->{$type} or do {
	carp "unknown value type $type";
	return undef;
    };
    $valuePB->$type(&$conv(@_));
    return $valuePB;
}

sub string {
    my $val = shift;

    return newValue('aString', $val);
}

# Converts a Perl value to a ValuePB.  Scalars are
# converted to strings (aString).  Undefined values
# are converted into ValuePB nulls (ValuePB with no
# fields set).  Perl hashes and arrays are recursively
# converted to dict (NameValPB) and aValue (ValuePB),
# respectively.  ValuePB values are left as is.
sub toValue {
    my $val = _deref(shift);

    defined $val or return newValue(); # null

    my $ref = ref($val) or do {
	return newValue("aString", $val);
    };

    $ref eq "HASH" and do {
	my @dict = ();
	for my $key (keys %$val) {
	    my $name = newValue("aString", $key);
	    my $value = toValue($val->{$key});
	    push @dict, [$name, $value];
	}
	return newValue("dict", @dict);
    };

    $ref eq "ARRAY" and do {
	my $aValue = &share([]);
	for my $value (@$val) {
	    push @$aValue, toValue($value);
	}
	return newValue("aValue", $aValue);
    };

    blessed $val or return undef;

    $val->isa("ValuePB") and return $val;

    $val->isa("OFMatchPB") and return newValue("ofMatch", $val);

    $val->isa("OFActionPB") and return newValue("ofAction", $val);

    $val->isa("NameValPB") and return newValue("dict", [$val->name, $val->value]);

    $val->isa("InetSockAddrPB") and return newValue("iSockAddr", $val);

    $val->isa("HostEntPB") and return newValue("hostEnt", $val);

    $val->isa("AddrInfoPB") and return newValue("addrInfo", $val);

    carp "Error in toValue: unconvertible value";
    return undef;
}

sub valueCompare {
    my $valuePB1 = shift;
    my $valuePB2 = shift;

    return 0 unless defined $valuePB1 || defined $valuePB2;
    return undef unless defined $valuePB1 && defined $valuePB2;

    for my $type (keys %{_VALUE_COMP()}) {
	my $val1 = $valuePB1->$type();
	my $val2 = $valuePB1->$type();
	next unless defined $val1 && defined $val2;
	my $comp = _VALUE_COMP->{$type};
	return &$comp($val1, $val2);
    }

    return undef;
}

sub valuesEqual {
    my $valuePB1 = shift;
    my $valuePB2 = shift;

    my $compare = valueCompare($valuePB1, $valuePB2);
    return defined $compare && $compare == 0;
}

sub _deref {
    my $val = shift;
    defined($val) or return undef;
    $val = $$val while (ref($val) eq "REF" || ref($val) eq "SCALAR");
    return $val;
}

sub _ident {
    shared_clone(shift);
}

sub _intCompare {
    my $val1 = shift;
    my $val2 = shift;

    return $val1 <=> $val2;
}

sub _boolCompare {
    my $val1 = (shift) ? 1 : 0;
    my $val2 = (shift) ? 1 : 0;

    return $val1 <=> $val2;
}

sub _stringCompare {
    my $val1 = shift;
    my $val2 = shift;

    return "$val1" cmp "$val2";
}

sub _noCompare {
    carp "ERROR: unimplemented ValuePB comparison";
    return undef;
}

sub _valuesCompare {
    my $ary1 = shift;
    my $ary2 = shift;

    my $len1 = scalar(@$ary1);
    my $len2 = scalar(@$ary2);
    return undef unless $len1 == $len2;
    for (my $i = 0; $i < $len1; $i++) {
	return undef unless valuesEqual($ary1->[$i], $ary2->[$i]);
    }
    return 0;
}

sub _dictCompare {
    my $ary1 = shift;
    my $ary2 = shift;

    my $len1 = scalar(@$ary1);
    my $len2 = scalar(@$ary2);
    return undef unless $len1 == $len2;
    OUTER: for (my $i = 0; $i < $len1; $i++) {
	my $nv1 = $ary1->[$i];
	INNER: for (my $j = 0; $j < $len2; $j++) {
	    my $nv2 = $ary2->[$j];
	    next INNER unless valuesEqual($nv1->name, $nv2->name);
	    next OUTER if valuesEqual($nv1->value, $nv2->value);
	    return undef; # values not equal
	}
	return undef; # no matching key
    }
    return 0; # all keys and values match
}

sub _matchCompare {
    my $val1 = shift;
    my $val2 = shift;

    return matchCompare($val1, $val2);
}

sub _newInetSockAddr {
    # TBD
}

sub _newHostEnt {
    # TBD
}

sub _newAddrInfoList {
    # TBD
}

sub _newNameValList {
    my $list = &share([]);
    while (my $pair = shift) {
	my $nameVal = &share(NameValPB->new());
	$nameVal->name(shared_clone($pair->[0]));
	$nameVal->value(shared_clone($pair->[1]));
	push @$list, $nameVal;
    }
    return $list;
}


1;
