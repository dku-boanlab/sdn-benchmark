## Preliminaries

If you haven't already done so, please read the [EULA] [].

[EULA]: LICENSE.html "End-User License"

## Contents

This distribution includes

* A pre-built SEFloodlight runtime,
* An audit subsystem,
* An OpenFlow NorthboundAPI, and
* Associated documentation, utilities, and development components.

## Pre-Configuration

We highly recommend that you configure your OpenFlow switch to run
in secure mode (cf., running as a "dumb" switch when disconnected
from an OpenFlow controller).

For example, for Open vSwitch,

<code>&nbsp; &nbsp; ovs-vsctl set-fail-mode </code>_bridge_<code> secure</code>

configures the switch to not set up flows on its own when the controller
connection fails.

## Quick Start

The following will start the SEFloodlight controller:

		cd runtime
		java -jar SEFloodlight.jar

Alternatively, for *nix-based systems, you can enter

		cd runtime
		./sefloodlight.sh

For information on floodlight, go [here] [fl].

[fl]: http://floodlight.openflowhub.org/ "Floodlight"

## SEFloodlight Overview

* This is an enhanced version of the Floodlight OpenFlow controller that
  [provides and enforces privilege-based OpenFlow operations] [1].
* SEFloodlight allows capture of controller [OpenFlow audit events] [2]
  for real-time or batch processing.
* This controller also integrates [SRI's OpenFlow Northbound API floodlight module]
  [3] (which communicates with external applications via Google Protocol Buffers
  messages). This API provides complete access to both asynchronous and synchronous
  OpenFlow controller-to-switch messages, and also provides additional convenience methods.

[1]: doc/config/SEFloodlight/index.html            "SEFloodlight"
[2]: doc/config/AuditDaemon/index.html             "OpenFlow Audit Events"
[3]: doc/config/SENorthboundAPI/NorthboundAPI.html "OpenFlow Northbound API"

## New Features

This release of SEFloodlight

* Replaces the Alias-set Rule Reduction (ARR) algorithm with the more
  comprehensive and efficient Rule-chain Conflict Analysis (RCA)
  algorithm (see the NDSS 2015 paper, "Securing the Software-Defined
  Network Control Layer", "IV. DESIGN OF A SECURE CONTROL MEDIATION
  LAYER").
* Implements flow-rule mediation among multiple OpenFlow switches using
  a [JSON interconnection description file] [4] (caveat emptor: this
  feature has not been well tested).

[4]: doc/config/SEFloodlight/Interconnections.html "Interconnected OpenFlow Switches"

## Sponsors and Acknowledgments

We gratefully acknowledge the support of the Defense Advanced Research
Project (DARPA) Contract No. FA8750-11-C-0249 and the Army Research
Office under the Cyber-TA Research Grant (No. W911NF-06-1-0316). Thank
you to Howie Schrobe, Bob Ladaga, and Cliff Wang, for their program
management support of basic research in Software Defined Network
Security.

## Release Information

		Package build date: Saturday, February 21, 2015 01:16:37 UTC
		Repository revision: 1993:1994M

