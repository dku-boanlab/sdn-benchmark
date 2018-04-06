/*

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

 */

package net.floodlightcontroller.linkdiscovery.internal;

import java.util.Collection;
import java.util.Set;

import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.security.IRegisterSEModule;
import net.floodlightcontroller.security.ISEFloodlightService;

import org.openflow.protocol.factory.BasicFactory;
import org.openflow.util.ProducerConsumer;
import org.slf4j.LoggerFactory;

public class SELinkDiscoveryManager
	extends LinkDiscoveryManager
	implements IRegisterSEModule {

    protected BasicFactory basicFactory;

    @Override
    protected BasicFactory getOFMessageFactory ()													// LinkDiscoveryManager
    {
    	return (basicFactory != null) ? basicFactory: floodlightProvider.getOFMessageFactory ();
    }

	@Override
	public void setOFMessageFactory (BasicFactory msgFactory)										// IRegisterSEModule
	{
		basicFactory = msgFactory;
	}

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies ()					// IFloodlightModule
    {
        Collection<Class<? extends IFloodlightService>> l = super.getModuleDependencies ();
        l.add (ISEFloodlightService.class);
        return l;
    }

    @Override
    public void init (FloodlightModuleContext context) throws FloodlightModuleException				// IFloodlightModule
    {
    	log = LoggerFactory.getLogger (SELinkDiscoveryManager.class);
    	super.init (context);
    }

    @Override
    public void startUp (FloodlightModuleContext context) throws FloodlightModuleException			// IFloodlightModule
    {
    	ProducerConsumer producerConsumer = ProducerConsumer.getSingleton ();

    	Set<Class<?>> ifaces = producerConsumer.registerConsumer (this);

    	if (!ifaces.contains (IRegisterSEModule.class))
    		log.warn ("Failed registration: " + IRegisterSEModule.class);

    	super.startUp (context);
    }

}

//Local Variables:
//tab-width: 4
//End:
