/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.wso2.carbon.identity.saml.inbound.internal;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.gateway.api.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.gateway.api.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.gateway.processor.handler.request.AbstractRequestHandler;
import org.wso2.carbon.identity.gateway.processor.handler.response.AbstractResponseHandler;
import org.wso2.carbon.identity.saml.inbound.request.SAMLIdentityRequestFactory;
import org.wso2.carbon.identity.saml.inbound.response.HttpSAMLResponseFactory;
import org.wso2.carbon.identity.saml.inbound.response.SAMLIdpInitResponseHandler;
import org.wso2.carbon.identity.saml.inbound.response.SAMLSPInitResponseHandler;
import org.wso2.carbon.identity.saml.inbound.validator.IDPInitSAMLValidator;
import org.wso2.carbon.identity.saml.inbound.validator.SPInitSAMLValidator;

@Component(
        name = "org.wso2.carbon.identity.saml.inbound.component",
        immediate = true
)
public class Activator implements BundleActivator {

    @Activate
    public void start(BundleContext bundleContext) throws Exception {
        try {
            bundleContext.registerService(HttpIdentityRequestFactory.class, new SAMLIdentityRequestFactory(), null);
            bundleContext.registerService(HttpIdentityResponseFactory.class, new HttpSAMLResponseFactory(), null);

            bundleContext.registerService(AbstractRequestHandler.class, new SPInitSAMLValidator(), null);
            bundleContext.registerService(AbstractRequestHandler.class, new IDPInitSAMLValidator(), null);

            bundleContext.registerService(AbstractResponseHandler.class, new SAMLSPInitResponseHandler(), null);
            bundleContext.registerService(AbstractResponseHandler.class, new SAMLIdpInitResponseHandler(), null);
        } catch (Throwable e) {
            System.out.println("Error while activating component");
        }
    }

    /**
     * This is called when the bundle is stopped.
     *
     * @param bundleContext BundleContext of this bundle
     * @throws Exception Could be thrown while bundle stopping
     */
    public void stop(BundleContext bundleContext) throws Exception {
    }
}
