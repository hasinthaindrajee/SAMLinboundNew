/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.saml.inbound.validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.gateway.api.FrameworkHandlerResponse;
import org.wso2.carbon.identity.gateway.api.IdentityMessageContext;
import org.wso2.carbon.identity.gateway.api.IdentityRequest;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.processor.handler.request.RequestHandlerException;
import org.wso2.carbon.identity.saml.inbound.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.inbound.request.SAMLIdpInitRequest;
import org.wso2.carbon.identity.saml.inbound.validators.IdPInitSSOAuthnRequestValidator;

import java.io.IOException;

public class IDPInitSAMLValidator extends SAMLValidator {

    private static Logger log = LoggerFactory.getLogger(IDPInitSAMLValidator.class);

    @Override
    public boolean canHandle(MessageContext messageContext) {
        if (messageContext instanceof IdentityMessageContext) {
            IdentityMessageContext identityMessageContext = (IdentityMessageContext) messageContext;
            if (identityMessageContext.getIdentityRequest() instanceof SAMLIdpInitRequest) {
                return true;
            }
            return false;
        }
        return false;
    }


    @Override
    public FrameworkHandlerResponse validate(AuthenticationContext authenticationContext) throws RequestHandlerException {
        super.validate(authenticationContext);
        IdentityRequest identityRequest = authenticationContext.getIdentityRequest();
        if (!((SAMLIdpInitRequest) identityRequest).isLogout()) {
            try {
                SAMLMessageContext messageContext = (SAMLMessageContext) authenticationContext.getParameter("SAMLContext");
                IdPInitSSOAuthnRequestValidator validator = new IdPInitSSOAuthnRequestValidator(messageContext);
                if (validator.validate(null)) {
                    return FrameworkHandlerResponse.CONTINUE;
                }
            } catch (IdentityException e) {
                throw new RequestHandlerException("Error while validating SAAML request");
            } catch (IOException e) {
                throw new RequestHandlerException("Error while validating SAAML request");
            }
        }
        throw new RequestHandlerException("Error while validating SAAML request");
    }

    public String getName() {
        return "IDPInitSAMLValidator";
    }

    public int getPriority(MessageContext messageContext) {
        return 11;
    }
}
