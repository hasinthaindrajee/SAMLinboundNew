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

package org.wso2.carbon.identity.saml.inbound.builders.assertion;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.saml.inbound.context.SAMLMessageContext;

public interface SAMLAssertionBuilder {

    public void init() throws IdentityException;

    /**
     * Encrypt the SAML assertion
     *
     * @param context      SAML assertion to be encrypted
     * @param notOnOrAfter Encrypting credential
     * @param sessionId    Certificate alias against which use to Encrypt the assertion.
     * @return Assertion
     * @throws IdentityException
     */

    public Assertion buildAssertion(AuthenticationContext context, DateTime notOnOrAfter,
                                    String sessionId) throws IdentityException;

}
