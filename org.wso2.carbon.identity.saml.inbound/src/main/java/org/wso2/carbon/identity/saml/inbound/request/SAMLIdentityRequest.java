package org.wso2.carbon.identity.saml.inbound.request;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.gateway.processor.request.ClientAuthenticationRequest;
import org.wso2.carbon.identity.saml.inbound.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.inbound.util.SAMLSSOUtil;
import org.wso2.msf4j.Request;

import java.io.UnsupportedEncodingException;

public class SAMLIdentityRequest extends ClientAuthenticationRequest {

    private static Logger log = LoggerFactory.getLogger(SAMLIdentityRequest.class);


    public SAMLIdentityRequest(SAMLIdentityRequestBuilder builder, String uniqueId, String type) {
        super(builder, uniqueId, type);
    }

    public String getRelayState() {
        if (this.getParameter(SAMLSSOConstants.RELAY_STATE) != null) {
            return (String) this.getParameter(SAMLSSOConstants.RELAY_STATE);
        } else {
            try {
                return SAMLSSOUtil.getParameterFromQueryString(this.getQueryString(), SAMLSSOConstants.RELAY_STATE);
            } catch (UnsupportedEncodingException e) {
//                if (log.isDebugEnabled()) {
//                    log.debug("Failed to decode the Relay State ", e);
//                }
            }
        }
        return null;
    }

    public static class SAMLIdentityRequestBuilder extends ClientAuthenticationRequest.ClientAuthenticationRequestBuilder {
        public SAMLIdentityRequestBuilder(Request request) {
            super();
        }

        public SAMLIdentityRequestBuilder() {
            super();
        }
    }

    public boolean isRedirect() {
        return this.getMethod() == SAMLSSOConstants.GET_METHOD;
    }
}
