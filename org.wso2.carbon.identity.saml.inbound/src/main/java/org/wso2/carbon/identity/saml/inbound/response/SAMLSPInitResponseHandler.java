package org.wso2.carbon.identity.saml.inbound.response;

import org.slf4j.Logger;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.gateway.api.FrameworkHandlerResponse;
import org.wso2.carbon.identity.gateway.api.IdentityMessageContext;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.processor.handler.response.ResponseException;
import org.wso2.carbon.identity.saml.inbound.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.inbound.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.inbound.request.SAMLSpInitRequest;

public class SAMLSPInitResponseHandler extends SAMLResponseHandler {

    private static Logger log = org.slf4j.LoggerFactory.getLogger(SAMLSPInitResponseHandler.class);

    @Override
    public FrameworkHandlerResponse buildErrorResponse(IdentityMessageContext identityMessageContext) throws ResponseException {
        return null;
    }

    @Override
    public FrameworkHandlerResponse buildResponse(IdentityMessageContext identityMessageContext) throws ResponseException {

        // TODO

//        if (identityMessageContext.getSubject() != null && messageContext.getUser() != null) {
//            String authenticatedSubjectIdentifier = messageContext.getUser().getAuthenticatedSubjectIdentifier();
//            if (authenticatedSubjectIdentifier != null && !authenticatedSubjectIdentifier.equals(messageContext
//                    .getSubject())) {
//                String msg = "Provided username does not match with the requested subject";
//                if (log.isDebugEnabled()) {
//                    log.debug(msg);
//                }
//                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
//                ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
//                        (messageContext.getId(), SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg,
//                                serviceProviderConfigs.getDefaultAssertionConsumerUrl()));
//                return builder;
//            }
//        }
        // TODO persist the session
        boolean isAuthenticated = true;
        SAMLResponse.SAMLResponseBuilder builder;
        SAMLMessageContext samlMessageContext = (SAMLMessageContext) identityMessageContext.getParameter(SAMLSSOConstants.SAMLContext);
        FrameworkHandlerResponse response = FrameworkHandlerResponse.REDIRECT;
        if (isAuthenticated) {
            builder = new SAMLLoginResponse.SAMLLoginResponseBuilder(identityMessageContext);
            String respString = null;
            try {
                respString = setResponse(identityMessageContext, ((SAMLLoginResponse.SAMLLoginResponseBuilder)
                        builder));
                //((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAcsUrl()
            } catch (IdentityException e) {

                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(identityMessageContext);
                // TODO
//            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
//                    (122, SAMLSSOConstants.StatusCodes
//                            .AUTHN_FAILURE, "Authentication Failure, invalid username or password.", null));
                response.setIdentityResponseBuilder(builder);
                return response;
            }

            if (log.isDebugEnabled()) {
                log.debug("Authentication successfully processed. The SAMLResponse is :" + respString);
            }
            response.setIdentityResponseBuilder(builder);
            return response;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Error processing the authentication request");
            }

            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(identityMessageContext);
            // TODO
//            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
//                    (122, SAMLSSOConstants.StatusCodes
//                            .AUTHN_FAILURE, "Authentication Failure, invalid username or password.", null));
            response.setIdentityResponseBuilder(builder);
            return response;
        }
    }


    public boolean canHandle(MessageContext messageContext) {
        if (messageContext instanceof AuthenticationContext) {
            return ((AuthenticationContext) messageContext).getIdentityRequest() instanceof SAMLSpInitRequest;
        }
        return false;
    }

    public String getName() {
        return "SPInitResponseHandler";
    }

    public int getPriority(MessageContext messageContext) {
        return 15;
    }

}
