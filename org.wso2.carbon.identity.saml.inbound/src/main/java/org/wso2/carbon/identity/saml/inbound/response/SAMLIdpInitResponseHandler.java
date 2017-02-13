package org.wso2.carbon.identity.saml.inbound.response;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.gateway.api.FrameworkHandlerResponse;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.processor.handler.response.ResponseException;
import org.wso2.carbon.identity.saml.inbound.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.inbound.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.inbound.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.saml.inbound.request.SAMLIdpInitRequest;
import org.wso2.carbon.identity.saml.inbound.util.SAMLSSOUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SAMLIdpInitResponseHandler extends SAMLResponseHandler {

    private static Logger log = org.slf4j.LoggerFactory.getLogger(SAMLSPInitResponseHandler.class);

    @Override
    public FrameworkHandlerResponse buildErrorResponse(AuthenticationContext authenticationContext) throws ResponseException {

        FrameworkHandlerResponse response = FrameworkHandlerResponse.REDIRECT;
        SAMLMessageContext samlMessageContext = (SAMLMessageContext) authenticationContext.getParameter(SAMLSSOConstants.SAMLContext);
        SAMLResponse.SAMLResponseBuilder builder;
            String destination = samlMessageContext.getDestination();
            String errorResp = null;
            try {
                errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.AUTHN_FAILURE,
                        "User authentication failed", destination);
            } catch (IdentityException e) {
                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(authenticationContext);
                // TODO
//            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
//                    (122, SAMLSSOConstants.StatusCodes
//                            .AUTHN_FAILURE, "Authentication Failure, invalid username or password.", null));
                response.setIdentityResponseBuilder(builder);
                return response;
            } catch (IOException e) {
                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(authenticationContext);
                // TODO
//            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
//                    (122, SAMLSSOConstants.StatusCodes
//                            .AUTHN_FAILURE, "Authentication Failure, invalid username or password.", null));
                response.setIdentityResponseBuilder(builder);
                return response;
            }
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(samlMessageContext);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(errorResp);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setStatus(SAMLSSOConstants
                    .Notification.EXCEPTION_STATUS);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setMessageLog(SAMLSSOConstants
                    .Notification.EXCEPTION_MESSAGE);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(((SAMLIdpInitRequest)
                    samlMessageContext.getIdentityRequest()).getAcs());
            response.setIdentityResponseBuilder(builder);
            return response;
    }

    @Override
    public FrameworkHandlerResponse buildResponse(AuthenticationContext authenticationContext) throws ResponseException {

        FrameworkHandlerResponse response = FrameworkHandlerResponse.REDIRECT;
        SAMLResponse.SAMLResponseBuilder builder;
        SAMLMessageContext samlMessageContext = (SAMLMessageContext) authenticationContext.getParameter(SAMLSSOConstants.SAMLContext);


        String relayState = (String) authenticationContext.getIdentityRequest().getParameter(SAMLSSOConstants.RELAY_STATE);
        if (StringUtils.isBlank(relayState)) {
            relayState = samlMessageContext.getRelayState();
        }

//            builder = authenticate(samlMessageContext, authnResult.isAuthenticated(), authnResult
//                    .getAuthenticatedAuthenticators(), SAMLSSOConstants.AuthnModes.USERNAME_PASSWORD);

        try {
            builder = authenticate(authenticationContext, true, null, SAMLSSOConstants.AuthnModes
                    .USERNAME_PASSWORD);
        } catch (IdentityException e) {
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(authenticationContext);
            // TODO
//            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
//                    (122, SAMLSSOConstants.StatusCodes
//                            .AUTHN_FAILURE, "Authentication Failure, invalid username or password.", null));
            response.setIdentityResponseBuilder(builder);
            return response;
        }


        if (builder instanceof SAMLLoginResponse.SAMLLoginResponseBuilder) { // authenticated
            ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setRelayState(relayState);
            ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAcsUrl(samlMessageContext
                    .getAssertionConsumerURL());
            ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setSubject("admin");
//                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAuthenticatedIdPs(samlMessageContext
//                        .getAuthenticationResult().getAuthenticatedIdPs());
            ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setTenantDomain(samlMessageContext
                    .getTenantDomain());
            response.setIdentityResponseBuilder(builder);
            return response;
        } else { // authentication FAILURE
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setStatus(SAMLSSOConstants
                    .Notification.EXCEPTION_STATUS);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setMessageLog(SAMLSSOConstants
                    .Notification.EXCEPTION_MESSAGE);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(samlMessageContext
                    .getSamlssoServiceProviderDO().getDefaultAssertionConsumerUrl());
            response.setIdentityResponseBuilder(builder);
            return response;
        }


    }


    private SAMLResponse.SAMLResponseBuilder authenticate(AuthenticationContext authenticationContext, boolean isAuthenticated,
                                                          String authenticators, String authMode) throws
            IdentityException {

        SAMLMessageContext messageContext = (SAMLMessageContext) authenticationContext.getParameter(SAMLSSOConstants.SAMLContext);
        SAMLSSOServiceProviderDO serviceProviderConfigs = SAMLSSOUtil.getServiceProviderConfig(messageContext);
        messageContext.setSamlssoServiceProviderDO(serviceProviderConfigs);
        SAMLResponse.SAMLResponseBuilder builder;

        if (serviceProviderConfigs == null) {
            String msg = "A Service Provider with the Issuer '" + messageContext.getIssuer() + "' is not " +
                    "registered." + " Service Provider should be registered in advance.";
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
//            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
//                    (null, SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, null));
            return builder;
        }

        if (!serviceProviderConfigs.isIdPInitSSOEnabled()) {
            String msg = "IdP initiated SSO not enabled for service provider '" + messageContext.getIssuer() + "'.";
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
//            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
//                    (null, SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, null));
            return builder;
        }

        if (serviceProviderConfigs.isEnableAttributesByDefault() && serviceProviderConfigs
                .getAttributeConsumingServiceIndex() != null) {
            messageContext.setAttributeConsumingServiceIndex(Integer.parseInt(serviceProviderConfigs
                    .getAttributeConsumingServiceIndex()));
        }


        String acsUrl = StringUtils.isNotBlank(((SAMLIdpInitRequest) messageContext.getIdentityRequest()).getAcs()) ? (
                (SAMLIdpInitRequest) messageContext.getIdentityRequest()).getAcs() : serviceProviderConfigs
                .getDefaultAssertionConsumerUrl();
        if (StringUtils.isBlank(acsUrl) || !serviceProviderConfigs.getAssertionConsumerUrlList().contains
                (acsUrl)) {
            String msg = "ALERT: Invalid Assertion Consumer URL value '" + acsUrl + "' in the " +
                    "AuthnRequest message from  the issuer '" + serviceProviderConfigs.getIssuer() +
                    "'. Possibly " + "an attempt for a spoofing attack";
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
//            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
//                    (null, SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, acsUrl));
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(acsUrl);
            return builder;
        }
        // TODO : persist the session
        if (isAuthenticated) {
            builder = new SAMLLoginResponse.SAMLLoginResponseBuilder(authenticationContext);
            String respString = setResponse(authenticationContext,((SAMLLoginResponse.SAMLLoginResponseBuilder)
                    builder));
            if (log.isDebugEnabled()) {
                log.debug("Authentication successfully processed. The SAMLResponse is :" + respString);
            }
            return builder;
        } else {
            List<String> statusCodes = new ArrayList<String>();
            statusCodes.add(SAMLSSOConstants.StatusCodes.AUTHN_FAILURE);
            statusCodes.add(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR);
            if (log.isDebugEnabled()) {
                log.debug("Error processing the authentication request.");
            }
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(SAMLSSOUtil.buildErrorResponse
                    (null, statusCodes, "Authentication Failure, invalid username or password.", null));
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(serviceProviderConfigs.getLoginPageURL());
            return builder;
        }
    }

    public boolean canHandle(MessageContext messageContext) {
        if (messageContext instanceof AuthenticationContext) {
            return ((AuthenticationContext) messageContext).getIdentityRequest() instanceof SAMLIdpInitRequest;
        }
        return false;
    }



    public String getName() {
        return "SAMLIdpInitResponseHandler";
    }


    public int getPriority(MessageContext messageContext) {
        return 16;
    }
}
