package org.wso2.carbon.identity.saml.inbound.response;

import org.apache.xml.security.utils.EncryptionConstants;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.xml.security.x509.X509Credential;
import org.slf4j.Logger;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.gateway.api.FrameworkHandlerResponse;
import org.wso2.carbon.identity.gateway.api.IdentityMessageContext;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.processor.handler.authentication.AuthenticationHandlerException;
import org.wso2.carbon.identity.gateway.processor.handler.response.AbstractResponseHandler;
import org.wso2.carbon.identity.gateway.processor.handler.response.ResponseException;
import org.wso2.carbon.identity.saml.inbound.SAMLConfigurations;
import org.wso2.carbon.identity.saml.inbound.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.inbound.bean.SAMLResponseHandlerConfig;
import org.wso2.carbon.identity.saml.inbound.builders.SignKeyDataHolder;
import org.wso2.carbon.identity.saml.inbound.builders.assertion.DefaultSAMLAssertionBuilder;
import org.wso2.carbon.identity.saml.inbound.builders.assertion.SAMLAssertionBuilder;
import org.wso2.carbon.identity.saml.inbound.builders.encryption.DefaultSSOEncrypter;
import org.wso2.carbon.identity.saml.inbound.builders.encryption.SSOEncrypter;
import org.wso2.carbon.identity.saml.inbound.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.inbound.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.saml.inbound.util.SAMLSSOUtil;

import java.util.Properties;

abstract public class SAMLResponseHandler extends AbstractResponseHandler {

    private static Logger log = org.slf4j.LoggerFactory.getLogger(SAMLSPInitResponseHandler.class);


    @Override
    public FrameworkHandlerResponse buildErrorResponse(AuthenticationContext authenticationContext) throws ResponseException {
        try {
            setSAMLResponseHandlerConfigs(authenticationContext);
        } catch (AuthenticationHandlerException e) {
            throw new ResponseException("Error while getting response handler configurations");
        }
        return FrameworkHandlerResponse.REDIRECT;
    }

    @Override
    public FrameworkHandlerResponse buildResponse(AuthenticationContext authenticationContext) throws ResponseException {
        try {
            setSAMLResponseHandlerConfigs(authenticationContext);
        } catch (AuthenticationHandlerException e) {
            throw new ResponseException("Error while getting response handler configurations");
        }
        return FrameworkHandlerResponse.REDIRECT;
    }


    public String setResponse(IdentityMessageContext context, SAMLLoginResponse.SAMLLoginResponseBuilder
            builder) throws IdentityException {

        SAMLMessageContext messageContext = (SAMLMessageContext) context.getParameter(SAMLSSOConstants.SAMLContext);
        SAMLSSOServiceProviderDO serviceProviderDO = messageContext.getSamlssoServiceProviderDO();
        if (log.isDebugEnabled()) {
            log.debug("Building SAML Response for the consumer '" + messageContext.getAssertionConsumerURL() + "'");
        }
        Response response = new org.opensaml.saml2.core.impl.ResponseBuilder().buildObject();
        response.setIssuer(SAMLSSOUtil.getIssuer());
        response.setID(SAMLSSOUtil.createID());
        if (!messageContext.isIdpInitSSO()) {
            response.setInResponseTo(messageContext.getId());
        }
        response.setDestination(messageContext.getAssertionConsumerURL());
        response.setStatus(buildStatus(SAMLSSOConstants.StatusCodes.SUCCESS_CODE, null));
        response.setVersion(SAMLVersion.VERSION_20);
        DateTime issueInstant = new DateTime();
        DateTime notOnOrAfter = new DateTime(issueInstant.getMillis()
                + SAMLConfigurations.getInstance().getSamlResponseValidityPeriod() * 60 * 1000L);
        response.setIssueInstant(issueInstant);
        //@TODO sessionHandling
        String sessionId = "";
        Assertion assertion = buildSAMLAssertion(messageContext, notOnOrAfter, sessionId);

        if (serviceProviderDO.isDoEnableEncryptedAssertion()) {

            String domainName = messageContext.getTenantDomain();
            String alias = serviceProviderDO.getCertAlias();
            // TODO
            if (alias != null) {
                EncryptedAssertion encryptedAssertion = setEncryptedAssertion(assertion,
                        EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256, alias, domainName);
                response.getEncryptedAssertions().add(encryptedAssertion);
            }
        } else {
            response.getAssertions().add(assertion);
        }
        if (serviceProviderDO.isDoSignResponse()) {
            SAMLSSOUtil.setSignature(response, serviceProviderDO.getSigningAlgorithmUri(), serviceProviderDO
                    .getDigestAlgorithmUri(), new SignKeyDataHolder());
        }
        builder.setResponse(response);
        String respString = SAMLSSOUtil.encode(SAMLSSOUtil.marshall(response));
        builder.setRespString(respString);
        builder.setAcsUrl(messageContext.getAssertionConsumerURL());
        builder.setRelayState(messageContext.getRelayState());
        return respString;
    }


    private Status buildStatus(String status, String statMsg) {

        Status stat = new StatusBuilder().buildObject();

        // Set the status code
        StatusCode statCode = new StatusCodeBuilder().buildObject();
        statCode.setValue(status);
        stat.setStatusCode(statCode);

        // Set the status Message
        if (statMsg != null) {
            StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
            statMesssage.setMessage(statMsg);
            stat.setStatusMessage(statMesssage);
        }

        return stat;
    }

    public EncryptedAssertion setEncryptedAssertion(Assertion assertion, String encryptionAlgorithm,
                                                    String alias, String domainName) throws IdentityException {
        SAMLSSOUtil.doBootstrap();

        SSOEncrypter ssoEncrypter = new DefaultSSOEncrypter();
        X509Credential cred = SAMLSSOUtil.getX509CredentialImplForTenant(domainName, alias);
        return ssoEncrypter.doEncryptedAssertion(assertion, cred, alias, encryptionAlgorithm);
    }

    public Assertion buildSAMLAssertion(SAMLMessageContext context, DateTime notOnOrAfter,
                                        String sessionId) throws IdentityException {
        SAMLSSOUtil.doBootstrap();
        SAMLAssertionBuilder samlAssertionBuilder = new DefaultSAMLAssertionBuilder();
        return samlAssertionBuilder.buildAssertion(context, notOnOrAfter, sessionId);

    }

    protected String getValidatorType() {
        return "SAML";
    }

    protected void setSAMLResponseHandlerConfigs (AuthenticationContext authenticationContext) throws
            AuthenticationHandlerException {
        SAMLMessageContext messageContext = (SAMLMessageContext) authenticationContext.getParameter(SAMLSSOConstants.SAMLContext);
        Properties samlValidatorProperties = getResponseBuilderConfigs(authenticationContext);
        SAMLResponseHandlerConfig samlResponseHandlerConfig = new SAMLResponseHandlerConfig(samlValidatorProperties);
        messageContext.setResponseHandlerConfig(samlResponseHandlerConfig);
    }
}
