/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.profile.saml2;

import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.HTTPSOAP11Decoder;
import org.opensaml.saml2.binding.decoding.HandlerChainAwareHTTPSOAP11Decoder;
import org.opensaml.saml2.binding.encoding.HandlerChainAwareHTTPSOAP11Encoder;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.Advice;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.ecp.RequestAuthenticated;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.samlext.saml2cb.ChannelBindings;
import org.opensaml.samlext.samlec.GeneratedKey;
import org.opensaml.ws.message.decoder.MessageDecodingException;

import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.ECPConfiguration;

import org.opensaml.ws.message.handler.BasicHandlerChain;
import org.opensaml.ws.message.handler.Handler;
import org.opensaml.ws.message.handler.HandlerChain;
import org.opensaml.ws.message.handler.HandlerChainResolver;
import org.opensaml.ws.message.handler.HandlerException;
import org.opensaml.ws.message.handler.StaticHandlerChainResolver;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.soap.soap11.ActorBearing;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.util.SOAPHelper;

import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;

/** SAML 2.0 ECP request profile handler. */
public class SAML2ECPProfileHandler extends SSOProfileHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(SAML2ECPProfileHandler.class);

    /** A {@link SecureRandom} PRNG to generate session keys. */
    private final SecureRandom prng = new SecureRandom();
    
    /** A context class reference to insert into the assertion. */
    private String authnContextClassRef = AuthnContext.PPT_AUTHN_CTX;
    
    /** Builder of ECP Response object. */
    private SAMLObjectBuilder<org.opensaml.saml2.ecp.Response> ecpResponseBuilder;

    /** Builder of RequestAuthenticated objects. */
    private SAMLObjectBuilder<RequestAuthenticated> reqAuthnBuilder;

    /** Builder of ChannelBindings objects. */
    private SAMLObjectBuilder<ChannelBindings> cbBuilder;

    /** Builder of GeneratedKey objects. */
    private SAMLObjectBuilder<GeneratedKey> keyBuilder;
    
    /** Builder of Advice objects. */
    private SAMLObjectBuilder<Advice> adviceBuilder;
    
    /** Builder of AuthnContext objects. */
    private SAMLObjectBuilder<AuthnContext> authnContextBuilder;

    /** Builder of AuthnContextClassRef objects. */
    private SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder;

    /** Static pre-security inbound handler chain resolver. */
    private StaticHandlerChainResolver inboundPreSecurityHandlerChainResolver;

    /** Static post-security inbound handler chain resolver. */
    private StaticHandlerChainResolver inboundPostSecurityHandlerChainResolver;
    
    /** Static outbound handler chain resolver. */
    private StaticHandlerChainResolver outboundHandlerChainResolver;
    
    /** SOAP message encoder to use. */
    private SAMLMessageEncoder messageEncoder;
    
    /** SOAP message decoder to use. */
    private SAMLMessageDecoder messageDecoder;

    /** SOAP fault message. */
    private final String soapFaultResponseMessage =
"<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
" <env:Body>" +
" <env:Fault>" +
" <faultcode>env:Client</faultcode>" +
" <faultstring>An error occurred processing the request.</faultstring>" +
" <detail/>" +
" </env:Fault>" +
" </env:Body>" +
"</env:Envelope>";


    /**
     * Constructor.
     * 
     */
    public SAML2ECPProfileHandler() {
        // Need a dummy value to build base class.
        super("/Save/My/Walrus");

        ecpResponseBuilder = (SAMLObjectBuilder<org.opensaml.saml2.ecp.Response>) Configuration.getBuilderFactory().
                getBuilder(org.opensaml.saml2.ecp.Response.DEFAULT_ELEMENT_NAME);
        reqAuthnBuilder = (SAMLObjectBuilder<RequestAuthenticated>) Configuration.getBuilderFactory().getBuilder(
                RequestAuthenticated.DEFAULT_ELEMENT_NAME);
        cbBuilder = (SAMLObjectBuilder<ChannelBindings>) Configuration.getBuilderFactory().getBuilder(
                ChannelBindings.DEFAULT_ELEMENT_NAME);
        keyBuilder = (SAMLObjectBuilder<GeneratedKey>) Configuration.getBuilderFactory().getBuilder(
                GeneratedKey.DEFAULT_ELEMENT_NAME);

        adviceBuilder = (SAMLObjectBuilder<Advice>) Configuration.getBuilderFactory().getBuilder(
                Advice.DEFAULT_ELEMENT_NAME);
        authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) getBuilderFactory().getBuilder(
                AuthnContext.DEFAULT_ELEMENT_NAME);
        authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) getBuilderFactory().getBuilder(
                AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
    }

    /** Initialize the profile handler. */
    public void initialize() {
        messageDecoder = new HandlerChainAwareHTTPSOAP11Decoder();
        ((HTTPSOAP11Decoder) messageDecoder).getUnderstoodHeaders().add(ChannelBindings.DEFAULT_ELEMENT_NAME);
        
        messageEncoder = new HandlerChainAwareHTTPSOAP11Encoder();
        ((HandlerChainAwareHTTPSOAP11Encoder) messageEncoder).setNotConfidential(true);
        
        inboundPreSecurityHandlerChainResolver =
                new StaticHandlerChainResolver(buildPreSecurityInboundHandlerChain());
        inboundPostSecurityHandlerChainResolver =
                new StaticHandlerChainResolver(buildPostSecurityInboundHandlerChain());
        outboundHandlerChainResolver = new StaticHandlerChainResolver(buildOutboundHandlerChain());

        // This is needed by the endpoint selector. We're obviously not actually responding over this binding.
        // In this profile handler, outbound binding selection is not determined by the product of the 
        // EndpointSelector.
        ArrayList<String> ecpOutboundBindings = new ArrayList<String>();
        ecpOutboundBindings.add(SAMLConstants.SAML2_PAOS_BINDING_URI);
        setSupportedOutboundBindings(ecpOutboundBindings);
    }


    /** {@inheritDoc} */
    public String getProfileId() {
        return ECPConfiguration.PROFILE_ID;
    }

    /**
     * Sets the AuthnContext class reference.
     * @param ref AuthnContext class reference to set
     */
    public void setAuthnContextClassRef(String ref) {
        authnContextClassRef = ref;
    }

    /**
     * Gets the AuthnContext class reference.
     * @return AuthnContext class reference
     */
    public String getAuthnContextClassRef() {
        return authnContextClassRef;
    }

    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        ECPRequestContext requestContext = buildRequestContext(inTransport, outTransport);

        Response samlResponse;

        try {
            decodeRequest(requestContext, inTransport, outTransport);
            checkSamlVersion(requestContext);
            checkNameIDPolicy(requestContext);

            if (requestContext.getPrincipalName() == null) {
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.AUTHN_FAILED_URI,
                        null));
                throw new ProfileException("Authentication not performed");
            }
            
            checkChannelBindings(requestContext);

            if (requestContext.getSubjectNameIdentifier() != null) {
                log.debug("Request contained a subject with a name identifier, resolving principal from NameID");
                String authenticatedName = requestContext.getPrincipalName();
                resolvePrincipal(requestContext);
                String requestedPrincipalName = requestContext.getPrincipalName();
                if (!DatatypeHelper.safeEquals(authenticatedName, requestedPrincipalName)) {
                    log.warn("Request identified principal {} but authentication mechanism identified principal {}",
                            requestedPrincipalName, authenticatedName);
                    requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.AUTHN_FAILED_URI,
                            null));
                    throw new ProfileException("User failed authentication");
                }
            }

            String relyingPartyId = requestContext.getInboundMessageIssuer();
            RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
            ProfileConfiguration ecpConfig = rpConfig.getProfileConfiguration(getProfileId());
            if (ecpConfig == null) {
                log.warn("SAML2ECP profile is not configured for relying party '{}'",
                        requestContext.getInboundMessageIssuer());
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI,
                        StatusCode.REQUEST_UNSUPPORTED_URI, null));
                throw new ProfileException("SAML2ECP profile is not configured for relying party");
            }

            resolveAttributes(requestContext);
            
            ArrayList<Statement> statements = new ArrayList<Statement>();
            statements.add(buildAuthnStatement(requestContext));
            if (requestContext.getProfileConfiguration().includeAttributeStatement()) {
                AttributeStatement attributeStatement = buildAttributeStatement(requestContext);
                if (attributeStatement != null) {
                    requestContext.setReleasedAttributes(requestContext.getAttributes().keySet());
                    statements.add(attributeStatement);
                }
            }

            samlResponse = buildResponse(requestContext, SubjectConfirmation.METHOD_BEARER, statements);
            samlResponse.setDestination(requestContext.getPeerEntityEndpoint().getLocation());

        } catch (ProfileException e) {
            if (requestContext.getPeerEntityEndpoint() != null) {
                samlResponse = buildErrorResponse(requestContext);
            } else {
                log.debug("Returning SOAP fault", e);
                try {
                   outTransport.setCharacterEncoding("UTF-8");
                   outTransport.setHeader("Content-Type", "application/soap+xml");
                   outTransport.setStatusCode(500);  // seem to lose the message when we report an error.
                   Writer out = new OutputStreamWriter(outTransport.getOutgoingStream(), "UTF-8");
                   out.write(soapFaultResponseMessage);
                   out.flush();
                } catch (Exception we) {
                   log.error("Error returning SOAP fault", we);
                }
                return;
            }
        }

        requestContext.setOutboundSAMLMessage(samlResponse);
        requestContext.setOutboundSAMLMessageId(samlResponse.getID());
        requestContext.setOutboundSAMLMessageIssueInstant(samlResponse.getIssueInstant());
        encodeResponse(requestContext);
        writeAuditLogEntry(requestContext);
    }

    /**
     * Decodes an incoming request and stores the information in a created request context.
     * 
     * @param inTransport inbound transport
     * @param outTransport outbound transport
     * @param requestContext request context to which decoded information should be added
     * 
     * @throws ProfileException thrown if the incoming message failed decoding
     */
    protected void decodeRequest(ECPRequestContext requestContext, HTTPInTransport inTransport,
            HTTPOutTransport outTransport) throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("Decoding message with decoder binding '{}'", getInboundMessageDecoder(requestContext)
                    .getBindingURI());
        }

        try {
            SAMLMessageDecoder decoder = getInboundMessageDecoder(requestContext);
            requestContext.setMessageDecoder(decoder);
            decoder.decode(requestContext);
            log.debug("Decoded request from relying party '{}'", requestContext.getInboundMessageIssuer());

            if (!(requestContext.getInboundSAMLMessage() instanceof AuthnRequest)) {
                log.warn("Incomming message was not a AuthnRequest, it was a '{}'", requestContext
                        .getInboundSAMLMessage().getClass().getName());
                requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER_URI,
                        StatusCode.REQUEST_UNSUPPORTED_URI, "Invalid SAML AuthnRequest message."));
                throw new ProfileException("Invalid SAML AuthnRequest message.");
            }
            
            AuthnRequest authnRequest = requestContext.getInboundSAMLMessage();
            Subject authnSubject = authnRequest.getSubject();
            if (authnSubject != null) {
                requestContext.setSubjectNameIdentifier(authnSubject.getNameID());
            }
            
            Extensions exts = authnRequest.getExtensions();
            if (exts != null) {
                List<XMLObject> cbs = exts.getUnknownXMLObjects(ChannelBindings.DEFAULT_ELEMENT_NAME);
                for (XMLObject cb : cbs) {
                    requestContext.getSPChannelBindings().add((ChannelBindings) cb);
                }
            }
        } catch (MessageDecodingException e) {
            String msg = "Error decoding authentication request message";
            requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER_URI,
                    StatusCode.REQUEST_UNSUPPORTED_URI, msg));
            log.warn(msg, e);
            throw new ProfileException(msg, e);
        } catch (SecurityException e) {
            String msg = "Message did not meet security requirements";
            requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER_URI, StatusCode.REQUEST_DENIED_URI, msg));
            log.warn(msg, e);
            throw new ProfileException(msg, e);
        }
        populateRequestContext(requestContext);
    }

    /**
     * Creates an authentication request context from the current environmental information.
     * 
     * @param in inbound transport
     * @param out outbount transport
     * 
     * @return created authentication request context
     * 
     * @throws ProfileException thrown if there is a problem creating the context
     */
    protected ECPRequestContext buildRequestContext(HTTPInTransport in, HTTPOutTransport out)
            throws ProfileException {
        ECPRequestContext requestContext = new ECPRequestContext();

        requestContext.setCommunicationProfileId(getProfileId());
        requestContext.setMessageDecoder(getInboundMessageDecoder(requestContext));
        requestContext.setInboundMessageTransport(in);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        requestContext.setOutboundMessageTransport(out);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        requestContext.setMetadataProvider(getMetadataProvider());
        requestContext.setSecurityPolicyResolver(getSecurityPolicyResolver());

        // Does this do anything?
        String relyingPartyId = requestContext.getInboundMessageIssuer();
        requestContext.setPeerEntityId(relyingPartyId);
        requestContext.setInboundMessageIssuer(relyingPartyId);
        
        requestContext.setPreSecurityInboundHandlerChainResolver(getPreSecurityInboundHandlerChainResolver());
        requestContext.setPostSecurityInboundHandlerChainResolver(getPostSecurityInboundHandlerChainResolver());
        requestContext.setOutboundHandlerChainResolver(getOutboundHandlerChainResolver());

        return requestContext;
    }

    /**
     * Checks for channel bindings to verify and either fails the request or populates the message context
     * with the matched information.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException if channel bindings are required and don't match or are missing
     */
    protected void checkChannelBindings(ECPRequestContext requestContext) throws ProfileException {
        if (requestContext.getSPChannelBindings().isEmpty() && requestContext.getClientChannelBindings().isEmpty()) {
            return;
        } else if (!requestContext.isInboundSAMLMessageAuthenticated()) {
            requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER_URI, null,
                    "Channel bindings verification failed, request was unauthenticated"));
            throw new ProfileException("Channel bindings verification failed, request was unauthenticated");
        }

        log.debug("Attempting to match channel bindings supplied by SP and client");
        for (ChannelBindings clientCB : requestContext.getClientChannelBindings()) {
            for (ChannelBindings spCB : requestContext.getSPChannelBindings()) {
                if (DatatypeHelper.safeEquals(clientCB.getType(), spCB.getType())) {
                    if (clientCB.getValue() != null && spCB.getValue() != null
                            && clientCB.getValue().equals(spCB.getValue())) {
                        requestContext.setMatchedChannelBindings(clientCB);
                        log.debug("Channel bindings of type {} matched", clientCB.getType());
                        return;
                    }
                }
            }
        }
        
        requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER_URI, null,
                "Channel bindings verification failed, no match found"));
        throw new ProfileException("Channel bindings verification failed, no match found");
    }
    
    /** {@inheritDoc} */
    protected void populateSAMLMessageInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        AuthnRequest authnRequest = (AuthnRequest) requestContext.getInboundSAMLMessage();
        Subject authnSubject = authnRequest.getSubject();
        if (authnSubject != null) {
            requestContext.setSubjectNameIdentifier(authnSubject.getNameID());
        }
    }

    /** {@inheritDoc} */
    protected AuthnStatement buildAuthnStatement(SSORequestContext requestContext) {
        AuthnStatement statement = super.buildAuthnStatement(requestContext);
        statement.setAuthnInstant(new DateTime());
        return statement;
    }

    /** {@inheritDoc} */
    protected AuthnContext buildAuthnContext(SSORequestContext requestContext) {
        if (getAuthnContextClassRef() != null) {
            AuthnContext authnContext = authnContextBuilder.buildObject();
            AuthnContextClassRef ref = authnContextClassRefBuilder.buildObject();
            ref.setAuthnContextClassRef(getAuthnContextClassRef());
            authnContext.setAuthnContextClassRef(ref);
            return authnContext;
        }
        return null;
    }

    /** {@inheritDoc} */
    protected void postProcessAssertion(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext, Assertion assertion)
            throws ProfileException {
        super.postProcessAssertion(requestContext, assertion);
        
        Advice advice = assertion.getAdvice();
        if (advice == null) {
            advice = adviceBuilder.buildObject();
            assertion.setAdvice(advice);
        }
        ChannelBindings cb = ((ECPRequestContext) requestContext).getMatchedChannelBindings();
        if (cb != null) {
            ChannelBindings cbOut = cbBuilder.buildObject();
            if (cb.getType() != null) {
                cbOut.setType(cb.getType());
            }
            advice.getChildren().add(cbOut);
        }
        GeneratedKey key = keyBuilder.buildObject();
        key.setValue(((ECPRequestContext) requestContext).getGeneratedKey());
        advice.getChildren().add(key);
    }
    
    /** Extended context information specific to ECP requests. */
    protected class ECPRequestContext extends SSORequestContext {
        
        /** Channel bindings from SP. */
        private List<ChannelBindings> spChannelBindings;

        /** Channel bindings from client. */
        private List<ChannelBindings> clientChannelBindings;
        
        /** A channel bindings structure that matched. */
        private ChannelBindings matchedChannelBindings;
        
        /** Session key for GSS-API generated by IdP. */
        private final String generatedKey;
        
        /** Constructor. */
        public ECPRequestContext() {
            spChannelBindings = new ArrayList<ChannelBindings>();
            clientChannelBindings = new ArrayList<ChannelBindings>();
            byte[] buf = new byte[32];
            prng.nextBytes(buf);
            generatedKey = Base64.encode(buf);
        }
        
        /**
         * Get the channel bindings sent from the SP for itself.
         * 
         * @return the SP's channel bindings
         */
        public List<ChannelBindings> getSPChannelBindings() {
            return spChannelBindings;
        }

        /**
         * Get the channel bindings sent from the client for the SP.
         * 
         * @return the client's channel bindings between itself and the SP
         */
        public List<ChannelBindings> getClientChannelBindings() {
            return clientChannelBindings;
        }
        
        /**
         * Get the verified channel bindings, if any.
         * 
         * @return a ChannelBindings element that matched, or null
         */
        public ChannelBindings getMatchedChannelBindings() {
            return matchedChannelBindings;
        }

        /**
         * Set the verified channel bindings, if any.
         * 
         * @param cb a ChannelBindings element that matched
         */
        public void setMatchedChannelBindings(ChannelBindings cb) {
            matchedChannelBindings = cb;
        }
        
        /**
         * Get the session key generated by the IdP.
         * @return the generated session key
         */
        public String getGeneratedKey() {
            return generatedKey;
        }
    }
    

    /**
     * Build the pre-security inbound handler chain.
     *
     * @return the handler chain
     */
    protected HandlerChain buildPreSecurityInboundHandlerChain() {
        BasicHandlerChain handlerChain = new BasicHandlerChain();

        handlerChain.getHandlers().add( new Handler() {
            public void invoke(MessageContext msgContext) throws HandlerException {
                ECPRequestContext ctx = (ECPRequestContext) msgContext;
                HttpServletRequest httpRequest =
                    ((HttpServletRequestAdapter) msgContext.getInboundMessageTransport()).getWrappedRequest();
                String user = httpRequest.getRemoteUser();
                if (user != null) {
                    log.debug("Setting principal name: {}", user);
                    ctx.setPrincipalName(user);
                } else {
                    log.warn("REMOTE_USER not set, unable to set principal name");
                }
            }
        });

       return handlerChain;
    }

    /**
     * Build the post-security inbound handler chain.
     *
     * @return the handler chain
     */
    protected HandlerChain buildPostSecurityInboundHandlerChain() {
        BasicHandlerChain handlerChain = new BasicHandlerChain();

        handlerChain.getHandlers().add( new Handler() {
            public void invoke(MessageContext msgContext) throws HandlerException {
                ECPRequestContext ctx = (ECPRequestContext) msgContext;
                if (msgContext.getInboundMessage() instanceof Envelope) {
                    Envelope env = (Envelope) msgContext.getInboundMessage();
                    if (env.getHeader() != null) {
                        List<XMLObject> cbList =
                                env.getHeader().getUnknownXMLObjects(ChannelBindings.DEFAULT_ELEMENT_NAME);
                        for (XMLObject cb : cbList) {
                            String actor = SOAPHelper.getSOAP11ActorAttribute(cb);
                            if (actor != null && ActorBearing.SOAP11_ACTOR_NEXT.equals(actor)) {
                                ctx.getClientChannelBindings().add((ChannelBindings) cb);
                            }
                        }
                    }
                } else {
                    throw new HandlerException("Inbound message not a SOAP envelope");
                }
            }
        });

       return handlerChain;
    }
    
    /**
     * Get the resolver used to resolve the pre-security inbound handler chain.
     *
     * @return the handler chain resolver
     */
    protected HandlerChainResolver getPreSecurityInboundHandlerChainResolver() {
        return inboundPreSecurityHandlerChainResolver;
    }

    /**
     * Get the resolver used to resolve the post-security inbound handler chain.
     *
     * @return the handler chain resolver
     */
    protected HandlerChainResolver getPostSecurityInboundHandlerChainResolver() {
        return inboundPostSecurityHandlerChainResolver;
    }
    
    /**
     * Build the outbound handler chain.
     *
     * @return the handler chain
     */
    protected HandlerChain buildOutboundHandlerChain() {
        BasicHandlerChain handlerChain = new BasicHandlerChain();

        handlerChain.getHandlers().add( new Handler() {
            public void invoke(MessageContext msgContext) throws HandlerException {
                SAMLMessageContext samlMsgCtx = (SAMLMessageContext) msgContext;
                org.opensaml.saml2.ecp.Response response = ecpResponseBuilder.buildObject();
                if (samlMsgCtx.getPeerEntityEndpoint() == null
                        || samlMsgCtx.getPeerEntityEndpoint().getLocation() == null) {
                    throw new HandlerException("Unable to determine ACS URL for response.");
                }
                response.setAssertionConsumerServiceURL(samlMsgCtx.getPeerEntityEndpoint().getLocation());
                SOAPHelper.addSOAP11MustUnderstandAttribute(response, true);
                SOAPHelper.addSOAP11ActorAttribute(response, ActorBearing.SOAP11_ACTOR_NEXT);
                SOAPHelper.addHeaderBlock(msgContext, response);
                
                if (samlMsgCtx.isInboundSAMLMessageAuthenticated()) {
                    RequestAuthenticated ra = reqAuthnBuilder.buildObject();
                    SOAPHelper.addSOAP11ActorAttribute(response, ActorBearing.SOAP11_ACTOR_NEXT);
                    SOAPHelper.addHeaderBlock(msgContext, ra);
                }
                
                ChannelBindings cb = ((ECPRequestContext) msgContext).getMatchedChannelBindings();
                if (cb != null) {
                    ChannelBindings cbOut = cbBuilder.buildObject();
                    if (cb.getType() != null) {
                        cbOut.setType(cb.getType());
                    }
                    SOAPHelper.addSOAP11MustUnderstandAttribute(cbOut, true);
                    SOAPHelper.addSOAP11ActorAttribute(cbOut, ActorBearing.SOAP11_ACTOR_NEXT);
                    SOAPHelper.addHeaderBlock(msgContext, cbOut);
                }
                
                GeneratedKey key = keyBuilder.buildObject();
                key.setValue(((ECPRequestContext) msgContext).getGeneratedKey());
                SOAPHelper.addSOAP11ActorAttribute(key, ActorBearing.SOAP11_ACTOR_NEXT);
                SOAPHelper.addHeaderBlock(msgContext, key);
            }
        });

        return handlerChain;
    }
    
    /**
     * Get the resolver used to resolve the outbound handler chain.
     *
     * @return the handler chain resolver
     */
    protected HandlerChainResolver getOutboundHandlerChainResolver() {
        return outboundHandlerChainResolver;
    }
    
    /** {@inheritDoc} */
    protected SAMLMessageEncoder getOutboundMessageEncoder(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        return messageEncoder;
    }

    /** {@inheritDoc} */
    protected SAMLMessageDecoder getInboundMessageDecoder(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        return messageDecoder;
    }
}
