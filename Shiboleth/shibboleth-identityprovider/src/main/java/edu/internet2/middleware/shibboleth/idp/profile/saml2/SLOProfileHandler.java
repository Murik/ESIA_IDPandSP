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

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.AbstractSAMLProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.LogoutRequestConfiguration;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.samlext.saml2aslo.Asynchronous;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.DatatypeHelper;
import org.owasp.esapi.ESAPI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Profile handler for limited logout capability.
 */
public class SLOProfileHandler extends AbstractSAML2ProfileHandler {

    /** Binding identifier representing "local" logout. */
    public static final String LOCAL_LOGOUT_BINDING = "urn:mace:shibboleth:2.0:profiles:LocalLogout";
    
    /** Name of attribute for tracking logged out session. */
    public static final String HTTP_LOGOUT_BINDING_ATTRIBUTE = "ShibbolethLogoutSession";
        
    /** Canned SOAP fault. */
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

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(SLOProfileHandler.class);
    
    /** Builder of SingleLogoutService objects. */
    private final SAMLObjectBuilder<SingleLogoutService> sloServiceBuilder;
    
    /** Builder of LogoutResponse objects. */
    private final SAMLObjectBuilder<LogoutResponse> responseBuilder;
    
    /** Velocity engine to use to render logout response to user. */
    private VelocityEngine velocity;

    /** Path to Velocity or JSP template for logout response to user. */
    private String templatePath;
    
    /**
     * Constructor.
     * 
     * @param newPath  path to JSP or Velocity template
     */
    public SLOProfileHandler(String newPath) {
        super();
        
        if (DatatypeHelper.isEmpty(newPath)) {
            throw new IllegalArgumentException("Logout template path may not be null");
        }
        templatePath = newPath;
        
        sloServiceBuilder = (SAMLObjectBuilder<SingleLogoutService>) getBuilderFactory().getBuilder(
                SingleLogoutService.DEFAULT_ELEMENT_NAME);
        responseBuilder = (SAMLObjectBuilder<LogoutResponse>) getBuilderFactory().getBuilder(
                LogoutResponse.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Gets the VelocityEngine to use.
     * 
     * @return  the VelocityEngine to use
     */
    public VelocityEngine getVelocityEngine() {
        return velocity;
    }

    /**
     * Sets the VelocityEngine to use.
     * 
     * @param newVelocity the VelocityEngine to use
     */
    public void setVelocityEngine(VelocityEngine newVelocity) {
        velocity = newVelocity;
    }
    
    /** {@inheritDoc} */
    @Override
    public String getProfileId() {
        return LogoutRequestConfiguration.PROFILE_ID;
    }
    
    /** {@inheritDoc} */
    @Override
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        if (getInboundBinding().equals(LOCAL_LOGOUT_BINDING)) {
            log.debug("Processing logout request");
            localLogout(null, inTransport, outTransport);
        } else {
            log.debug("Processing incoming SAML LogoutRequest");
            processLogoutRequest(inTransport, outTransport);
        }
    }
    
    /**
     * Handles clearing the active session, possibly an additional "indirect" session,
     * and presenting a logout response to the client using a Velocity template.
     * 
     * @param indirect      additional session to clear during logout
     * @param inTransport   incoming transport object
     * @param outTransport  outgoing transport object
     * @throws ProfileException if an error occurs during profile execution
     */
    protected void localLogout(Session indirect, HTTPInTransport inTransport, HTTPOutTransport outTransport)
        throws ProfileException {

        // Context info for template.
        HttpServletRequest request = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
        HttpServletResponse response = ((HttpServletResponseAdapter) outTransport).getWrappedResponse();

        Session activeSession = getUserSession(inTransport);
        
        if (indirect != null) {
            log.info("Invalidating session identified by LogoutRequest: {}", indirect.getSessionID());
            destroySession(indirect);
        }

        if (activeSession != null) {
            if (indirect == null || !DatatypeHelper.safeEquals(activeSession.getSessionID(), indirect.getSessionID())) {
                log.info("Invalidating session identified from client request: {}", activeSession.getSessionID());
                destroySession(activeSession);
            }
        } else {
            log.info("No session to invalidate from client request.");
        }

        response.setContentType("text/html");
        response.setHeader("Cache-Control", "content=\"no-store,no-cache,must-revalidate\"");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "-1");
        
        if (velocity != null) {        
            VelocityContext vCtx = new VelocityContext();
            vCtx.put("encoder", ESAPI.encoder());
            vCtx.put("request", request);
            vCtx.put("response", response);
            vCtx.put("session", (activeSession != null) ? activeSession : indirect);
                    
            try {
                Template template = velocity.getTemplate(templatePath);
                PrintWriter writer = response.getWriter();
                template.merge(vCtx, writer);
                writer.flush();
            } catch (Exception e) {
                log.error(e.getMessage());
                throw new ProfileException("Error while processing logout template.", e);
            }
        } else {
            RequestDispatcher dispatcher = request.getRequestDispatcher(
                    (templatePath.startsWith("/") ? templatePath : "/" + templatePath));
            try {
                request.setAttribute(HTTP_LOGOUT_BINDING_ATTRIBUTE, (activeSession != null) ? activeSession : indirect);
                dispatcher.forward(request, response);
            } catch (Exception e) {
                throw new ProfileException("Could not dispatch to JSP page.", e);
            }
        }
    }

    /**
     * Process and respond to a SAML LogoutRequest message. This is a very simplified version
     * because it doesn't propagate the logout to any SPs. It just handles the IdP session(s)
     * and then either responds to the client or to the SP depending on the async flag.
     * 
     * @param inTransport   incoming transport object
     * @param outTransport  outgoing transport object
     * @throws ProfileException if an error occurs during profile execution
     */
    protected void processLogoutRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {

        LogoutResponse samlResponse = null;
        SLORequestContext requestContext = new SLORequestContext();

        try {
            decodeRequest(requestContext, inTransport, outTransport);

            ProfileConfiguration sloConfig =
                    requestContext.getRelyingPartyConfiguration().getProfileConfiguration(getProfileId());
            if (sloConfig == null) {
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                        "SAML 2 SLO profile not configured"));
                String msg = "SAML 2 SLO profile is not configured for relying party "
                        + requestContext.getInboundMessageIssuer();
                log.warn(msg);
                throw new ProfileException(msg);
            }

            checkSamlVersion(requestContext);
            
            // Get session corresponding to NameID. This is limited to one session, which means
            // we can't know if more than one might have been issued for a particular NameID.
            SessionManager<Session> sessionManager = getSessionManager();
            String nameIDIndex = getSessionIndexFromNameID(requestContext.getSubjectNameIdentifier());
            log.debug("Querying SessionManager based on NameID '{}'", nameIDIndex);
            Session indexedSession = sessionManager.getSession(nameIDIndex);
            
            Status status = null;
            
            if (indexedSession == null) {
                // No session matched.
                log.info("LogoutRequest did not reference an active session.");
                status = buildStatus(StatusCode.REQUESTER_URI, StatusCode.UNKNOWN_PRINCIPAL_URI, null);
            } else if (!indexedSession.getServicesInformation().keySet().contains(
                    requestContext.getInboundMessageIssuer())) {
                // Session matched, but it's not associated with the requesting SP.
                indexedSession = null;
                log.warn("Requesting entity is not a participant in the referenced session.");
                status = buildStatus(StatusCode.REQUESTER_URI, StatusCode.UNKNOWN_PRINCIPAL_URI, null);
            } else if (getInboundBinding().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
                // For SOAP, there's no active session and all we're doing is destroying the matched one.
                // If there are other service records attached, then it's a partial logout.
                if (indexedSession.getServicesInformation().keySet().size() > 1) {
                    status = buildStatus(StatusCode.SUCCESS_URI, StatusCode.PARTIAL_LOGOUT_URI, null);
                } else {
                    status = buildStatus(StatusCode.SUCCESS_URI, null, null);
                }
            } else {
                // Get active session and compare it to the matched one.
                Session activeSession = getUserSession(inTransport);
                if (activeSession == null ||
                        DatatypeHelper.safeEquals(activeSession.getSessionID(), indexedSession.getSessionID())) {
                    // If there are other service records attached, then it's a partial logout.
                    if (indexedSession.getServicesInformation().keySet().size() > 1) {
                        status = buildStatus(StatusCode.SUCCESS_URI, StatusCode.PARTIAL_LOGOUT_URI, null);
                    } else {
                        status = buildStatus(StatusCode.SUCCESS_URI, null, null);
                    }
                } else {
                    // Session found, but it's not the same as the active session.
                    indexedSession = null;
                    log.warn("LogoutRequest referenced a session other than the client's current one.");
                    status = buildStatus(StatusCode.REQUESTER_URI, StatusCode.UNKNOWN_PRINCIPAL_URI, null);
                }
            }
            
            // Async means that we're not responding to the SP, but to the user.
            // SOAP is an outlying case, not technically expected, but we can just
            // return an empty response in that case.
            if (requestContext.isAsynchronous()) {
                if (getInboundBinding().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
                    if (indexedSession != null) {
                        log.info("Invalidating session identified by LogoutRequest: {}", indexedSession.getSessionID());
                        destroySession(indexedSession);
                    }
                    try {
                        outTransport.setCharacterEncoding("UTF-8");
                        outTransport.setHeader("Content-Type", "text/plain");
                        outTransport.setStatusCode(HttpServletResponse.SC_OK);
                        Writer out = new OutputStreamWriter(outTransport.getOutgoingStream(), "UTF-8");
                        out.flush();
                     } catch (Exception we) {
                        log.error("Error returning empty response.", we);
                     }
                } else {
                    localLogout(indexedSession, inTransport, outTransport);
                }
                writeAuditLogEntry(requestContext);
                return;
            }
            
            if (status.getStatusCode().getValue().equals(StatusCode.SUCCESS_URI)) {
                log.info("Invalidating session identified by LogoutRequest: {}", indexedSession.getSessionID());
	            HttpServletRequest request = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
	            request.getSession().invalidate();
                destroySession(indexedSession);
                samlResponse = buildLogoutResponse(requestContext, status);
            } else {
                requestContext.setFailureStatus(status);
                samlResponse = buildLogoutResponse(requestContext, null);
            }

        } catch (ProfileException e) {
            if (requestContext.getPeerEntityEndpoint() != null) {
                // This means it wasn't an Async LogoutRequest.
                if (requestContext.getFailureStatus() == null) {
                    requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, e.getMessage()));
                }
                samlResponse = buildLogoutResponse(requestContext, null);
            } else if (!requestContext.isAsynchronous()
                    && getInboundBinding().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
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
            } else {
                throw e;
            }
        }

        requestContext.setOutboundSAMLMessage(samlResponse);
        requestContext.setOutboundSAMLMessageId(samlResponse.getID());
        requestContext.setOutboundSAMLMessageIssueInstant(samlResponse.getIssueInstant());
        encodeResponse(requestContext);
        writeAuditLogEntry(requestContext);
    }
       
    /**
     * Builds LogoutResponse. If status is null, the requestContext's failure status property will be used.
     *
     * @param requestContext    context information for the current request
     * @param status    a Status to add to the response
     * @return  a new LogoutResponse message
     * @throws ProfileException if an error occurs during profile execution
     */
    protected LogoutResponse buildLogoutResponse(SLORequestContext requestContext, Status status)
            throws ProfileException {
        LogoutResponse logoutResponse = responseBuilder.buildObject();
        logoutResponse.setIssueInstant(new DateTime());
        populateStatusResponse(requestContext, logoutResponse);
        if (status != null) {
            logoutResponse.setStatus(status);
        } else {
            logoutResponse.setStatus(requestContext.getFailureStatus());
        }
        return logoutResponse;
    }

    /**
     * Destroy a session.
     *
     * @param session   session to destroy
     */
    protected void destroySession(Session session) {
        getSessionManager().destroySession(session.getSessionID());
    }
    
    /** {@inheritDoc} */
    @Override
    protected void populateSAMLMessageInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        if (requestContext.getInboundSAMLMessage() instanceof LogoutRequest) {
            LogoutRequest request = (LogoutRequest) requestContext.getInboundSAMLMessage();
            requestContext.setPeerEntityId(request.getIssuer().getValue());
            requestContext.setInboundSAMLMessageId(request.getID());
            if (request.getNameID() != null) {
                requestContext.setSubjectNameIdentifier(request.getNameID());
            } else if (request.getEncryptedID() != null) {
                throw new ProfileException("Use of EncryptedID not supported in LogoutRequest.");
            } else {
                throw new ProfileException("Incoming LogoutRequest did not contain SAML2 NameID.");
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void populateRelyingPartyInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        super.populateRelyingPartyInformation(requestContext);

        EntityDescriptor relyingPartyMetadata = requestContext.getPeerEntityMetadata();
        if (relyingPartyMetadata != null) {
            requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
            requestContext.setPeerEntityRoleMetadata(relyingPartyMetadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS));
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void populateAssertingPartyInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        super.populateAssertingPartyInformation(requestContext);

        EntityDescriptor localEntityDescriptor = requestContext.getLocalEntityMetadata();
        if (localEntityDescriptor != null) {
            requestContext.setLocalEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
            requestContext.setLocalEntityRoleMetadata(localEntityDescriptor
                    .getIDPSSODescriptor(SAMLConstants.SAML20P_NS));
        }
    }
    
    /** {@inheritDoc} */
    @Override
    protected Endpoint selectEndpoint(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        Endpoint endpoint = null;
        if (getInboundBinding().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
            endpoint = sloServiceBuilder.buildObject();
            endpoint.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
        } else {
            BasicEndpointSelector endpointSelector = new BasicEndpointSelector();
            endpointSelector.setEndpointType(SingleLogoutService.DEFAULT_ELEMENT_NAME);
            endpointSelector.setMetadataProvider(getMetadataProvider());
            endpointSelector.setEntityMetadata(requestContext.getPeerEntityMetadata());
            endpointSelector.setEntityRoleMetadata(requestContext.getPeerEntityRoleMetadata());
            endpointSelector.setSamlRequest(requestContext.getInboundSAMLMessage());
            endpointSelector.getSupportedIssuerBindings().addAll(getSupportedOutboundBindings());
            endpoint = endpointSelector.selectEndpoint();
        }

        return endpoint;
    }

    /** {@inheritDoc} */
    @Override
    protected void populateProfileInformation(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
        // Overriding this so we can short-circuit the "no peer endpoint error".
        // We can treat that failure as equivalent to a request with the aslo:Asynchronous extension.
        AbstractSAMLProfileConfiguration profileConfig = (AbstractSAMLProfileConfiguration) requestContext
                .getRelyingPartyConfiguration().getProfileConfiguration(getProfileId());
        if (profileConfig != null) {
            requestContext.setProfileConfiguration(profileConfig);
            requestContext.setOutboundMessageArtifactType(profileConfig.getOutboundArtifactType());
        }

        boolean async = ((SLORequestContext) requestContext).isAsynchronous();
        if (!async) {
            Endpoint endpoint = selectEndpoint(requestContext);
            if (endpoint == null) {
                log.warn("No return endpoint available for relying party {}, treating LogoutRequest as Asynchronous",
                        requestContext.getInboundMessageIssuer());
                ((SLORequestContext) requestContext).setAsynchronous(true);
            }
            requestContext.setPeerEntityEndpoint(endpoint);
        } else {
            log.debug("No response requested, so skipping endpoint selection.");
        }
    }
    
    /**
     * Decodes an incoming request and populates a created request context with the resultant information.
     *
     * @param requestContext request context to which decoded information should be added
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     *
     * @throws ProfileException if there is a problem decoding the request
     */
    protected void decodeRequest(SLORequestContext requestContext,
            HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        log.debug("Decoding message with decoder binding '{}'", getInboundBinding());
        requestContext.setCommunicationProfileId(getProfileId());
        requestContext.setMetadataProvider(getMetadataProvider());
        requestContext.setInboundMessageTransport(inTransport);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        requestContext.setSecurityPolicyResolver(getSecurityPolicyResolver());
        requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        requestContext.setOutboundMessageTransport(outTransport);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);

        try {
            SAMLMessageDecoder decoder = getInboundMessageDecoder(requestContext);
            requestContext.setMessageDecoder(decoder);
            decoder.decode(requestContext);
            log.debug("Decoded request from relying party '{}'", requestContext.getInboundMessageIssuer());

            if (!(requestContext.getInboundSAMLMessage() instanceof LogoutRequest)) {
                log.warn("Incoming message was not a LogoutRequest, it was a {}",
                        requestContext.getInboundSAMLMessage().getClass().getName());
                requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER_URI, null,
                        "Invalid SAML LogoutRequest message."));
                throw new ProfileException("Invalid SAML LogoutRequest message.");
            }
            
            // Check for aslo:Asynchronous extension.
            LogoutRequest logoutRequest = (LogoutRequest) requestContext.getInboundSAMLMessage();
            Extensions exts = logoutRequest.getExtensions();
            if (exts != null) {
                List<XMLObject> asyncs = exts.getUnknownXMLObjects(Asynchronous.DEFAULT_ELEMENT_NAME);
                requestContext.setAsynchronous(asyncs != null && !asyncs.isEmpty());
                if (requestContext.isAsynchronous()) {
                    log.debug("Incoming LogoutRequest contains aslo:Asynchronous extension.");
                }
            }
        } catch (MessageDecodingException e) {
            String msg = "Error decoding logout request message";
            log.warn(msg, e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, msg));
            throw new ProfileException(msg, e);
        } catch (SecurityException e) {
            String msg = "Message did not meet security requirements";
            log.warn(msg, e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.REQUEST_DENIED_URI, msg));
            throw new ProfileException(msg, e);
        } finally {
            // Set as much information as can be retrieved from the decoded message
            populateRequestContext(requestContext);
        }
    }

    /** Represents the internal state of a Logout Request while it's being processed by the IdP. */
    public class SLORequestContext
            extends BaseSAML2ProfileRequestContext<LogoutRequest, LogoutResponse, LogoutRequestConfiguration> {
        
        /** Request included the aslo:Asynchronous extension. */
        private boolean async;
        
        /**
         * Indicates whether the request included the aslo:Asynchronous extension.
         * 
         * @return the async flag
         */
        public boolean isAsynchronous() {
            return async;
        }
        
        /**
         * Sets whether the request included the aslo:Asynchronous extension.
         * 
         * @param flag the async flag
         */
        public void setAsynchronous(boolean flag) {
            async = flag;
        }
    }
}