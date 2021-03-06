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
package edu.internet2.middleware.shibboleth.idp.session.impl;

import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;

import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.core.NameID;

/** Information about a service a user has logged in to. */
public class ServiceInformationImpl implements ServiceInformation {

    /** Serial version UID. */
    private static final long serialVersionUID = -4284509878936885637L;
    
    /** Entity ID of the service. */
    private String entityID;
    
    /** Instant the user was authenticated to the service. */
    private long authenticationInstant;
    
    /** Authentication method used to authenticate the user to the service. */
    private AuthenticationMethodInformation methodInfo;
    
    /** Name identifier used to identify the user at the service. */
    private String nameIdentifier;
    
    /** Name identifier format. */
    private String nameIdentifierFormat;
    
    /** SP Name qualifier for the name identifier. */
    private String SPNameQualifier;
    
    /** Name qualifier for the name identifier. */
    private String nameQualifier;

    /**
     * Default constructor.
     * 
     * @param id unique identifier for the service.
     * @param loginInstant time the user logged in to the service.
     * @param method authentication method used to log into the service.
     */
    public ServiceInformationImpl(String id, DateTime loginInstant, AuthenticationMethodInformation method) {
        entityID = id;
        authenticationInstant = loginInstant.toDateTime(ISOChronology.getInstanceUTC()).getMillis();
        methodInfo = method;
    }

    /** {@inheritDoc} */
    public synchronized String getEntityID() {
        return entityID;
    }

    /** {@inheritDoc} */
    public synchronized DateTime getLoginInstant() {
        return new DateTime(authenticationInstant, ISOChronology.getInstanceUTC());
    }

    /** {@inheritDoc} */
    public synchronized AuthenticationMethodInformation getAuthenticationMethod() {
        return methodInfo;
    }

    /** {@inheritDoc} */
    public synchronized int hashCode() {
        return entityID.hashCode();
    }

    /** {@inheritDoc} */
    public synchronized boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        if (!(obj instanceof ServiceInformation)) {
            return false;
        }

        ServiceInformation si = (ServiceInformation) obj;
        return entityID.equals(si.getEntityID());
    }

    /**
     * Sets the name identifier for the principal known by the service.
     * 
     * @param nameIdentifier
     */
    public synchronized void setSAML2NameIdentifier(NameID nameIdentifier) {
        if (nameIdentifier != null) {
            this.nameIdentifier = nameIdentifier.getValue();
            this.nameIdentifierFormat = nameIdentifier.getFormat();
            this.nameQualifier = nameIdentifier.getNameQualifier();
            this.SPNameQualifier = nameIdentifier.getSPNameQualifier();
        }
    }

    /**
     * Sets the name identifier for the principal known by the service.
     * 
     * @param nameIdentifier
     */
    public synchronized void setShibbolethNameIdentifier(NameIdentifier nameIdentifier) {
        if (nameIdentifier != null) {
            this.nameIdentifier = nameIdentifier.getNameIdentifier();
            this.nameIdentifierFormat = nameIdentifier.getFormat();
            this.nameQualifier = nameIdentifier.getNameQualifier();
        }
    }

    /** {@inheritDoc} */
    public synchronized String getNameIdentifier() {
        return nameIdentifier;
    }

    /** {@inheritDoc} */
    public synchronized String getNameIdentifierFormat() {
        return nameIdentifierFormat;
    }

    /** {@inheritDoc} */
    public synchronized String getNameQualifier() {
        return nameQualifier;
    }

    /** {@inheritDoc} */
    public synchronized String getSPNameQualifier() {
        return SPNameQualifier;
    }
}
