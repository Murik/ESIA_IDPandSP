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

package edu.internet2.middleware.shibboleth.idp.ui;

import java.io.IOException;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspWriter;
import javax.servlet.jsp.tagext.BodyContent;

import org.opensaml.saml2.metadata.Organization;
import org.opensaml.saml2.metadata.OrganizationDisplayName;
import org.owasp.esapi.ESAPI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Service OrganizationDisplayName - directly from the metadata if present. */
public class OrganizationDisplayNameTag extends ServiceTagSupport {

    /** check style requires the serialVersionUID. */
    private static final long serialVersionUID = -6071985143143995657L;
    
    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(OrganizationDisplayNameTag.class);

    /**
     * look for the &lt;OrganizationDisplayName&gt;.
     * 
     * @return null or an appropriate string
     */
    private String getOrganizationDisplayName() {
        Organization org = getSPOrganization();
        if (org != null && org.getDisplayNames() != null) {
            for (String lang : getBrowserLanguages()) {

                for (OrganizationDisplayName name : org.getDisplayNames()) {
                    if (name.getName() == null || name.getName().getLanguage() == null) {
                        continue;
                    } else {
                        log.debug("Found OrganizationDisplayName in Organization, language={}",
                                name.getName().getLanguage());
                    }
                    
                    if (name.getName().getLanguage().equals(lang)) {
                        //
                        // Found it
                        //
                        log.debug("returning OrganizationDisplayName from Organization, {}",
                                name.getName().getLocalString());
                        return name.getName().getLocalString();
                    }
                }
            }
            log.debug("No relevant OrganizationDisplayName in Organization");
        }
        return null;
    }

    @Override
    public int doEndTag() throws JspException {

        String name = getOrganizationDisplayName();

        try {
            if (null == name) {
                BodyContent bc = getBodyContent();
                if (null != bc) {
                    JspWriter ew = bc.getEnclosingWriter();
                    if (ew != null) {
                        bc.writeOut(ew);
                    }
                }
            } else {
                pageContext.getOut().print(ESAPI.encoder().encodeForHTML(name));
            }
        } catch (IOException e) {
            log.warn("Error generating OrganizationDisplayName");
            throw new JspException("EndTag", e);
        }
        return super.doEndTag();
    }

}