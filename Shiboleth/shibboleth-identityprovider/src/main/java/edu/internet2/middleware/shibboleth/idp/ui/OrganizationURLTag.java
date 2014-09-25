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
import org.opensaml.saml2.metadata.OrganizationURL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Service OrganizationURL - directly from the metadata if present. */
public class OrganizationURLTag extends ServiceTagSupport {

    /** check style requires the serialVersionUID. */
    private static final long serialVersionUID = -5907239557715040242L;

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(OrganizationURLTag.class);

    /** Bean storage for the link text attribute. */
    private static String linkText;

    /**
     * Bean setter for the link text attribute.
     * 
     * @param text the link text to put in
     */
    public void setLinkText(String text) {
        linkText = text;
    }

    /**
     * look for the &lt;OrganizationURL&gt;.
     * 
     * @return null or an appropriate string
     */
    private String getOrganizationURL() {
        Organization org = getSPOrganization();
        if (org != null && org.getURLs() != null) {
            for (String lang : getBrowserLanguages()) {

                for (OrganizationURL orgURL : org.getURLs()) {
                    if (orgURL.getURL() == null || orgURL.getURL().getLanguage() == null) {
                        continue;
                    } else {
                        log.debug("Found OrganizationURL in Organization, language={}", orgURL.getURL().getLanguage());
                    }
                    
                    if (orgURL.getURL().getLanguage().equals(lang)) {
                        //
                        // Found it
                        //
                        log.debug("returning OrganizationURL from Organization, {}", orgURL.getURL().getLocalString());
                        return orgURL.getURL().getLocalString();
                    }
                }
            }
            log.debug("No relevant OrganizationURL in Organization");
        }
        return null;
    }

    @Override
    public int doEndTag() throws JspException {

        String orgURL = getOrganizationURL();

        try {
            if (null == orgURL) {
                BodyContent bc = getBodyContent();
                if (null != bc) {
                    JspWriter ew = bc.getEnclosingWriter();
                    if (ew != null) {
                        bc.writeOut(ew);
                    }
                }
            } else {
                pageContext.getOut().print(buildHyperLink(orgURL, linkText));
            }
        } catch (IOException e) {
            log.warn("Error generating OrganizationURL");
            throw new JspException("EndTag", e);
        }
        return super.doEndTag();
    }

}