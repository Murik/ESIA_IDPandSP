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
import java.util.List;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspWriter;
import javax.servlet.jsp.tagext.BodyContent;

import org.opensaml.samlext.saml2mdui.PrivacyStatementURL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Service PrivacyURL - directly from the metadata if present. */
public class ServicePrivacyURLTag extends ServiceTagSupport {

    /** checkstyle needs serial version UID. */
    private static final long serialVersionUID = 1706444251504545781L;

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(ServicePrivacyURLTag.class);

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
     * look for the &lt;PrivacyURL&gt; in the &lt;UIInfo&gt;.
     * 
     * @return null or an appropriate string.
     */
    private String getPrivacyURLFromUIIinfo() {
        if (getSPUIInfo() != null && getSPUIInfo().getPrivacyStatementURLs() != null) {
            
            List<String> languages = getBrowserLanguages();
            for (String lang : languages) {

                for (PrivacyStatementURL privacyURL : getSPUIInfo().getPrivacyStatementURLs()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Found PrivacyStatementURL in UIInfo, language=" + privacyURL.getXMLLang());
                    }
                    if (privacyURL.getXMLLang().equals(lang)) {
                        //
                        // Found it
                        //
                        if (log.isDebugEnabled()) {
                            log.debug("returning URL from UIInfo " + privacyURL.getURI().getLocalString());
                        }
                        return privacyURL.getURI().getLocalString();
                    }
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("No relevant PrivacyStatementURL in UIInfo");
            }
        }
        return null;
    }

    @Override
    public int doEndTag() throws JspException {

        String privacyURL = getPrivacyURLFromUIIinfo();

        try {
            if (null == privacyURL) {
                BodyContent bc = getBodyContent();
                if (null != bc) {
                    JspWriter ew = bc.getEnclosingWriter();
                    if (ew != null) {
                        bc.writeOut(ew);
                    }
                }
            } else {
                pageContext.getOut().print(buildHyperLink(privacyURL, linkText));
            }
        } catch (IOException e) {
            log.warn("Error generating PrivacyStatementURL");
            throw new JspException("EndTag", e);
        }
        return super.doEndTag();
    }

}
