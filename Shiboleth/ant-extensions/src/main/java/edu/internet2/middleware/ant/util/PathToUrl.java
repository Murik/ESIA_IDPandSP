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

package edu.internet2.middleware.ant.util;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;

import org.apache.tools.ant.Task;

/**
 * Converts a filesystem path into a URL.
 * 
 * This ant task requires two attributes:
 * <ul>
 * <li><strong>path</strong> - the path that will be converted in to a URL</li>
 * <li><strong>addProperty</strong> - name of the property that will receive the file contents as a string</li>
 * <ul>
 */
public class PathToUrl extends Task {

    /** Property name to which the file URL is added. */
    private String addProperty;

    /** Path to convert into a URL. */
    private String path;

    /** {@inheritDoc} */
    public void execute() {

        if (addProperty != null && getProject().getProperty(addProperty) != null) {
            log("Skipping " + getTaskName() + " as property " + addProperty + " has already been set.");
            return;
        }

        if (path == null) {
            log("Skipping " + getTaskName() + " because path was not specified.");
            return;
        }

        try {
            URL fileUrl = new File(path).toURI().toURL();
            getProject().setNewProperty(addProperty, fileUrl.toString());
        } catch (MalformedURLException e) {
            log("Skipping " + getTaskName() + " because path (" + path + ") could not be converted to a URL.");
            return;
        }
    }

    /**
     * Sets the name of the property that will contain the URL to the file.
     * 
     * @param property name of the property that will contain the URL to the file
     */
    public void setAddProperty(String property) {
        addProperty = property;
    }

    /**
     * Sets the path that will be converted into a file URL.
     * 
     * @param relativePath path that will be converted into a file URL
     */
    public void setPath(String relativePath) {
        path = relativePath;
    }
}