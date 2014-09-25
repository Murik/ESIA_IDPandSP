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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

/**
 * Ant task that makes the contents of a file available as a property.
 * 
 * This ant task requires two attributes:
 * <ul>
 * <li><strong>input</strong> - the path to the input file</li>
 * <li><strong>addProperty</strong> - name of the property that will receive the file contents as a string</li>
 * <ul>
 */
public class StringFromFile extends Task {

    /** The input file. */
    private File input;

    /** Property name to which the file contents are added. */
    private String addProperty;

    /** {@inheritDoc} */
    public void execute() throws BuildException {
        try {
            StringBuilder fileData = new StringBuilder(1000);
            BufferedReader reader = new BufferedReader(new FileReader(input));
            char[] buf = new char[1024];
            int numRead = 0;
            while ((numRead = reader.read(buf)) != -1) {
                fileData.append(buf, 0, numRead);
            }
            reader.close();
            getProject().setProperty(addProperty, fileData.toString());
        } catch (IOException e) {
            throw new BuildException("Unable to read file " + input.getAbsolutePath(), e);
        }
    }

    /**
     * Sets the file from which the data will be read.
     * 
     * @param input file from which the data will be read
     */
    public void setInput(File input) {
        this.input = input;
    }

    /**
     * Sets the property name to which the file contents are added.
     * 
     * @param addProperty property name to which the file contents are added.
     */
    public void setAddProperty(String addProperty) {
        this.addProperty = addProperty;
    }
}