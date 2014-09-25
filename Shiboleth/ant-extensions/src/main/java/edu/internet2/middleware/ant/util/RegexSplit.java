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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.tools.ant.Task;

/**
 * A task that splits a string based on a regular expression.
 * 
 * This ant task requires three attributes:
 * <ul>
 * <li><strong>input</strong> - the value to be split by the regular expression</li>
 * <li><strong>regex</strong> - regular expression, with one matching group, use to split the string</li>
 * <li><strong>addProperty</strong> - name of the property that will receive the split string</li>
 * <ul>
 */
public class RegexSplit extends Task {

    /** The input string to be split. */
    private String input;

    /** The regular expression used to split the input string. */
    private String regex;

    /** The name of the property that will receive the split string. */
    private String addProperty;

    /** {@inheritDoc} */
    public void execute() {
        Pattern regexPat = Pattern.compile(regex);
        Matcher stringSplitter = regexPat.matcher(input);
        stringSplitter.matches();
        getProject().setProperty(addProperty, stringSplitter.group(1));
    }

    /**
     * Sets the input string to be split.
     * 
     * @param input input string to be split
     */
    public void setInput(String input) {
        this.input = input.trim();
    }

    /**
     * Sets the regular expression used to split the input string.
     * 
     * @param regex regular expression used to split the input string
     */
    public void setRegex(String regex) {
        this.regex = regex;
    }

    /**
     * Sets the name of the property that will receive the split string.
     * 
     * @param addProperty name of the property that will receive the split string
     */
    public void setAddProperty(String addProperty) {
        this.addProperty = addProperty;
    }
}