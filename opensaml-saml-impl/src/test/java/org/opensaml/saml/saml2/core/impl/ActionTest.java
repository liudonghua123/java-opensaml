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

package org.opensaml.saml.saml2.core.impl;

import org.testng.annotations.Test;
import org.testng.annotations.BeforeMethod;
import org.testng.Assert;
import javax.xml.namespace.QName;

import org.opensaml.core.testing.XMLObjectProviderBaseTestCase;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Action;

/**
 * Test case for creating, marshalling, and unmarshalling {@link org.opensaml.saml.saml2.core.impl.ActionImpl}.
 */
public class ActionTest extends XMLObjectProviderBaseTestCase {

    /** Expected value of action */
    protected String expectedAction;

    /** Expected value of Namespace */
    protected String expectedNamespace;

    /** Constructor */
    public ActionTest() {
        singleElementFile = "/org/opensaml/saml/saml2/core/impl/Action.xml";
        singleElementOptionalAttributesFile = "/org/opensaml/saml/saml2/core/impl/ActionOptionalAttributes.xml";
    }

    @BeforeMethod
    protected void setUp() throws Exception {
        expectedAction = "action name";
        expectedNamespace = "ns";
    }

    /** {@inheritDoc} */
    @Test
    public void testSingleElementUnmarshall() {
        Action action = (Action) unmarshallElement(singleElementFile);

        String actionname = action.getValue();
        Assert.assertEquals(actionname, expectedAction, "Action was " + actionname + ", expected " + expectedAction);
    }

    /** {@inheritDoc} */
    @Test
    public void testSingleElementOptionalAttributesUnmarshall() {
        Action action = (Action) unmarshallElement(singleElementOptionalAttributesFile);

        String actionname = action.getValue();
        Assert.assertEquals(actionname, expectedAction, "Action was " + actionname + ", expected " + expectedAction);

        String namespace = action.getNamespace();
        Assert.assertEquals(namespace, expectedNamespace, "Namespace was " + namespace + ", expected " + expectedNamespace);
    }

    /** {@inheritDoc} */
    @Test
    public void testSingleElementMarshall() {
        QName qname = new QName(SAMLConstants.SAML20_NS, Action.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);
        Action action = (Action) buildXMLObject(qname);

        action.setValue(expectedAction);
        assertXMLEquals(expectedDOM, action);
    }

    /** {@inheritDoc} */
    @Test
    public void testSingleElementOptionalAttributesMarshall() {
        QName qname = new QName(SAMLConstants.SAML20_NS, Action.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);
        Action action = (Action) buildXMLObject(qname);

        action.setValue(expectedAction);
        action.setNamespace(expectedNamespace);
        assertXMLEquals(expectedOptionalAttributesDOM, action);
    }
}