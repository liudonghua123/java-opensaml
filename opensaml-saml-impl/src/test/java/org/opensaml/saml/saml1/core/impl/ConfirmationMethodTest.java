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

/**
 * 
 */
package org.opensaml.saml.saml1.core.impl;

import org.testng.annotations.Test;
import org.testng.Assert;
import javax.xml.namespace.QName;

import org.opensaml.core.xml.XMLObjectProviderBaseTestCase;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml1.core.ConfirmationMethod;

/**
 * test for {@link org.opensaml.saml.saml1.core.ConfirmationMethod}
 */
public class ConfirmationMethodTest extends XMLObjectProviderBaseTestCase {

    /** name used to generate objects */
    private final QName qname;

    /** Pattern in XML file */
    private String expectedConfirmationMethod;
    
    /**
     * Constructor
     */
    public ConfirmationMethodTest() {
        singleElementFile = "/org/opensaml/saml/saml1/impl/singleConfirmationMethod.xml";
        singleElementOptionalAttributesFile = "/org/opensaml/saml/saml1/impl/singleConfirmationMethodAttributes.xml";
        expectedConfirmationMethod = "confirmation";
        
        qname = new QName(SAMLConstants.SAML1_NS, ConfirmationMethod.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML1_PREFIX);
    }

    /** {@inheritDoc} */

    @Test
    public void testSingleElementUnmarshall() {
        ConfirmationMethod confirmationMethod = (ConfirmationMethod) unmarshallElement(singleElementFile);
        
        Assert.assertNull(confirmationMethod.getURI(), "Contents of Confirmation Method");

    }

    /** {@inheritDoc} */

    @Test
    public void testSingleElementOptionalAttributesUnmarshall() {
        ConfirmationMethod confirmationMethod = (ConfirmationMethod) unmarshallElement(singleElementOptionalAttributesFile);
        
        Assert.assertEquals(confirmationMethod.getURI(), expectedConfirmationMethod, "Contents of Confirmation Method");
    }

    /** {@inheritDoc} */

    @Test
    public void testSingleElementMarshall() {
        assertXMLEquals(expectedDOM, buildXMLObject(qname));
    }

    /** {@inheritDoc} */

    @Test
    public void testSingleElementOptionalAttributesMarshall() {
        ConfirmationMethod confirmationMethod = (ConfirmationMethod) buildXMLObject(qname);
        confirmationMethod.setURI(expectedConfirmationMethod);
        
        assertXMLEquals(expectedOptionalAttributesDOM, confirmationMethod);
    }

}
