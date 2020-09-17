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

package org.opensaml.saml.saml2.metadata.impl;

import org.opensaml.core.testing.XMLObjectProviderBaseTestCase;
import org.opensaml.saml.saml2.metadata.AdditionalMetadataLocation;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Test case for creating, marshalling, and unmarshalling
 * {@link org.opensaml.saml.saml2.metadata.impl.AdditionalMetadataLocationImpl}.
 */
public class AdditionalMetadataLocationTest extends XMLObjectProviderBaseTestCase {

    /** Expected value of namespace attribute */
    protected String expectedNamespace;

    /** Expected value of element content */
    protected String expectedContent;

    /**
     * Constructor
     */
    public AdditionalMetadataLocationTest() {
        singleElementFile = "/org/opensaml/saml/saml2/metadata/impl/AdditionalMetadataLocation.xml";
    }

    @BeforeMethod
    protected void setUp() throws Exception {
        expectedNamespace = "http://example.org/xmlns";
        expectedContent = "http://example.org";
    }

    /** {@inheritDoc} */
    @Test
    public void testSingleElementUnmarshall() {
        AdditionalMetadataLocation locationObj = (AdditionalMetadataLocation) unmarshallElement(singleElementFile);

        String location = locationObj.getURI();
        Assert.assertEquals(location, expectedContent, "Location URI was " + location + ", expected " + expectedContent);

        String namespace = locationObj.getNamespaceURI();
        Assert.assertEquals(namespace, expectedNamespace, "Namepsace URI was " + namespace + ", expected " + expectedNamespace);
    }

    /** {@inheritDoc} */
    @Test
    public void testSingleElementMarshall() {
        AdditionalMetadataLocation location = (new AdditionalMetadataLocationBuilder()).buildObject(); 
        location.setURI(expectedContent);
        location.setNamespaceURI(expectedNamespace);

        assertXMLEquals(expectedDOM, location);
    }
}