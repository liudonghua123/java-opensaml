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

package org.opensaml.xmlsec.signature.impl;


import org.opensaml.core.testing.XMLObjectProviderBaseTestCase;
import org.opensaml.xmlsec.signature.PublicKey;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 *
 */
public class PublicKeyTest extends XMLObjectProviderBaseTestCase {
    
    private String expectedCryptoBinaryContent;

    /**
     * Constructor
     *
     */
    public PublicKeyTest() {
        singleElementFile = "/org/opensaml/xmlsec/signature/impl/PublicKey.xml";
    }

    @BeforeMethod
    protected void setUp() throws Exception {
        expectedCryptoBinaryContent = "someCryptoBinaryValue";
    }

    /** {@inheritDoc} */
    @Test
    public void testSingleElementUnmarshall() {
        PublicKey cbType = (PublicKey) unmarshallElement(singleElementFile);
        
        Assert.assertNotNull(cbType, "PublicKey");
        Assert.assertEquals(cbType.getValue(), expectedCryptoBinaryContent, "PublicKey value");
    }

    /** {@inheritDoc} */
    @Test
    public void testSingleElementMarshall() {
        PublicKey cbType = (PublicKey) buildXMLObject(PublicKey.DEFAULT_ELEMENT_NAME);
        cbType.setValue(expectedCryptoBinaryContent);
        
        assertXMLEquals(expectedDOM, cbType);
    }

}