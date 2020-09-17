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

package org.opensaml.xmlsec.encryption.impl;


import org.testng.annotations.Test;
import org.testng.annotations.BeforeMethod;
import org.testng.Assert;
import org.opensaml.core.testing.XMLObjectProviderBaseTestCase;
import org.opensaml.xmlsec.encryption.DataReference;
import org.opensaml.xmlsec.encryption.KeyReference;
import org.opensaml.xmlsec.encryption.ReferenceList;

/**
 *
 */
public class ReferenceListTest extends XMLObjectProviderBaseTestCase {
    
    private int expectedNumDataRefs;
    private int expectedNumKeyRefs;
    
    /**
     * Constructor
     *
     */
    public ReferenceListTest() {
        singleElementFile = "/org/opensaml/xmlsec/encryption/impl/ReferenceList.xml";
        childElementsFile = "/org/opensaml/xmlsec/encryption/impl/ReferenceListChildElements.xml";
    }

    @BeforeMethod
    protected void setUp() throws Exception {
        expectedNumDataRefs = 2;
        expectedNumKeyRefs = 1;
    }

    /** {@inheritDoc} */
    @Test
    public void testSingleElementUnmarshall() {
        ReferenceList rl = (ReferenceList) unmarshallElement(singleElementFile);
        
        Assert.assertNotNull(rl, "ReferenceList");
        Assert.assertEquals(rl.getDataReferences().size(), 0, "# of DataReference children");
        Assert.assertEquals(rl.getKeyReferences().size(), 0, "# of KeyReference children");
    }

    /** {@inheritDoc} */
    @Test
    public void testChildElementsUnmarshall() {
        ReferenceList rl = (ReferenceList) unmarshallElement(childElementsFile);
        
        Assert.assertNotNull(rl, "ReferenceList");
        Assert.assertEquals(rl.getDataReferences().size(), expectedNumDataRefs, "# of DataReference children");
        Assert.assertEquals(rl.getKeyReferences().size(), expectedNumKeyRefs, "# of KeyReference children");
    }

    /** {@inheritDoc} */
    @Test
    public void testSingleElementMarshall() {
        ReferenceList rl = (ReferenceList) buildXMLObject(ReferenceList.DEFAULT_ELEMENT_NAME);
        
        assertXMLEquals(expectedDOM, rl);
    }

    /** {@inheritDoc} */
    @Test
    public void testChildElementsMarshall() {
        ReferenceList rl = (ReferenceList) buildXMLObject(ReferenceList.DEFAULT_ELEMENT_NAME);
        
        rl.getReferences().add( (DataReference) buildXMLObject(DataReference.DEFAULT_ELEMENT_NAME));
        rl.getReferences().add( (KeyReference) buildXMLObject(KeyReference.DEFAULT_ELEMENT_NAME));
        rl.getReferences().add( (DataReference) buildXMLObject(DataReference.DEFAULT_ELEMENT_NAME));
        
        assertXMLEquals(expectedChildElementsDOM, rl);
    }

}
