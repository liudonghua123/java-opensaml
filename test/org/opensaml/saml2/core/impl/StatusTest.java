/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
package org.opensaml.saml2.core.impl;

import javax.xml.namespace.QName;

import org.opensaml.common.SAMLObjectBaseTestCase;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Status;

/**
 * Test case for creating, marshalling, and unmarshalling
 * {@link org.opensaml.saml2.core.impl.StatusImpl}.
 */
public class StatusTest extends SAMLObjectBaseTestCase {

    /**
     * Constructor
     *
     */
    public StatusTest() {
        singleElementFile = "/data/org/opensaml/saml2/core/impl/Status.xml";
        childElementsFile = "/data/org/opensaml/saml2/core/impl/StatusChildElements.xml";
    }

    
    /**
     * @see org.opensaml.common.SAMLObjectBaseTestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();
        
    }


    /**
     * @see org.opensaml.common.SAMLObjectBaseTestCase#testSingleElementMarshall()
     */
    public void testSingleElementMarshall() {
        QName qname = new QName(SAMLConstants.SAML20P_NS, Status.LOCAL_NAME);
        Status status = (Status) buildSAMLObject(qname);
        
        assertEquals(expectedDOM, status);
    }
    
    
    
    /**
     * @see org.opensaml.common.SAMLObjectBaseTestCase#testChildElementsMarshall()
     */
    public void testChildElementsMarshall() {
        QName qname = new QName(SAMLConstants.SAML20P_NS, Status.LOCAL_NAME);
        Status status = (Status) buildSAMLObject(qname);
        
        status.setStatusCode(new StatusCodeImpl());
        status.setStatusMessage(new StatusMessageImpl());
        
        assertEquals(expectedChildElementsDOM, status);
    }


    /**
     * @see org.opensaml.common.SAMLObjectBaseTestCase#testSingleElementUnmarshall()
     */
    public void testSingleElementUnmarshall() {
        Status status = (Status) unmarshallElement(singleElementFile);
        
        assertNotNull(status);
    }


    /**
     * @see org.opensaml.common.SAMLObjectBaseTestCase#testChildElementsUnmarshall()
     */
    public void testChildElementsUnmarshall() {
        Status status = (Status) unmarshallElement(childElementsFile);
        
        assertNotNull("StatusCode of Status was null", status.getStatusCode());
        assertNotNull("StatusMessage of Status was null", status.getStatusMessage());
    }
    

}
