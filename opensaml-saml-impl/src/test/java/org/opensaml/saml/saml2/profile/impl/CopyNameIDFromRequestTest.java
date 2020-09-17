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

package org.opensaml.saml.saml2.profile.impl;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.opensaml.core.testing.OpenSAMLInitBaseTestCase;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.testing.ActionTestingSupport;
import org.opensaml.profile.testing.RequestContextBuilder;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.testing.SAML2ActionTestingSupport;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/** Test for {@link CopyNameIDFromRequest}. */
public class CopyNameIDFromRequestTest extends OpenSAMLInitBaseTestCase {

    private static final String NAME_QUALIFIER = "https://idp.example.org";

    private ProfileRequestContext prc;
    
    private CopyNameIDFromRequest action;
    
    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        prc = new RequestContextBuilder().buildProfileRequestContext();
        
        action = new CopyNameIDFromRequest();
        action.initialize();
    }
    
    @Test
    public void testNoResponse() {
        action.execute(prc);
        ActionTestingSupport.assertEvent(prc, EventIds.INVALID_MSG_CTX);
    }

    @Test
    public void testNoAssertions() {
        prc.getOutboundMessageContext().setMessage(SAML2ActionTestingSupport.buildResponse());

        action.execute(prc);
        ActionTestingSupport.assertProceedEvent(prc);
        Assert.assertTrue(((Response) prc.getOutboundMessageContext().getMessage()).getAssertions().isEmpty());
    }

    @Test
    public void testNoRequest() {
        prc.getOutboundMessageContext().setMessage(SAML2ActionTestingSupport.buildResponse());
        ((Response) prc.getOutboundMessageContext().getMessage()).getAssertions().add(SAML2ActionTestingSupport.buildAssertion());
        addAssertions();

        action.execute(prc);
        ActionTestingSupport.assertEvent(prc, EventIds.INVALID_MSG_CTX);
    }

    @Test
    public void testNoName() {
        prc.getOutboundMessageContext().setMessage(SAML2ActionTestingSupport.buildResponse());
        ((Response) prc.getOutboundMessageContext().getMessage()).getAssertions().add(SAML2ActionTestingSupport.buildAssertion());
        addAssertions();

        prc.getInboundMessageContext().setMessage(SAML2ActionTestingSupport.buildAttributeQueryRequest(null));
        
        action.execute(prc);
        ActionTestingSupport.assertEvent(prc, EventIds.INVALID_MSG_CTX);
    }
    
    @Test void testCopy() {
        
        Subject subject = SAML2ActionTestingSupport.buildSubject("jdoe");
        subject.getNameID().setNameQualifier(NAME_QUALIFIER);
        prc.getInboundMessageContext().setMessage(SAML2ActionTestingSupport.buildAttributeQueryRequest(subject));
        addAssertions();
        
        action.execute(prc);
        ActionTestingSupport.assertProceedEvent(prc);
        
        Assertion assertion = ((Response) prc.getOutboundMessageContext().getMessage()).getAssertions().get(0);
        subject = assertion.getSubject();
        Assert.assertNotNull(subject);
        Assert.assertNotNull(subject.getNameID());
        Assert.assertEquals(subject.getNameID().getValue(), "jdoe");
        Assert.assertEquals(subject.getNameID().getNameQualifier(), NAME_QUALIFIER);
    }

    /** Set up the test message with some assertions. */
    private void addAssertions() {
        final Response response = SAML2ActionTestingSupport.buildResponse();
        response.getAssertions().add(SAML2ActionTestingSupport.buildAssertion());
        response.getAssertions().add(SAML2ActionTestingSupport.buildAssertion());
        prc.getOutboundMessageContext().setMessage(response);
    }
    
}