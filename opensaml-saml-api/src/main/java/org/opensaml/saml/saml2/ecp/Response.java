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

package org.opensaml.saml.saml2.ecp;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.soap.soap11.ActorBearing;
import org.opensaml.soap.soap11.MustUnderstandBearing;

import net.shibboleth.shared.annotation.constraint.NotEmpty;

/**
 * SAML 2.0 ECP Response SOAP header.
 */
public interface Response extends SAMLObject, MustUnderstandBearing, ActorBearing {
    
    /** Element local name. */
    @Nonnull @NotEmpty static final String DEFAULT_ELEMENT_LOCAL_NAME = "Response";

    /** Default element name. */
    @Nonnull static final QName DEFAULT_ELEMENT_NAME =
        new QName(SAMLConstants.SAML20ECP_NS, DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20ECP_PREFIX);

    /** Local name of the XSI type. */
    @Nonnull @NotEmpty static final String TYPE_LOCAL_NAME = "ResponseType";

    /** QName of the XSI type. */
    @Nonnull static final QName TYPE_NAME =
        new QName(SAMLConstants.SAML20ECP_NS, TYPE_LOCAL_NAME, SAMLConstants.SAML20ECP_PREFIX);

    /** ProviderName attribute name. */
    @Nonnull @NotEmpty static final String ASSERTION_CONSUMER_SERVICE_URL_ATTRIB_NAME = "AssertionConsumerServiceURL";
    
    /**
     * Get the AssertionConsumerServiceURL attribute value.
     * 
     * @return the AssertionConsumerServiceURL attribute value
     */
    @Nullable String getAssertionConsumerServiceURL();

    /**
     * Get the AssertionConsumerServiceURL attribute value.
     * 
     * @param newAssertionConsumerServiceURL the new AssertionConsumerServiceURL attribute value
     */
    void setAssertionConsumerServiceURL(@Nullable final String newAssertionConsumerServiceURL);

}
