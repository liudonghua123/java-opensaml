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
package org.opensaml.saml.saml1.core;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.primitive.DeprecationSupport;
import net.shibboleth.utilities.java.support.primitive.DeprecationSupport.ObjectType;

/**
 * This interface defines how the object representing a SAML1 <code> ConfirmationMethod </code> element behaves.
 */
public interface ConfirmationMethod extends SAMLObject, XSURI {
    
    /** Element name, no namespace. */
    @Nonnull @NotEmpty static final String DEFAULT_ELEMENT_LOCAL_NAME = "ConfirmationMethod";
    
    /** Default element name. */
    @Nonnull static final QName DEFAULT_ELEMENT_NAME =
            new QName(SAMLConstants.SAML1_NS, DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML1_PREFIX);
        
    /** Bearer confirmation method. */
    @Nonnull @NotEmpty static final String METHOD_BEARER = "urn:oasis:names:tc:SAML:1.0:cm:bearer";

    /** Artifact confirmation method. */
    @Nonnull @NotEmpty static final String METHOD_ARTIFACT = "urn:oasis:names:tc:SAML:1.0:cm:artifact";

    /** Deprecated Artifact confirmation method. */
    @Deprecated
    @Nonnull @NotEmpty static final String METHOD_ARTIFACT_DEPRECATED = "urn:oasis:names:tc:SAML:1.0:cm:artifact-01";
    
    /** Holder of Key confirmation method. */
    @Nonnull @NotEmpty static final String METHOD_HOLDER_OF_KEY = "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key";

    /** Sender-Vouches confirmation method. */
    @Nonnull @NotEmpty static final String METHOD_SENDER_VOUCHES = "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches";
    
    /**
     * Gets the confirmation method.
     * 
     * @return the confirmation method
     */
    @Deprecated(forRemoval=true, since="4.0.0")
    @Nullable default String getConfirmationMethod() {
        DeprecationSupport.warn(ObjectType.METHOD, "getConfirmationMethod", ConfirmationMethod.class.toString(),
                "getURI");
        return getURI();
    }
    
    /**
     * Sets the confirmation method.
     * 
     * @param uri the confirmation method
     */
    @Deprecated(forRemoval=true, since="4.0.0")
    default void setConfirmationMethod(@Nullable final String uri) {
        DeprecationSupport.warn(ObjectType.METHOD, "setConfirmationMethod", ConfirmationMethod.class.toString(),
                "setURI");
        setURI(uri);
    }
    
}