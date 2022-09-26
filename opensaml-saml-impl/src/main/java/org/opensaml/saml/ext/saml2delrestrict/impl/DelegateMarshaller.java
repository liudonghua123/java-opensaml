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

package org.opensaml.saml.ext.saml2delrestrict.impl;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.AbstractSAMLObjectMarshaller;
import org.opensaml.saml.ext.saml2delrestrict.Delegate;
import org.w3c.dom.Element;

import com.google.common.base.Strings;

import net.shibboleth.shared.xml.AttributeSupport;

/**
 * Marshaller for instances of {@link Delegate}.
 */
public class DelegateMarshaller extends AbstractSAMLObjectMarshaller {

    /** {@inheritDoc} */
    protected void marshallAttributes(final XMLObject xmlObject, final Element domElement) throws MarshallingException {
        final Delegate delegate = (Delegate) xmlObject;
        
        if (delegate.getDelegationInstant() != null) {
            AttributeSupport.appendDateTimeAttribute(domElement,
                    Delegate.DELEGATION_INSTANT_ATTRIB_QNAME, delegate.getDelegationInstant());
        }
        if (!Strings.isNullOrEmpty(delegate.getConfirmationMethod())) {
            domElement.setAttributeNS(null, Delegate.CONFIRMATION_METHOD_ATTRIB_NAME, delegate.getConfirmationMethod());
        }
        
        super.marshallAttributes(xmlObject, domElement);
    }

}
