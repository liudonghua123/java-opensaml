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

package org.opensaml.saml.saml2.core.impl;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.AbstractSAMLObjectUnmarshaller;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.w3c.dom.Attr;

import com.google.common.base.Strings;

import net.shibboleth.shared.xml.DOMTypeSupport;

/**
 * A thread-safe Unmarshaller for {@link org.opensaml.saml.saml2.core.SubjectConfirmationData} objects.
 */
public class SubjectConfirmationDataUnmarshaller extends AbstractSAMLObjectUnmarshaller {

    /**
     * {@inheritDoc}
     */
    protected void processChildElement(final XMLObject parentSAMLObject, final XMLObject childSAMLObject)
            throws UnmarshallingException {
        final SubjectConfirmationData subjectCD = (SubjectConfirmationData) parentSAMLObject;

        subjectCD.getUnknownXMLObjects().add(childSAMLObject);
    }

    /** {@inheritDoc} */
    protected void processAttribute(final XMLObject samlObject, final Attr attribute) throws UnmarshallingException {
        final SubjectConfirmationData subjectCD = (SubjectConfirmationData) samlObject;

        if (attribute.getNamespaceURI() == null) {
            if (attribute.getLocalName().equals(SubjectConfirmationData.NOT_BEFORE_ATTRIB_NAME)
                    && !Strings.isNullOrEmpty(attribute.getValue())) {
                subjectCD.setNotBefore(DOMTypeSupport.stringToInstant(attribute.getValue()));
            } else if (attribute.getLocalName().equals(SubjectConfirmationData.NOT_ON_OR_AFTER_ATTRIB_NAME)
                    && !Strings.isNullOrEmpty(attribute.getValue())) {
                subjectCD.setNotOnOrAfter(DOMTypeSupport.stringToInstant(attribute.getValue()));
            } else if (attribute.getLocalName().equals(SubjectConfirmationData.RECIPIENT_ATTRIB_NAME)) {
                subjectCD.setRecipient(attribute.getValue());
            } else if (attribute.getLocalName().equals(SubjectConfirmationData.IN_RESPONSE_TO_ATTRIB_NAME)) {
                subjectCD.setInResponseTo(attribute.getValue());
            } else if (attribute.getLocalName().equals(SubjectConfirmationData.ADDRESS_ATTRIB_NAME)) {
                subjectCD.setAddress(attribute.getValue());
            } else {
                super.processAttribute(samlObject, attribute);
            }
        } else {
            processUnknownAttribute(subjectCD, attribute);
        }
    }
}