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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.opensaml.core.xml.AbstractXMLObject;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.xmlsec.encryption.CipherReference;
import org.opensaml.xmlsec.encryption.Transforms;

/**
 * Concrete implementation of {@link org.opensaml.xmlsec.encryption.CipherReference}.
 */
public class CipherReferenceImpl extends AbstractXMLObject implements CipherReference {

    /** URI attribute value. */
    private String uri;

    /** Transforms child element value. */
    private Transforms transforms;

    /**
     * Constructor.
     * 
     * @param namespaceURI namespace URI
     * @param elementLocalName local name
     * @param namespacePrefix namespace prefix
     */
    protected CipherReferenceImpl(final String namespaceURI, final String elementLocalName,
            final String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    /** {@inheritDoc} */
    public String getURI() {
        return this.uri;
    }

    /** {@inheritDoc} */
    public void setURI(final String newURI) {
        this.uri = prepareForAssignment(this.uri, newURI);
    }

    /** {@inheritDoc} */
    public Transforms getTransforms() {
        return this.transforms;
    }

    /** {@inheritDoc} */
    public void setTransforms(final Transforms newTransforms) {
        this.transforms = prepareForAssignment(this.transforms, newTransforms);
    }

    /** {@inheritDoc} */
    public List<XMLObject> getOrderedChildren() {
        final ArrayList<XMLObject> children = new ArrayList<>();

        if (transforms != null) {
            children.add(transforms);
        }

        if (children.size() == 0) {
            return null;
        }

        return Collections.unmodifiableList(children);
    }

}
