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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.core.xml.AbstractXMLObject;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.IndexedXMLObjectChildrenList;
import org.opensaml.xmlsec.signature.DigestMethod;

/**
 * Concrete implementation of {@link org.opensaml.xmlsec.signature.DigestMethod}.
 */
public class DigestMethodImpl extends AbstractXMLObject implements DigestMethod {
    
    /** Algorithm attribute value. */
    private String algorithm;
    
    /** "any" children. */
    private final IndexedXMLObjectChildrenList<XMLObject> unknownChildren;
    
    /**
     * Constructor.
     *
     * @param namespaceURI the namespace the element is in
     * @param elementLocalName the local name of the XML element this Object represents
     * @param namespacePrefix the prefix for the given namespace
     */
    protected DigestMethodImpl(final String namespaceURI, final String elementLocalName, final String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
        
        unknownChildren = new IndexedXMLObjectChildrenList<>(this);
    }

    /** {@inheritDoc} */
    public String getAlgorithm() {
        return this.algorithm;
    }

    /** {@inheritDoc} */
    public void setAlgorithm(final String newAlgorithm) {
        this.algorithm = prepareForAssignment(this.algorithm, newAlgorithm);
    }

    /** {@inheritDoc} */
    public List<XMLObject> getUnknownXMLObjects() {
        return this.unknownChildren;
    }
    /** {@inheritDoc} */
    public List<XMLObject> getUnknownXMLObjects(final QName typeOrName) {
        return (List<XMLObject>) unknownChildren.subList(typeOrName);
    }

    /** {@inheritDoc} */
    public List<XMLObject> getOrderedChildren() {
        final ArrayList<XMLObject> children = new ArrayList<>();
        
        children.addAll(unknownChildren);
        
        if (children.size() == 0) {
            return null;
        }
        
        return Collections.unmodifiableList(children);
    }

}