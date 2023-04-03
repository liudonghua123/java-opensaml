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

package org.opensaml.saml.saml2.metadata.impl;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.AttributeMap;
import org.opensaml.core.xml.util.XMLObjectChildrenList;
import org.opensaml.saml.common.AbstractSignableSAMLObject;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.AffiliateMember;
import org.opensaml.saml.saml2.metadata.AffiliationDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;

import net.shibboleth.shared.collection.CollectionSupport;

/**
 * Concrete implementation of {@link org.opensaml.saml.saml2.metadata.AffiliationDescriptor}.
 */
public class AffiliationDescriptorImpl extends AbstractSignableSAMLObject implements AffiliationDescriptor {

    /** ID of the owner of this affiliation. */
    private String ownerID;
    
    /** ID attribute. */
    private String id;

    /** validUntil attribute. */
    private Instant validUntil;

    /** cacheDurection attribute. */
    private Duration cacheDuration;

    /** Extensions child. */
    private Extensions extensions;
    
    /** "anyAttribute" attributes. */
    private final AttributeMap unknownAttributes;

    /** Members of this affiliation. */
    private final XMLObjectChildrenList<AffiliateMember> members;

    /** Key descriptors for this role. */
    private final XMLObjectChildrenList<KeyDescriptor> keyDescriptors;

    /**
     * Constructor.
     * 
     * @param namespaceURI namespace
     * @param elementLocalName localname
     * @param namespacePrefix prefix
     */
    protected AffiliationDescriptorImpl(final String namespaceURI, final String elementLocalName,
            final String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
        unknownAttributes = new AttributeMap(this);
        members = new XMLObjectChildrenList<>(this);
        keyDescriptors = new XMLObjectChildrenList<>(this);
    }

    /** {@inheritDoc} */
    public String getOwnerID() {
        return ownerID;
    }

    /** {@inheritDoc} */
    public void setOwnerID(final String newOwnerID) {
        if (newOwnerID != null && newOwnerID.length() > 1024) {
            throw new IllegalArgumentException("Owner ID can not exceed 1024 characters in length");
        }
        ownerID = prepareForAssignment(ownerID, newOwnerID);
    }
    
    /** {@inheritDoc} */
    public String getID() {
        return id;
    }
    
    /** {@inheritDoc} */
    public void setID(final String newID) {
        final String oldID = id;
        this.id = prepareForAssignment(id, newID);
        registerOwnID(oldID, id);
    }

    /** {@inheritDoc} */
    public boolean isValid() {
        if (null == validUntil) {
            return true;
        }

        return Instant.now().isBefore(validUntil);
    }

    /** {@inheritDoc} */
    public Instant getValidUntil() {
        return validUntil;
    }

    /** {@inheritDoc} */
    public void setValidUntil(final Instant theValidUntil) {
        validUntil = prepareForAssignment(validUntil, theValidUntil);
    }

    /** {@inheritDoc} */
    public Duration getCacheDuration() {
        return cacheDuration;
    }

    /** {@inheritDoc} */
    public void setCacheDuration(final Duration duration) {
        cacheDuration = prepareForAssignment(cacheDuration, duration);
    }

    /** {@inheritDoc} */
    public Extensions getExtensions() {
        return extensions;
    }

    /** {@inheritDoc} */
    public void setExtensions(final Extensions theExtensions) {
        extensions = prepareForAssignment(extensions, theExtensions);
    }

    /** {@inheritDoc} */
    public List<AffiliateMember> getMembers() {
        return members;
    }

    /** {@inheritDoc} */
    public List<KeyDescriptor> getKeyDescriptors() {
        return keyDescriptors;
    }
    
    /** {@inheritDoc} */
    public AttributeMap getUnknownAttributes() {
        return unknownAttributes;
    }
    
    /** {@inheritDoc} */
    @Override
    public String getSignatureReferenceID(){
        return id;
    }

    /** {@inheritDoc} */
    @Override
    public List<XMLObject> getOrderedChildren() {
        final ArrayList<XMLObject> children = new ArrayList<>();

        if(getSignature() != null){
            children.add(getSignature());
        }
        
        if (getExtensions() != null) {
            children.add(getExtensions());
        }

        children.addAll(getMembers());

        children.addAll(getKeyDescriptors());

        return CollectionSupport.copyToList(children);
    }

}