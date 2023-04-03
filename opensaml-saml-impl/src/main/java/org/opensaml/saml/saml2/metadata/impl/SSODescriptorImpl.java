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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.XMLObjectChildrenList;
import org.opensaml.saml.metadata.support.SAML2MetadataSupport;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.ManageNameIDService;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;

import net.shibboleth.shared.collection.CollectionSupport;

/**
 * Concrete implementation of {@link org.opensaml.saml.saml2.metadata.SSODescriptor}.
 */
public abstract class SSODescriptorImpl extends RoleDescriptorImpl implements SSODescriptor {

    /** Supported artifact resolutions services. */
    private final XMLObjectChildrenList<ArtifactResolutionService> artifactResolutionServices;

    /** Logout services for this SSO entity. */
    private final XMLObjectChildrenList<SingleLogoutService> singleLogoutServices;

    /** Manage NameID services for this entity. */
    private final XMLObjectChildrenList<ManageNameIDService> manageNameIDServices;

    /** NameID formats supported by this entity. */
    private final XMLObjectChildrenList<NameIDFormat> nameIDFormats;
    
    /**
     * Constructor.
     * 
     * @param namespaceURI the namespace the element is in
     * @param elementLocalName the local name of the XML element this Object represents
     * @param namespacePrefix the prefix for the given namespace
     */
    protected SSODescriptorImpl(final String namespaceURI, final String elementLocalName,
            final String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
        artifactResolutionServices = new XMLObjectChildrenList<>(this);
        singleLogoutServices = new XMLObjectChildrenList<>(this);
        manageNameIDServices = new XMLObjectChildrenList<>(this);
        nameIDFormats = new XMLObjectChildrenList<>(this);
    }

    /** {@inheritDoc} */
    public List<ArtifactResolutionService> getArtifactResolutionServices() {
        return artifactResolutionServices;
    }
    
    /** {@inheritDoc} */
    public ArtifactResolutionService getDefaultArtifactResolutionService(){
        return SAML2MetadataSupport.getDefaultIndexedEndpoint(artifactResolutionServices);
    }
    
    /** {@inheritDoc} */
    public List<SingleLogoutService> getSingleLogoutServices() {
        return singleLogoutServices;
    }

    /** {@inheritDoc} */
    public List<ManageNameIDService> getManageNameIDServices() {
        return manageNameIDServices;
    }

    /** {@inheritDoc} */
    public List<NameIDFormat> getNameIDFormats() {
        return nameIDFormats;
    }
    
    /** {@inheritDoc} */
    public List<Endpoint> getEndpoints() {
        final List<Endpoint> endpoints = new ArrayList<>();
        endpoints.addAll(artifactResolutionServices);
        endpoints.addAll(singleLogoutServices);
        endpoints.addAll(manageNameIDServices);
        return Collections.unmodifiableList(endpoints);
    }
    
    /** {@inheritDoc} */
    public List<Endpoint> getEndpoints(final QName type) {
        if(type.equals(ArtifactResolutionService.DEFAULT_ELEMENT_NAME)){
            return Collections.unmodifiableList(new ArrayList<Endpoint>(artifactResolutionServices));
        }else if(type.equals(SingleLogoutService.DEFAULT_ELEMENT_NAME)){
            return Collections.unmodifiableList(new ArrayList<Endpoint>(singleLogoutServices));
        }else if(type.equals(ManageNameIDService.DEFAULT_ELEMENT_NAME)){
            return Collections.unmodifiableList(new ArrayList<Endpoint>(manageNameIDServices));
        }
        
        return CollectionSupport.emptyList();
    }
    
    /** {@inheritDoc} */
    public List<XMLObject> getOrderedChildren() {
        final ArrayList<XMLObject> children = new ArrayList<>();
        
        final List<XMLObject> parentChildren = super.getOrderedChildren();
        if (parentChildren != null) {
            children.addAll(parentChildren);
        }
        children.addAll(artifactResolutionServices);
        children.addAll(singleLogoutServices);
        children.addAll(manageNameIDServices);
        children.addAll(nameIDFormats);
        
        return CollectionSupport.copyToList(children);
    }
}