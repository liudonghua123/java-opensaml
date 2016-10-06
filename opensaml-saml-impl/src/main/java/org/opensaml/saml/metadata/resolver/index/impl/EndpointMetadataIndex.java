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

package org.opensaml.saml.metadata.resolver.index.impl;

import java.net.MalformedURLException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import org.opensaml.saml.metadata.resolver.index.MetadataIndex;
import org.opensaml.saml.metadata.resolver.index.MetadataIndexKey;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.MoreObjects;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.net.SimpleURLCanonicalizer;
import net.shibboleth.utilities.java.support.net.URLBuilder;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;

/**
 * An implementation of {@link MetadataIndex} which indexes entities by their role endpoint locations.
 * 
 * <p>
 * The indexed endpoint location keys are scoped by the containing {@link RoleDescriptor} type, {@link Endpoint} type,
 * and whether or not the endpoint value was a standard location ({@link Endpoint#getLocation()}) 
 * or a response location ({@link Endpoint#getResponseLocation()}).
 * </p>
 */
public class EndpointMetadataIndex implements MetadataIndex {
    
    /** Logger. */
    private Logger log = LoggerFactory.getLogger(EndpointMetadataIndex.class);
    
    /** The predicate which selects which endpoints to index. */
    private Predicate<Endpoint> endpointSelectionPredicate;
    
    /**
     * Constructor.
     * 
     * <p>
     * All entity descriptor endpoints will be indexed.
     * </p>
     */
    public EndpointMetadataIndex() {
        endpointSelectionPredicate = Predicates.alwaysTrue();
    }
    
    /**
     * Constructor.
     *
     * @param endpointPredicate the predicate which selects which endpoints to index
     */
    public EndpointMetadataIndex(Predicate<Endpoint> endpointPredicate) {
        endpointSelectionPredicate = Constraint.isNotNull(endpointPredicate, 
                "Endpoint selection predicate may not be null");
    }

    /** {@inheritDoc} */
    @Nullable @NonnullElements @Unmodifiable @NotLive
    public Set<MetadataIndexKey> generateKeys(@Nonnull EntityDescriptor descriptor) {
        Constraint.isNotNull(descriptor, "EntityDescriptor was null");
        HashSet<MetadataIndexKey> result = new HashSet<>();
        for (RoleDescriptor role : descriptor.getRoleDescriptors()) {
            QName roleType = role.getSchemaType();
            if (roleType == null) {
                roleType = role.getElementQName();
            }
            
            for (Endpoint endpoint : role.getEndpoints()) {
                QName endpointType = endpoint.getSchemaType();
                if (endpointType == null) {
                    endpointType = endpoint.getElementQName();
                }
                
                if (endpointSelectionPredicate.apply(endpoint)) {
                    String location = StringSupport.trimOrNull(endpoint.getLocation());
                    if (location != null) {
                        log.trace("Indexing Endpoint: role '{}', endpoint type '{}', location '{}'", 
                                roleType, endpointType, location);
                        result.add(new EndpointMetadataIndexKey(roleType, endpointType, location, false));
                    }
                    String responseLocation = StringSupport.trimOrNull(endpoint.getResponseLocation());
                    if (responseLocation != null) {
                        log.trace("Indexing response Endpoint - role '{}', endpoint type '{}', response location '{}'", 
                                roleType, endpointType, responseLocation);
                        result.add(new EndpointMetadataIndexKey(roleType, endpointType, responseLocation, true));
                    }
                }
            }
        }
        return result;
    }

    /** {@inheritDoc} */
    @Nullable @NonnullElements @Unmodifiable @NotLive
    public Set<MetadataIndexKey> generateKeys(@Nonnull CriteriaSet criteriaSet) {
        // TODO Auto-generated method stub
        return null;
    }
    
    /**
     * The default endpoint selection predicate, which evaluates an {@link Endpoint} using
     * a map of {@link QName} endpoint types, indexed by role type.
     */
    public static class DefaultEndpointSelectionPredicate implements Predicate<Endpoint> {
        
        /** The indexable endpoint types. */
        private Map<QName, Set<QName>> endpointTypes;
        
        /**
         * Constructor.
         */
        public DefaultEndpointSelectionPredicate() {
            endpointTypes = Collections.emptyMap();
        }
        
        /**
         * Constructor.
         *
         * @param indexableTypes a map controlling the types of endpoints to index
         */
        public DefaultEndpointSelectionPredicate(Map<QName, Set<QName>> indexableTypes) {
            endpointTypes = Constraint.isNotNull(indexableTypes, "Indexable endpoint types map was null");
        }

        /** {@inheritDoc} */
        public boolean apply(Endpoint endpoint) {
            if (endpoint == null) {
                return false;
            }
            
            RoleDescriptor role = (RoleDescriptor) endpoint.getParent();
            if (role == null) {
                return false;
            }
            
            QName roleType = role.getSchemaType();
            if (roleType == null) {
                roleType = role.getElementQName();
            }
            
            QName endpointType = endpoint.getSchemaType();
            if (endpointType == null) {
                endpointType = endpoint.getElementQName();
            }
            
            Set<QName> indexableEndpoints = endpointTypes.get(roleType);
            if (indexableEndpoints != null && indexableEndpoints.contains(endpointType)) {
                return true;
            }
            
            return false;
        }
        
    }
    
    /**
     * An implementation of {@link MetadataIndexKey} representing a single SAML metadata endpoint.
     */
    protected static class EndpointMetadataIndexKey implements MetadataIndexKey {
        
        /** Logger. */
        private final Logger log = LoggerFactory.getLogger(EndpointMetadataIndexKey.class);
        
        /** The role type. */
        @Nonnull private final QName role;
        
        /** The endpoint type. */
        @Nonnull private final QName endpoint;
        
        /** The location. */
        @Nonnull private final String location;
        
        /** Respone location flag. */
        private final boolean response;

        /** The canonicalized location. */
        @Nonnull private String canonicalizedLocation;
        
        /** Flag indicating whether canonicalized location is the simple lower case fallback strategy. */
        private boolean isCanonicalizedLowerCase;
        
        /**
         * Constructor.
         * 
         * @param roleType the role type
         * @param endpointType the endpoint type
         * @param endpointLocation the endpoint location
         * @param isResponse flag indicating whether location is a response or not
         */
        public EndpointMetadataIndexKey(@Nonnull final QName roleType, 
                @Nonnull final QName endpointType, 
                @Nonnull @NotEmpty final String endpointLocation,
                boolean isResponse) {
            role = Constraint.isNotNull(roleType, "SAML role cannot be null");
            endpoint = Constraint.isNotNull(endpointType, "SAML endpoint type cannot be null");
            location = Constraint.isNotNull(StringSupport.trimOrNull(endpointLocation),
                    "SAML role cannot be null or empty");
            response = isResponse;
            
            try {
                canonicalizedLocation = canonicalizeLocation(location);
            } catch (MalformedURLException e) {
                // This is unlikely to happen on realistic real world inputs. If it does, don't be fatal, 
                // just switch to alternate strategy.
                log.warn("Input location '{}' was a malformed URL, switching to lower case strategy", 
                        location, e);
                canonicalizedLocation = location.toLowerCase();
                isCanonicalizedLowerCase = true;
            }
        }

        /**
         * Gets the entity role.
         * 
         * @return the entity role
         */
        @Nonnull public QName getRoleType() {
            return role;
        }
        
        /**
         * Gets the entity endpoint type.
         * 
         * @return the endpoint type
         */
        @Nonnull public QName getEndpointType() {
            return endpoint;
        }

        /**
         * Gets the location.
         * 
         * @return the location
         */
        @Nonnull public String getLocation() {
            return location;
        }
        
        /**
         * Gets the response location flag.
         * 
         * @return true if endpoint is a response location, false otherwise
         */
        public boolean isResponse() {
            return response;
        }
        
        /**
         * Get the canonicalized representation of the location, primarily for use in
         * {@link #hashCode()} and {@link #equals(Object)}.
         * 
         * @return the canonicalized source location
         */
        @Nonnull public String getCanonicalizedLocation() {
            return canonicalizedLocation;
        }

        /** {@inheritDoc} */
        @Override
        public String toString() {
            return MoreObjects.toStringHelper(this)
                    .add("role", role)
                    .add("endpoint", endpoint)
                    .add("location", location)
                    .add("isResponse", response)
                    .add("canonicalizedLocation", canonicalizedLocation)
                    .add("isCanonicalizedLowerCase", isCanonicalizedLowerCase)
                    .toString();
        }

        /** {@inheritDoc} */
        @Override
        public int hashCode() {
            return Objects.hash(getRoleType(), getEndpointType(), getCanonicalizedLocation(), isResponse());
        }

        /** {@inheritDoc} */
        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }

            if (obj instanceof EndpointMetadataIndexKey) {
                EndpointMetadataIndexKey other = (EndpointMetadataIndexKey) obj;
                String thisLocation = this.canonicalizedLocation;
                String otherLocation = other.canonicalizedLocation;
                if (this.isCanonicalizedLowerCase != other.isCanonicalizedLowerCase) {
                    if (this.isCanonicalizedLowerCase) {
                        otherLocation = other.location.toLowerCase();
                    } else {
                        thisLocation = this.location.toLowerCase();
                    }
                }
                return this.role.equals(other.role) 
                        && this.endpoint.equals(other.endpoint) 
                        && thisLocation.equals(otherLocation) 
                        && this.response == other.response;
            }

            return false;
        }
        
        /**
         * Canonicalize the location to be indexed.
         * 
         * @param url the location
         * @return the canonicalized location value to index
         * @throws MalformedURLException if URL can not be canonicalized
         */
        private String canonicalizeLocation(String url) throws MalformedURLException {
            URLBuilder urlBuilder = new URLBuilder(url);
            urlBuilder.setUsername(null);
            urlBuilder.setPassword(null);
            urlBuilder.getQueryParams().clear();
            urlBuilder.setFragment(null);
            return SimpleURLCanonicalizer.canonicalize(urlBuilder.buildURL());
        }

    }

}
