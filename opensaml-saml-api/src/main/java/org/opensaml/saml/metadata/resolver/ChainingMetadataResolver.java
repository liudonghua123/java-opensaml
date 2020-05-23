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

package org.opensaml.saml.metadata.resolver;

import java.time.Instant;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A metadata provider that uses registered resolvers, in turn, to answer queries.
 * 
 * The Iterable of entity descriptors returned is the first non-null and non-empty Iterable found while iterating over
 * the registered resolvers in resolver list order.
 */
public class ChainingMetadataResolver extends AbstractIdentifiableInitializableComponent implements MetadataResolver,
        RefreshableMetadataResolver, ClearableMetadataResolver {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ChainingMetadataResolver.class);

    /** Registered resolvers. */
    @Nonnull @NonnullElements private List<MetadataResolver> resolvers;

    /** Constructor. */
    public ChainingMetadataResolver() {
        resolvers = Collections.emptyList();
    }

    /**
     * Get an immutable the list of currently registered resolvers.
     * 
     * @return list of currently registered resolvers
     */
    @Nonnull @NonnullElements @Unmodifiable @NotLive public List<MetadataResolver> getResolvers() {
        return resolvers;
    }

    /**
     * Set the registered metadata resolvers.
     * 
     * @param newResolvers the metadata resolvers to use
     * 
     * @throws ResolverException thrown if there is a problem adding the metadata resolvers
     */
    public void setResolvers(@Nonnull @NonnullElements final List<? extends MetadataResolver> newResolvers)
            throws ResolverException {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        if (newResolvers == null || newResolvers.isEmpty()) {
            resolvers = Collections.emptyList();
            return;
        }

        resolvers = List.copyOf(newResolvers);
    }

    /** {@inheritDoc} */
    @Override public boolean isRequireValidMetadata() {
        log.warn("Attempt to access unsupported requireValidMetadata property on ChainingMetadataResolver");
        return false;
    }

    /** {@inheritDoc} */
    @Override public void setRequireValidMetadata(final boolean requireValidMetadata) {
        throw new UnsupportedOperationException("Setting requireValidMetadata is not supported on chaining resolver");
    }

    /** {@inheritDoc} */
    @Override public MetadataFilter getMetadataFilter() {
        log.warn("Attempt to access unsupported MetadataFilter property on ChainingMetadataResolver");
        return null;
    }

    /** {@inheritDoc} */
    @Override public void setMetadataFilter(final MetadataFilter newFilter) {
        throw new UnsupportedOperationException("Metadata filters are not supported on ChainingMetadataResolver");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable public EntityDescriptor resolveSingle(@Nullable final CriteriaSet criteria) throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);

        final Iterable<EntityDescriptor> iterable = resolve(criteria);
        if (iterable != null) {
            final Iterator<EntityDescriptor> iterator = iterable.iterator();
            if (iterator != null && iterator.hasNext()) {
                return iterator.next();
            }
        }
        return null;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull public Iterable<EntityDescriptor> resolve(@Nullable final CriteriaSet criteria) throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);

        for (final MetadataResolver resolver : resolvers) {
            try {
                final Iterable<EntityDescriptor> descriptors = resolver.resolve(criteria);
                if (descriptors != null && descriptors.iterator().hasNext()) {
                    return descriptors;
                }
            } catch (final ResolverException e) {
                log.warn("Error retrieving metadata from resolver of type {}, proceeding to next resolver",
                        resolver.getClass().getName(), e);
                continue;
            }
        }

        return Collections.emptyList();
    }
    
    /** {@inheritDoc} */
    public void clear() throws ResolverException {
        for (final MetadataResolver resolver : resolvers) {
            if (resolver instanceof ClearableMetadataResolver) {
                ((ClearableMetadataResolver) resolver).clear();
            }
        }
    }

    /** {@inheritDoc} */
    public void clear(final String entityID) throws ResolverException {
        for (final MetadataResolver resolver : resolvers) {
            if (resolver instanceof ClearableMetadataResolver) {
                ((ClearableMetadataResolver) resolver).clear(entityID);
            }
        }
    }

    /** {@inheritDoc} */
    @Override public void refresh() throws ResolverException {
        for (final MetadataResolver resolver : resolvers) {
            if (resolver instanceof RefreshableMetadataResolver) {
                ((RefreshableMetadataResolver) resolver).refresh();
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    @Nullable public Instant getLastUpdate() {
        Instant ret = null;
        for (final MetadataResolver resolver : resolvers) {
            if (resolver instanceof RefreshableMetadataResolver) {
                final Instant lastUpdate = ((RefreshableMetadataResolver) resolver).getLastUpdate();
                if (ret == null || lastUpdate == null || ret.isBefore(lastUpdate)) {
                    ret = lastUpdate;
                }
            }
        }
        
        return ret;
    }

    /** {@inheritDoc} */
    @Override
    @Nullable public Instant getLastRefresh() {
        Instant ret = null;
        for (final MetadataResolver resolver : resolvers) {
            if (resolver instanceof RefreshableMetadataResolver) {
                final Instant lastRefresh = ((RefreshableMetadataResolver) resolver).getLastRefresh();
                if (ret == null || lastRefresh == null || ret.isBefore(lastRefresh)) {
                    ret = lastRefresh;
                }
            }
        }
        
        return ret;
    }
    
    /** {@inheritDoc} */
    public Instant getLastSuccessfulRefresh() {
        Instant ret = null;
        for (final MetadataResolver resolver : resolvers) {
            if (resolver instanceof RefreshableMetadataResolver) {
                final Instant lastSuccessRefresh = ((RefreshableMetadataResolver) resolver).getLastSuccessfulRefresh();
                if (ret == null || lastSuccessRefresh == null || ret.isBefore(lastSuccessRefresh)) {
                    ret = lastSuccessRefresh;
                }
            }
        }
        
        return ret;
    }

    /** {@inheritDoc} */
    public Boolean wasLastRefreshSuccess() {
        for (final MetadataResolver resolver : resolvers) {
            if (resolver instanceof RefreshableMetadataResolver) {
                final RefreshableMetadataResolver refreshable = (RefreshableMetadataResolver) resolver;
                if (refreshable.wasLastRefreshSuccess() != null && !refreshable.wasLastRefreshSuccess()) {
                    return false;
                }
            }
        }
        
        return true;
    }
    
    /** {@inheritDoc} */
    public Throwable getLastFailureCause() {
        for (final MetadataResolver resolver : resolvers) {
            if (resolver instanceof RefreshableMetadataResolver) {
                final RefreshableMetadataResolver refreshable = (RefreshableMetadataResolver) resolver;
                if (refreshable.getLastFailureCause() != null) {
                    return refreshable.getLastFailureCause();
                }
            }
        }

        return null;
    }

    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (resolvers == null) {
            log.warn("ChainingMetadataResolver was not configured with any member MetadataResolvers");
            resolvers = Collections.emptyList();
        }
    }

    /** {@inheritDoc} */
    @Override protected void doDestroy() {
        super.doDestroy();
        resolvers = Collections.emptyList();
    }

}