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

package org.opensaml.saml.metadata.resolver.impl;

import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.http.client.HttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;

/**
 * Simple implementation of an HTTP-based dynamic metadata resolver which builds the request URL
 * to process based on a {@link Function} instance.
 * 
 * <p>
 * The function defaults to an instance of {@link HTTPEntityIDRequestURLBuilder}, thereby implementing
 * the "well-known location" resolution mechanism defined in the SAML 2 metadata specification if the entity ID
 * is an HTTP or HTTPS URL.
 * </p>
 */
public class FunctionDrivenDynamicHTTPMetadataResolver extends AbstractDynamicHTTPMetadataResolver {
    
    /** Logger. */
    private final Logger log = LoggerFactory.getLogger(FunctionDrivenDynamicHTTPMetadataResolver.class);
    
    /** Function for building the request URL. */
    private Function<CriteriaSet, String> requestURLBuilder;

    /**
     * Constructor.
     *
     * @param client the instance of {@link HttpClient} used to fetch remote metadata
     */
    public FunctionDrivenDynamicHTTPMetadataResolver(final HttpClient client) {
        this(null, client);
    }
    
    /**
     * Constructor.
     *
     * @param backgroundTaskTimer the {@link Timer} instance used to run resolver background managment tasks
     * @param client the instance of {@link HttpClient} used to fetch remote metadata
     */
    public FunctionDrivenDynamicHTTPMetadataResolver(@Nullable final Timer backgroundTaskTimer,
                                                     @Nonnull final HttpClient client) {
        super(backgroundTaskTimer, client);
        setRequestURLBuilder(new HTTPEntityIDRequestURLBuilder());
    }

    /**
     * Get the function which builds the request URL.
     * 
     * <p>Defaults to an instance of {@link HTTPEntityIDRequestURLBuilder}.</p>
     * 
     * @return the request URL builder function instance
     */
    @Nonnull public Function<CriteriaSet, String> getRequestURLBuilder() {
        return requestURLBuilder;
    }

    /**
     * 
     * Set the function which builds the request URL.
     * 
     * <p>Defaults to an instance of {@link HTTPEntityIDRequestURLBuilder}.</p>
     * 
     * @param builder the request URL builder function instance
     */
    public void setRequestURLBuilder(@Nonnull final Function<CriteriaSet, String> builder) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);
        requestURLBuilder = Constraint.isNotNull(builder, "Request URL builder function was null");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable protected String buildRequestURL(@Nonnull final CriteriaSet criteria) {
        final String url = getRequestURLBuilder().apply(criteria);
        
        log.debug("{} URL generated by request builder was: {}", getLogPrefix(), url);
        
        return url;
    }

}
