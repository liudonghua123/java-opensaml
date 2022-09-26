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

package org.opensaml.xmlsec.impl;

import java.util.List;

import javax.annotation.Nonnull;

import net.shibboleth.shared.annotation.constraint.NonnullElements;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.NotLive;
import net.shibboleth.shared.annotation.constraint.Unmodifiable;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.resolver.Criterion;

import org.opensaml.xmlsec.AlgorithmPolicyConfiguration;

/**
 * Criterion which holds one or more instances of {@link AlgorithmPolicyConfiguration},
 * used exclusively for testing the {@link AbstractSecurityParametersResolver}.
 */
public class AlgorithmPolicyConfigurationCriterion implements Criterion {
    
    /** The list of configuration instances. */
    private List<AlgorithmPolicyConfiguration> configs;
    
    /**
     * Constructor.
     *
     * @param configurations list of configuration instances
     */
    public AlgorithmPolicyConfigurationCriterion(@Nonnull @NonnullElements @NotEmpty
            final List<AlgorithmPolicyConfiguration> configurations) {
        configs = List.copyOf(Constraint.isNotNull(configurations, "List of configurations may not be null"));
        Constraint.isNotEmpty(configs, "At least one configuration is required");
        
    }
    
    /**
     * Constructor.
     *
     * @param configurations varargs array of configuration instances
     */
    public AlgorithmPolicyConfigurationCriterion(@Nonnull @NonnullElements @NotEmpty
            final AlgorithmPolicyConfiguration... configurations) {
        configs = List.of(Constraint.isNotNull(configurations, "List of configurations may not be null"));
        Constraint.isNotEmpty(configs, "At least one configuration is required");
    }
    
    /**
     * Get the list of configuration instances.
     * @return the list of configuration instances
     */
    @Nonnull @NonnullElements @NotLive @Unmodifiable @NotEmpty
    public List<AlgorithmPolicyConfiguration> getConfigurations() {
        return configs;
    }
    
    /** {@inheritDoc} */
    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("WhitelistBlacklistConfigurationCriterion [configs=");
        builder.append(configs);
        builder.append("]");
        return builder.toString();
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        return configs.hashCode();
    }

    /** {@inheritDoc} */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null) {
            return false;
        }

        if (obj instanceof AlgorithmPolicyConfigurationCriterion) {
            return configs.equals(((AlgorithmPolicyConfigurationCriterion) obj).getConfigurations());
        }

        return false;
    }

}