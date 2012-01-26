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

package org.opensaml.saml.criterion;

import net.shibboleth.utilities.java.support.logic.Assert;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.resolver.Criterion;

/** {@link Criterion} representing a SAML binding location. */
public final class BindingLocation implements Criterion {

    /** The binding location URI. */
    private final String location;

    /**
     * Constructor.
     * 
     * @param locationUri the binding location URI, never null or empty
     */
    public BindingLocation(String locationUri) {
        location = Assert.isNotNull(StringSupport.trimOrNull(locationUri), "Location can not be null or empty");
    }

    /**
     * Gets the binding location URI.
     * 
     * @return the binding location URI, never null or empty
     */
    public String getLocation() {
        return location;
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("BindingLocation [location=");
        builder.append(location);
        builder.append("]");
        return builder.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return location.hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null) {
            return false;
        }

        if (obj instanceof BindingLocation) {
            return location.equals(((BindingLocation) obj).location);
        }

        return false;
    }
}