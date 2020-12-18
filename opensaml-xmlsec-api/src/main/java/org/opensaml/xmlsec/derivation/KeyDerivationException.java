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

package org.opensaml.xmlsec.derivation;

import javax.annotation.Nullable;

/**
 * Exception thrown when an error occurs during key derivation operations.
 */
public class KeyDerivationException extends Exception {

    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = 1745203357584881658L;

    /**
     * Constructor.
     */
    public KeyDerivationException() {
        super();
    }

    /**
     * Constructor.
     *
     * @param message exception message
     */
    public KeyDerivationException(@Nullable final String message) {
        super(message);
    }
    
    /**
     * Constructor.
     * 
     * @param cause exception to be wrapped by this one
     */
    public KeyDerivationException(@Nullable final Throwable cause) {
        super(cause);
    }

    /**
     * Constructor.
     * 
     * @param message exception message
     * @param cause exception to be wrapped by this one
     */
    public KeyDerivationException(@Nullable final String message, @Nullable final Throwable cause) {
        super(message, cause);
    }

}