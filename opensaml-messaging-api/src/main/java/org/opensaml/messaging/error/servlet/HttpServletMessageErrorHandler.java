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

package org.opensaml.messaging.error.servlet;

import java.util.function.Supplier;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.messaging.error.MessageErrorHandler;


/**
 * A specialization of message error handler for HTTP servlet container environments.
 */
public interface HttpServletMessageErrorHandler extends MessageErrorHandler {
    
    /**
     * Get the HTTP servlet request.
     * 
     * @return the HTTP servlet request
     */
    @Nullable HttpServletRequest getHttpServletRequest();
    
    /**
     * Set the HTTP servlet request.
     * 
     * @param request the HTTP servlet request
     */
    @Deprecated(forRemoval = true, since="4.3")
    void setHttpServletRequest(@Nullable final HttpServletRequest request);

    /**
     * Set the supplier for the HTTP servlet request on which to operate.
     *
     * @param requestSupplier the HTTP servlet request
     */
    default void setHttpServletRequestSupplier(@Nullable final Supplier<HttpServletRequest> requestSupplier) {
        setHttpServletRequest(requestSupplier.get());
    }

    /**
     * Get the HTTP servlet response.
     * 
     * @return the HTTP servlet response
     */
    @Nullable HttpServletResponse getHttpServletResponse();
    
    /**
     * Set the HTTP servlet response.
     * 
     * @param response the HTTP servlet response
     */
    @Deprecated(forRemoval = true, since="4.3")
    void setHttpServletResponse(@Nullable final HttpServletResponse response);

    /**
     * Set the supplier for the HTTP servlet response on which to operate.
     *
     * @param requestSupplier the HTTP servlet response
     */
    default void setHttpServletResponseSupplier(@Nullable final Supplier<HttpServletResponse> responseSupplier) {
        setHttpServletResponse(responseSupplier.get());
    }

}