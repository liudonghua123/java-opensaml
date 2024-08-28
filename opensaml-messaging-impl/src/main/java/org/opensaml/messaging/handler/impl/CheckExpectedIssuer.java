/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.messaging.handler.impl;

import java.util.Objects;
import java.util.function.Function;

import javax.annotation.Nonnull;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.AbstractMessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.slf4j.Logger;

import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;

/**
 * Message handler that checks that a message context's issuer matches an expected value,
 * both supplied by a lookup function.
 */
public final class CheckExpectedIssuer extends AbstractMessageHandler {
    
    /** Logger. */
    @Nonnull private Logger log = LoggerFactory.getLogger(CheckExpectedIssuer.class);

    /** Strategy used to look up the issuer associated with the message context. */
    @NonnullAfterInit private Function<MessageContext,String> issuerLookupStrategy;
    
    /** Strategy used to look up the expected issuer associated with the message context. */
    @NonnullAfterInit private Function<MessageContext,String> expectedIssuerLookupStrategy;
    
    /**
     * Set the strategy used to look up the issuer associated with the message context.
     * 
     * @param strategy lookup strategy
     */
    public void setIssuerLookupStrategy(@Nonnull final Function<MessageContext,String> strategy) {
        checkSetterPreconditions();

        issuerLookupStrategy = Constraint.isNotNull(strategy, "Message context issuer lookup strategy cannot be null");
    }
    
    /**
     * Set the strategy used to look up the expected issuer associated with the message context.
     * 
     * @param strategy lookup strategy
     */
    public void setExpectedIssuerLookupStrategy(@Nonnull final Function<MessageContext,String> strategy) {
        checkSetterPreconditions();

        expectedIssuerLookupStrategy = Constraint.isNotNull(strategy, 
                "Message context expected issuer lookup strategy cannot be null");
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        
        if (issuerLookupStrategy == null) {
            throw new ComponentInitializationException(
                    "Message context issuer lookup strategy cannot be null");
        }
        if (expectedIssuerLookupStrategy == null) {
            throw new ComponentInitializationException(
                    "Message context expected issuer lookup strategy cannot be null");
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void doInvoke(@Nonnull final MessageContext messageContext) throws MessageHandlerException {
        final String issuer = issuerLookupStrategy.apply(messageContext);
        if (issuer == null) {
            throw new MessageHandlerException("Message context did not contain an issuer");
        }
        
        final String expectedIssuer = expectedIssuerLookupStrategy.apply(messageContext);
        if (expectedIssuer == null) {
            throw new MessageHandlerException("Message context did not contain an expected issuer");
        }
        
        log.debug("Saw issuer '{}', expected issuer '{}'", issuer, expectedIssuer);
        
        if (!Objects.equals(issuer, expectedIssuer)) {
            throw new MessageHandlerException("Message context issuer did not match expected issuer");
        }
    }
    
}