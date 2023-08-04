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

package org.opensaml.saml.saml1.binding.decoding.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.BindingDescriptor;
import org.opensaml.saml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.saml.common.binding.impl.SAMLSOAPDecoderBodyHandler;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.slf4j.Logger;

import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.primitive.LoggerFactory;

/**
 * SAML 1.1 HTTP SOAP 1.1 binding decoder.
 */
public class HTTPSOAP11Decoder extends org.opensaml.soap.soap11.decoder.http.impl.HTTPSOAP11Decoder 
        implements SAMLMessageDecoder {
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(HTTPSOAP11Decoder.class);

    /** Optional {@link BindingDescriptor} to inject into {@link SAMLBindingContext} created. */
    @Nullable private BindingDescriptor bindingDescriptor;

    /**
     * Constructor.
     *
     */
    public HTTPSOAP11Decoder() {
        super();
        setProtocolMessageLoggerSubCategory("SAML");
    }

    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String getBindingURI() {
        return SAMLConstants.SAML1_SOAP11_BINDING_URI;
    }

    /**
     * Get an optional {@link BindingDescriptor} to inject into {@link SAMLBindingContext} created.
     * 
     * @return binding descriptor
     */
    @Nullable public BindingDescriptor getBindingDescriptor() {
        return bindingDescriptor;
    }
    
    /**
     * Set an optional {@link BindingDescriptor} to inject into {@link SAMLBindingContext} created.
     * 
     * @param descriptor a binding descriptor
     */
    public void setBindingDescriptor(@Nullable final BindingDescriptor descriptor) {
        bindingDescriptor = descriptor;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        
        // Need to set this before calling base class.
        if (getBodyHandler() == null) {
            final MessageHandler handler = new SAMLSOAPDecoderBodyHandler();
            handler.initialize();
            setBodyHandler(handler);
        }
        
        super.doInitialize();
    }
    
    /** {@inheritDoc} */
    protected void doDecode() throws MessageDecodingException {
        super.doDecode();
        
        final MessageContext msgCtx = getMessageContext();
        assert msgCtx != null;
        
        populateBindingContext(msgCtx);
        
        final Object samlMessage = msgCtx.getMessage();
        if (samlMessage instanceof SAMLObject) {
            log.debug("Decoded SOAP messaged which included SAML message of type {}",
                    ((SAMLObject) samlMessage).getElementQName());
        } else {
            throw new MessageDecodingException("Decoded message was not a SAMLObject");
        }
    }
    
    /**
     * Populate the context which carries information specific to this binding.
     * 
     * @param messageContext the current message context
     */
    protected void populateBindingContext(@Nonnull final MessageContext messageContext) {
        final SAMLBindingContext bindingContext = messageContext.ensureSubcontext(SAMLBindingContext.class);
        bindingContext.setBindingUri(getBindingURI());
        bindingContext.setBindingDescriptor(bindingDescriptor);
        bindingContext.setHasBindingSignature(false);
        bindingContext.setIntendedDestinationEndpointURIRequired(false);
    }

}