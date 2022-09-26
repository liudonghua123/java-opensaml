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

package org.opensaml.messaging.encoder.httpclient;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import net.shibboleth.shared.xml.SerializeSupport;

/**
 * Base class for message encoders which encode XML messages to HttpRequest.
 */
public abstract class BaseHttpClientRequestXMLMessageEncoder  extends AbstractHttpClientRequestMessageEncoder {
    
    /** Used to log protocol messages. */
    @Nonnull private Logger protocolMessageLog = LoggerFactory.getLogger("PROTOCOL_MESSAGE");

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(BaseHttpClientRequestXMLMessageEncoder.class);

    /** {@inheritDoc} */
    public void encode() throws MessageEncodingException {
        if (log.isDebugEnabled() && getMessageContext().getMessage() != null) {
            log.debug("Beginning encode of message of type: {}", getMessageContext().getMessage().getClass().getName());
        }

        super.encode();

        logEncodedMessage();
        
        log.debug("Successfully encoded message.");
    }

    /**
     * Log the encoded message to the protocol message logger.
     */
    protected void logEncodedMessage() {
        if (protocolMessageLog.isDebugEnabled() ){
            final Object message = getMessageToLog();
            if (message == null || !(message instanceof XMLObject)) {
                log.warn("Encoded message was null or unsupported, nothing to log");
                return;
            }
            
            try {
                final Element dom = XMLObjectSupport.marshall((XMLObject) message);
                protocolMessageLog.debug("\n" + SerializeSupport.prettyPrintXML(dom));
            } catch (final MarshallingException e) {
                log.error("Unable to marshall message for logging purposes", e);
            }
        }
    }
    
    /**
     * Get the XMLObject which will be logged as the protocol message.
     * 
     * @return the XMLObject message considered to be the protocol message for logging purposes
     */
    @Nullable protected Object getMessageToLog() {
        return getMessageContext().getMessage();
    }

    /**
     * Helper method that marshalls the given message.
     * 
     * @param message message the marshall and serialize
     * 
     * @return marshalled message
     * 
     * @throws MessageEncodingException thrown if the give message can not be marshalled into its DOM representation
     */
    @Nonnull protected Element marshallMessage(@Nonnull final XMLObject message) throws MessageEncodingException {
        log.debug("Marshalling message");
        
        try {
            return XMLObjectSupport.marshall(message);
        } catch (final MarshallingException e) {
            log.error("Error marshalling message: {}", e.getMessage());
            throw new MessageEncodingException("Error marshalling message", e);
        }
    }

}
