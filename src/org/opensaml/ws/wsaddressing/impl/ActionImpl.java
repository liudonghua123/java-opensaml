/*
 * Copyright 2008 Members of the EGEE Collaboration.
 * Copyright 2008 University Corporation for Advanced Internet Development, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.ws.wsaddressing.impl;

import org.opensaml.ws.wsaddressing.Action;
import org.opensaml.xml.schema.impl.XSURIImpl;

/**
 * ActionImpl is the concrete implementation of {@link Action}.
 * 
 * @author Valery Tschopp <tschopp@switch.ch>
 * @version $Revision$
 */
public class ActionImpl extends XSURIImpl implements Action {

    /**
     * Constructor.
     * 
     * @param namespaceURI The namespace of the element
     * @param elementLocalName The local name of the element
     * @param namespacePrefix The namespace prefix of the element
     */
    public ActionImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

}
