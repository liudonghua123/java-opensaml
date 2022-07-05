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

package org.opensaml.spring.trust;

import javax.xml.namespace.QName;

import org.opensaml.spring.SecurityNamespaceHandler;
import org.w3c.dom.Element;

/**
 * Parser for &lt;ValidationInfo type="PKIXInline"&gt;.
 * 
 * <p>
 * All of the heavy lifting is done in the super class and the associated factory bean (which gets the parameters of
 * the type is wants by virtue of Springs type coercion).
 * </p>
 */
public class PKIXInlineValidationInfoParser extends AbstractPKIXValidationInfoParser {
    
    /** Element Name.*/
    public static final QName SCHEMA_TYPE = new QName(SecurityNamespaceHandler.SECURITY_NAMESPACE, "PKIXInline");
    
    /** {@inheritDoc} */
    @Override protected Class<?> getBeanClass(final Element element) {
        return PKIXInlineValidationInfoFactoryBean.class;
    }
}
