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

package org.opensaml.spring;

import javax.annotation.Nonnull;
import javax.xml.namespace.QName;

import org.opensaml.spring.credential.BasicInlineCredentialParser;
import org.opensaml.spring.credential.BasicResourceCredentialParser;
import org.opensaml.spring.credential.X509InlineCredentialParser;
import org.opensaml.spring.credential.X509ResourceCredentialParser;
import org.opensaml.spring.trust.CertPathPKIXValidationOptionsParser;
import org.opensaml.spring.trust.ChainingParser;
import org.opensaml.spring.trust.PKIXInlineValidationInfoParser;
import org.opensaml.spring.trust.PKIXResourceValidationInfoParser;
import org.opensaml.spring.trust.PKIXValidationOptionsParser;
import org.opensaml.spring.trust.SignatureChainingParser;
import org.opensaml.spring.trust.StaticExplicitKeyParser;
import org.opensaml.spring.trust.StaticExplicitKeySignatureParser;
import org.opensaml.spring.trust.StaticPKIXSignatureParser;
import org.opensaml.spring.trust.StaticPKIXX509CredentialParser;

import net.shibboleth.ext.spring.util.BaseSpringNamespaceHandler;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/** Namespace handler for {@link #SECURITY_NAMESPACE}. */
public class SecurityNamespaceHandler extends BaseSpringNamespaceHandler {

    /** Namespace for Security. */
    @Nonnull @NotEmpty public static final String SECURITY_NAMESPACE = "urn:mace:shibboleth:2.0:security";

    /** Credential element name. */
    @Nonnull public static final QName CREDENTIAL_ELEMENT_NAME = new QName(SECURITY_NAMESPACE, "Credential");

    /** TrustEngine Element name. */
    @Nonnull public static final QName TRUST_ENGINE_ELEMENT_NAME = new QName(SECURITY_NAMESPACE, "TrustEngine");

    /** TrustEngineRef element name. */
    @Nonnull public static final QName TRUST_ENGINE_REF = new QName(SECURITY_NAMESPACE, "TrustEngineRef");

    /** {@inheritDoc} */
    @Override public void init() {
        // Credentials
        registerBeanDefinitionParser(X509ResourceCredentialParser.TYPE_NAME_RESOURCE,
                new X509ResourceCredentialParser());
        registerBeanDefinitionParser(X509InlineCredentialParser.TYPE_NAME, new X509InlineCredentialParser());
        registerBeanDefinitionParser(BasicInlineCredentialParser.TYPE_NAME, new BasicInlineCredentialParser());
        registerBeanDefinitionParser(BasicResourceCredentialParser.TYPE_NAME_RESOURCE,
                new BasicResourceCredentialParser());

        registerBeanDefinitionParser(StaticExplicitKeySignatureParser.TYPE_NAME, 
                new StaticExplicitKeySignatureParser());
        registerBeanDefinitionParser(StaticPKIXSignatureParser.TYPE_NAME, new StaticPKIXSignatureParser());
        registerBeanDefinitionParser(SignatureChainingParser.TYPE_NAME, new SignatureChainingParser());

        // Validation Info
        registerBeanDefinitionParser(PKIXResourceValidationInfoParser.TYPE_NAME_RESOURCE,
                new PKIXResourceValidationInfoParser());
        registerBeanDefinitionParser(PKIXInlineValidationInfoParser.SCHEMA_TYPE, new PKIXInlineValidationInfoParser());

        // Validation Opts
        registerBeanDefinitionParser(PKIXValidationOptionsParser.ELEMENT_NAME, new PKIXValidationOptionsParser());
        registerBeanDefinitionParser(CertPathPKIXValidationOptionsParser.ELEMENT_NAME,
                new CertPathPKIXValidationOptionsParser());

        //
        // Trust Engines needed for the HttpMetadataProvider
        //
        registerBeanDefinitionParser(ChainingParser.TYPE_NAME, new ChainingParser());
        registerBeanDefinitionParser(StaticExplicitKeyParser.TYPE_NAME, new StaticExplicitKeyParser());
        registerBeanDefinitionParser(StaticPKIXX509CredentialParser.TYPE_NAME, new StaticPKIXX509CredentialParser());

    }
}