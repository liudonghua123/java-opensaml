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

package org.opensaml.saml.security.impl;

import java.security.Key;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.impl.BasicEncryptionParametersResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicate;

/**
 * A specialization of {@link BasicEncryptionParametersResolver} which resolves
 * credentials and algorithm preferences against SAML metadata via a {@link MetadataCredentialResolver}.
 * 
 * <p>
 * In addition to the {@link net.shibboleth.utilities.java.support.resolver.Criterion} inputs documented in 
 * {@link BasicEncryptionParametersResolver}, the following inputs are also supported:
 * <ul>
 * <li>{@link org.opensaml.core.criterion.EntityIdCriterion} - required</li> 
 * <li>{@link org.opensaml.core.criterion.EntityRoleCriterion} - required</li> 
 * <li>{@link org.opensaml.core.criterion.ProtocolCriterion} - optional</li> 
 * <li>{@link org.opensaml.security.criteria.UsageCriterion} - optional</li> 
 * </ul>
 * </p>
 */
public class SAMLMetadataEncryptionParametersResolver extends BasicEncryptionParametersResolver {
    
    /** Logger. */
    private Logger log = LoggerFactory.getLogger(SAMLMetadataEncryptionParametersResolver.class);
    
    /** Metadata credential resolver. */
    private MetadataCredentialResolver credentialResolver;
    
    /**
     * Constructor.
     *
     * @param resolver the metadata credential resolver instance to use to resolve encryption credentials
     */
    public SAMLMetadataEncryptionParametersResolver(@Nonnull final MetadataCredentialResolver resolver) {
        credentialResolver = Constraint.isNotNull(resolver, "MetadataCredentialResoler may not be null");
    }
    
    /**
     * Get the metadata credential resolver instance to use to resolve encryption credentials.
     * 
     * @return the configured metadata credential resolver instance
     */
    @Nonnull protected MetadataCredentialResolver getMetadataCredentialResolver() {
        return credentialResolver;
    }

    /** {@inheritDoc} */
    protected void resolveAndPopulateCredentialsAndAlgorithms(@Nonnull final EncryptionParameters params,
            @Nonnull final CriteriaSet criteria, @Nonnull final Predicate<String> whitelistBlacklistPredicate) {
        
        // Note: Here we assume that we will only ever resolve a key transport credential from metadata.
        // Even if it's a symmetric key credential (via a key agreement protocol, or resolved from a KeyName, etc),
        // it ought to be used for symmetric key wrap, not direct data encryption.
        try {
            for (Credential keyTransportCredential : getMetadataCredentialResolver().resolve(criteria)) {
                SAMLMDCredentialContext metadataCredContext = 
                        keyTransportCredential.getCredentialContextSet().get(SAMLMDCredentialContext.class);
                
                String keyTransportAlgorithm = resolveKeyTransportAlgorithm(keyTransportCredential,
                        criteria, whitelistBlacklistPredicate, metadataCredContext);
                if (keyTransportAlgorithm == null) {
                    log.debug("Unable to resolve key transport algorithm for credential with key type '{}', " 
                            + "considering other credentials", 
                            CredentialSupport.extractEncryptionKey(keyTransportCredential));
                    continue;
                }
                
                String dataEncryptionAlgorithm = resolveDataEncryptionAlgorithmByKeyTransportCredential(
                        keyTransportCredential, keyTransportAlgorithm, criteria, whitelistBlacklistPredicate, 
                        metadataCredContext);
                if (dataEncryptionAlgorithm == null) {
                    log.debug("Unable to resolve data encryption algorithm URI for use with key transport key " 
                            + "'{}' and algorithm '{}', encryption will use internal defaults", 
                            CredentialSupport.extractEncryptionKey(keyTransportCredential), keyTransportAlgorithm);
                }
                
                params.setKeyTransportEncryptionCredential(keyTransportCredential);
                params.setKeyTransportEncryptionAlgorithmURI(keyTransportAlgorithm);
                params.setDataEncryptionAlgorithmURI(dataEncryptionAlgorithm);
                if (isAutoGenerateDataEncryptionCredential() && dataEncryptionAlgorithm != null) {
                    params.setDataEncryptionCredential(generateDataEncryptionCredential(dataEncryptionAlgorithm));
                }
                return;
                
            }
        } catch (ResolverException e) {
            log.warn("Problem resolving credentials from metadata, falling back to local configuration", e);
        }
        
        log.debug("Could not resolve encryption parameters based on SAML metadata, " 
                + "falling back to locally configured credentials and algorithms");
        
        super.resolveAndPopulateCredentialsAndAlgorithms(params, criteria, whitelistBlacklistPredicate);
    }

    /**
     * Determine the key transport algorithm URI to use with the specified credential.
     * 
     * @param keyTransportCredential the key transport credential to evaluate
     * @param criteria  the criteria instance being evaluated
     * @param whitelistBlacklistPredicate the whitelist/blacklist predicate with which to evaluate the 
     *          candidate data encryption and key transport algorithm URIs
     * @param metadataCredContext the credential context extracted from metadata
     * @return the selected algorithm URI
     */
    @Nullable protected String resolveKeyTransportAlgorithm(@Nonnull final Credential keyTransportCredential, 
            @Nonnull final CriteriaSet criteria, @Nonnull final Predicate<String> whitelistBlacklistPredicate,
            @Nullable final SAMLMDCredentialContext metadataCredContext) {
        
        if (metadataCredContext != null) {
            for (EncryptionMethod encryptionMethod : metadataCredContext.getEncryptionMethods()) {
                String algorithm = encryptionMethod.getAlgorithm();
                if (isKeyTransportAlgorithm(algorithm) && whitelistBlacklistPredicate.apply(algorithm) 
                        && credentialSupportsEncryptionMethod(keyTransportCredential, encryptionMethod)) {
                    return algorithm;
                }
            }
        }
        
        log.debug("Could not key transport algorithm based on SAML metadata, " 
                + "falling back to locally configured algorithms");
        
        return super.resolveKeyTransportAlgorithm(keyTransportCredential, criteria, whitelistBlacklistPredicate);
    }

    /**
     * Determine the data encryption algorithm URI to use with the specified key transport credential.
     * 
     * <p>
     * Note that the selection here is based on the <b>key transport</b> encryption credential, 
     * not the data encryption credential.  It is a candidate key transport credential that is passed
     * to this method.
     * </p>
     * 
     * @param keyTransportCredential the key transport credential to evaluate
     * @param keyTransportAlgorithm the key transport algorithm to evaluate
     * @param criteria  the criteria instance being evaluated
     * @param whitelistBlacklistPredicate the whitelist/blacklist predicate with which to evaluate the 
     *          candidate data encryption and key transport algorithm URIs
     * @param metadataCredContext the credential context extracted from metadata
     * @return the selected algorithm URI
     */
    @Nullable protected String resolveDataEncryptionAlgorithmByKeyTransportCredential(
            @Nonnull final Credential keyTransportCredential, @Nonnull final String keyTransportAlgorithm,
            @Nonnull final CriteriaSet criteria, @Nonnull final Predicate<String> whitelistBlacklistPredicate,
            @Nullable final SAMLMDCredentialContext metadataCredContext) {
        
        if (metadataCredContext != null) {
            for (EncryptionMethod encryptionMethod : metadataCredContext.getEncryptionMethods()) {
                String algorithm = encryptionMethod.getAlgorithm();
                if (isDataEncryptionAlgorithm(algorithm) && whitelistBlacklistPredicate.apply(algorithm)) {
                    return algorithm;
                }
            }
        }
        
        log.debug("Could not resolve data encryption algorithm based on SAML metadata, " 
                + "falling back to locally configured algorithms");
        
        return super.resolveDataEncryptionAlgorithmByKeyTransportCredential(keyTransportCredential, 
                keyTransportAlgorithm, criteria, whitelistBlacklistPredicate);
    }

    /**
     * Evaluate whether the specified credential is supported for use with the specified {@link EncryptionMethod}.
     * 
     * @param credential the credential to evaluate
     * @param encryptionMethod the encryption method to evaluate
     * @return true if credential may be used with the supplied encryption method, false otherwise
     */
    protected boolean credentialSupportsEncryptionMethod(@Nonnull final Credential credential, 
            @Nonnull @NotEmpty final EncryptionMethod encryptionMethod) {
        if (!credentialSupportsAlgorithm(credential, encryptionMethod.getAlgorithm())) {
            return false;
        }
        
        if (encryptionMethod.getKeySize() != null && encryptionMethod.getKeySize().getValue() != null) {
            Key encryptionKey = CredentialSupport.extractEncryptionKey(credential);
            if (encryptionKey == null) {
                log.warn("Could not extract encryption key from credential. Failing evaluation");
                return false;
            }
            
            Integer keyLength = KeySupport.getKeyLength(encryptionKey);
            if (keyLength == null) {
                log.warn("Could not determine key length of candidate encryption credential. Failing evaluation");
                return false;
            }
        
            if (! keyLength.equals(encryptionMethod.getKeySize().getValue())) {
                return false;
            }
        }
        
        //TODO anything else?  OAEPParams?
        
        return true;
    }

}