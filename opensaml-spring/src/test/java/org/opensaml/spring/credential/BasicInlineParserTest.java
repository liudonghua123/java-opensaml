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

package org.opensaml.spring.credential;

import java.io.IOException;

import javax.crypto.SecretKey;

import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.spring.AbstractSecurityParserTest;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * test parsing Basic Inline Credentials
 */
@SuppressWarnings("javadoc")
public class BasicInlineParserTest extends AbstractSecurityParserTest {

    @Test public void publicOnly() throws IOException {
        final BasicCredential credential =
                (BasicCredential) getBean(Credential.class, "credential/inlinePublicOnly.xml");

        Assert.assertNull(credential.getPrivateKey());
    }
/*    
    @Test(expectedExceptions={BeanCreationException.class,}) public void wrongCert() throws IOException {
        getBean(Credential.class, true, "credential/inlineWrongCert.xml");
    }
  */  
    @Test public void publicPrivate() throws IOException {
        final BasicCredential credential =
                (BasicCredential) getBean(Credential.class, "credential/inlinePublicPrivate.xml");
        Assert.assertNotNull(credential.getPrivateKey());

    }
    
    @Test public void secretBase64() throws IOException {
        final BasicCredential credential =
                (BasicCredential) getBean(Credential.class, "credential/secretKeyAESBase64.xml");
        Assert.assertNotNull(credential.getSecretKey());
        SecretKey key = credential.getSecretKey();
        Assert.assertEquals(key.getAlgorithm(), "AES");
    }
    
    @Test public void secretHex() throws IOException {
        final BasicCredential credential =
                (BasicCredential) getBean(Credential.class, "credential/secretKeyAESHex.xml");
        Assert.assertNotNull(credential.getSecretKey());
        SecretKey key = credential.getSecretKey();
        Assert.assertEquals(key.getAlgorithm(), "AES");
    }
    
}