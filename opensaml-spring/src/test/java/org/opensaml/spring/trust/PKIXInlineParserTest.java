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

import java.io.IOException;

import org.opensaml.spring.AbstractSecurityParserTest;

import org.opensaml.security.x509.PKIXValidationInformation;
import org.opensaml.security.x509.impl.BasicPKIXValidationInformation;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * test for parsing of inline ValidationInfo
 */
@SuppressWarnings("javadoc")
public class PKIXInlineParserTest extends AbstractSecurityParserTest {

    private BasicPKIXValidationInformation lookup(String file) throws IOException {
        return (BasicPKIXValidationInformation) getBean(PKIXValidationInformation.class, "trust/" + file);
    }

    @Test public void simple() throws IOException {
        final BasicPKIXValidationInformation info = lookup("inlineValidationInfo.xml");
        Assert.assertNull(info.getVerificationDepth());
        Assert.assertTrue(info.getCertificates().isEmpty());
        Assert.assertTrue(info.getCRLs().isEmpty());
    }

    @Test(enabled=true) public void complex() throws IOException {
        final BasicPKIXValidationInformation info = lookup("inlineValidationInfoValues.xml");
        Assert.assertEquals(info.getVerificationDepth().intValue(), 98);
        Assert.assertEquals(info.getCertificates().size(), 2);
        Assert.assertEquals(info.getCRLs().size(), 1);
    }

}
