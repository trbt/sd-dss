/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.digidoc4j.dss.xades;


import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.XPathQueryHolder;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.xades.signature.XAdESLevelLTTest;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.apache.commons.lang.StringUtils;
import org.junit.Test;
import org.w3c.dom.Element;

import java.io.IOException;
import java.util.List;

import static eu.europa.esig.dss.DigestAlgorithm.SHA256;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class BDocXadesTest extends XAdESLevelLTTest {

    private static final String TM_POLICY = "urn:oid:1.3.6.1.4.1.10015.1000.3.2.1";
    private static final String OIDAS_URN = "OIDAsURN";

    @Test
    public void bdocTM_shouldNotContainTimestamp() throws Exception {
        XAdESSignature xAdESSignature = createXadesSignatureForBdocTm();
        assertTrue(isTimestampEmpty(xAdESSignature));
        SignatureLevel signatureLevel = xAdESSignature.getDataFoundUpToLevel();
        //TODO
        //assertEquals(SignatureLevel.XAdES_BASELINE_LT, signatureLevel);
    }

    @Test
    public void bdocTM_shouldContainPolicyId() throws Exception {
        XAdESSignature xAdESSignature = createXadesSignatureForBdocTm();
        SignaturePolicy policy = xAdESSignature.getPolicyId();
        String policyIdentifier = policy.getIdentifier().trim();
        assertEquals(TM_POLICY, policyIdentifier);
        assertTrue(StringUtils.isNotBlank(policy.getUrl()));
    }

    @Test
    public void bdocTM_shoudlContainPolicyQualifier() throws Exception {
        XAdESSignature xAdESSignature = createXadesSignatureForBdocTm();
        String qualifier = getSignaturePolicyQualifier(xAdESSignature);
        assertEquals(OIDAS_URN, qualifier);
    }

    @Test
    public void setSignatureId_whenCreatingXadesSignature() throws Exception {
        getSignatureParameters().setDeterministicId("SIGNATURE-1");
        XAdESSignature signature = createXadesSignatureForBdocTm();
        assertEquals("SIGNATURE-1", signature.getId());
    }

    private XAdESSignature createXadesSignatureForBdocTm() {
        addSignaturePolicy();
        DSSDocument signedDocument = sign();
        return extractXadesSignature(signedDocument);
    }

    private XAdESSignature extractXadesSignature(DSSDocument signedDocument) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        List<AdvancedSignature> signatureList = validator.getSignatures();
        return (XAdESSignature)signatureList.get(0);
    }

    private void addSignaturePolicy() {
        Policy signaturePolicy = new Policy();
        signaturePolicy.setId(TM_POLICY);
        signaturePolicy.setDigestValue(decodeBase64("3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs="));
        signaturePolicy.setDigestAlgorithm(SHA256);
        signaturePolicy.setSpuri("https://www.sk.ee/repository/bdoc-spec21.pdf");
        getSignatureParameters().bLevel().setSignaturePolicy(signaturePolicy);
    }

    private boolean isTimestampEmpty(XAdESSignature xAdESSignature) {
        List<TimestampToken> signatureTimestamps = xAdESSignature.getSignatureTimestamps();
        return signatureTimestamps == null || signatureTimestamps.size() == 0;
    }

    private String getSignaturePolicyQualifier(XAdESSignature xAdESSignature) {
        XPathQueryHolder xPathQueryHolder = xAdESSignature.getXPathQueryHolder();
        Element signatureElement = xAdESSignature.getSignatureElement();
        Element element = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_POLICY_IDENTIFIER);
        Element identifier = DSSXMLUtils.getElement(element, "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Identifier");
        return identifier.getAttribute("Qualifier");
    }

    @Override
    public void signAndVerify() throws IOException {
        //Skip the test
    }
}
