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
package org.digidoc4j.dss.asic;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.XPathQueryHolder;
import eu.europa.esig.dss.asic.signature.asice.ASiCELevelLTTest;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.IOException;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class BDocTest extends ASiCELevelLTTest {

    private DSSDocument documentToSign;

    @Before
    public void setUp() throws Exception {
        documentToSign = new InMemoryDocument("Hello Wolrd !".getBytes(), "test.text");
    }

    @Test
    public void bdocShouldContainManifest() throws Exception {
        documentToSign = sign();
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToSign);
        Assert.assertTrue("BDoc does not contain META-INF/manifest.xml", containsManifest(validator));
    }

    @Test
    public void signingTwiceShouldNotCreateConflictingManifest() throws Exception {
        documentToSign = sign();
        getSignatureParameters().aSiC().setSignatureFileName("signatures002.xml");
        documentToSign = sign();
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToSign);
        Assert.assertTrue("BDoc does not contain META-INF/manifest.xml", containsManifest(validator));
    }

    @Test
    public void settingSignatureIdWhenSigningAsic() throws Exception {
        getSignatureParameters().setDeterministicId("SIGNATURE-1");
        documentToSign = sign();
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToSign);
        assertEquals("SIGNATURE-1", validator.getSignatures().get(0).getId());
    }

    @Test
    public void signatureReferences_ShouldUseUriEncoding() throws Exception {
        documentToSign = new InMemoryDocument("Hello Wolrd !".getBytes(), "dds_JÜRIÖÖ € žŠ päev.txt");
        getSignatureParameters().setDetachedContent(documentToSign);
        documentToSign = sign();
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToSign);
        XAdESSignature signature = (XAdESSignature)validator.getSignatures().get(0);
        String referenceUri = getSignedDataFileReferenceUri(signature);
        assertEquals("dds_J%C3%9CRI%C3%96%C3%96%20%E2%82%AC%20%C5%BE%C5%A0%20p%C3%A4ev.txt", referenceUri);
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    public void signAndVerify() throws IOException {
        //DO nothing
    }

    private boolean containsManifest(SignedDocumentValidator validator) {
        List<DSSDocument> detachedContents = validator.getDetachedContents();
        for (DSSDocument dssDocument : detachedContents) {
            if ("META-INF/manifest.xml".equals(dssDocument.getName())) {
                return true;
            }
        }
        return false;
    }

    private String getSignedDataFileReferenceUri(XAdESSignature xAdESSignature) {
        XPathQueryHolder xPathQueryHolder = xAdESSignature.getXPathQueryHolder();
        Element signatureElement = xAdESSignature.getSignatureElement();
        NodeList references = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_REFERENCE);
        Node dataFileReference = references.item(0);
        String uri = dataFileReference.getAttributes().getNamedItem("URI").getNodeValue();
        return uri;
    }
}
