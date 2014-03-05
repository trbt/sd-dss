/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.cades;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSASN1Utils;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.AbstractSignatureService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;

/**
 * CAdES implementation of DocumentSignatureService
 *
 * @version $Revision: 3434 $ - $Date: 2014-02-10 14:00:08 +0100 (Mon, 10 Feb 2014) $
 */

public class CAdESService extends AbstractSignatureService {

    private static final Logger LOG = LoggerFactory.getLogger(CAdESService.class.getName());

    private final CMSSignedDataGeneratorBuilder cmsSignedDataGeneratorBuilder;

    private TSPSource tspSource;

    /**
     * The default constructor for CAdESService.
     */
    public CAdESService(final CertificateVerifier certificateVerifier) {

        super(certificateVerifier);
        Security.addProvider(new BouncyCastleProvider());
        cmsSignedDataGeneratorBuilder = new CMSSignedDataGeneratorBuilder();
    }

    @Override
    public void setTspSource(TSPSource tspSource) {

        this.tspSource = tspSource;
    }

    private SignatureExtension getExtensionProfile(final SignatureParameters parameters, final boolean onlyLastCMSSignature) {

        final SignatureLevel signatureLevel = parameters.getSignatureLevel();
        switch (signatureLevel) {
            case CAdES_BASELINE_T:
                return new CAdESLevelBaselineT(tspSource, certificateVerifier, onlyLastCMSSignature);
            case CAdES_BASELINE_LT:
                return new CAdESLevelBaselineLT(tspSource, certificateVerifier, onlyLastCMSSignature);
            case CAdES_BASELINE_LTA:
                return new CAdESLevelBaselineLTA(tspSource, certificateVerifier, onlyLastCMSSignature);
            default:
                throw new DSSException("Unsupported signature format " + signatureLevel);
        }
    }

    @Override
    @Deprecated
    public InputStream toBeSigned(final DSSDocument document, final SignatureParameters parameters) throws DSSException {

        final byte[] dataToSign = getDataToSign(document, parameters);
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(dataToSign);
        return byteArrayInputStream;
    }

    @Override
    public byte[] getDataToSign(final DSSDocument document, final SignatureParameters parameters) throws DSSException {

        assertSigningDateInCertificateValidityRange(parameters);

        final SignaturePackaging packaging = parameters.getSignaturePackaging();
        assertSignaturePackaging(packaging);

        final DSSDocument dssDocument = getSignedContent(document);

        final SignatureAlgorithm signatureAlgo = parameters.getSignatureAlgorithm();
        final PreComputedContentSigner preComputedContentSigner = new PreComputedContentSigner(signatureAlgo.getJCEId());

        SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = cmsSignedDataGeneratorBuilder.getSignerInfoGeneratorBuilder(dssDocument, parameters, false);

        CMSSignedData originalSignedData = getCmsSignedData(dssDocument, parameters);

        final X509Certificate signingCertificate = parameters.getSigningCertificate();
        final List<X509Certificate> certificateChain = parameters.getCertificateChain();
        final CMSSignedDataGenerator generator = cmsSignedDataGeneratorBuilder
              .createCMSSignedDataGenerator(certificateVerifier, signingCertificate, certificateChain, preComputedContentSigner, signerInfoGeneratorBuilder, originalSignedData);

        final byte[] dssDocumentBytes = dssDocument.getBytes();
        final CMSProcessableByteArray content = new CMSProcessableByteArray(dssDocumentBytes);
        final boolean encapsulate = !packaging.equals(SignaturePackaging.DETACHED);
        DSSASN1Utils.generate(generator, content, encapsulate);
        return preComputedContentSigner.getOutputStream().toByteArray();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DSSDocument signDocument(final DSSDocument document, final SignatureParameters parameters, final byte[] signatureValue) throws DSSException {

        assertSigningDateInCertificateValidityRange(parameters);
        final SignaturePackaging packaging = parameters.getSignaturePackaging();
        assertSignaturePackaging(packaging);

        final SignatureAlgorithm signatureAlgo = parameters.getSignatureAlgorithm();
        final PreComputedContentSigner preComputedContentSigner = new PreComputedContentSigner(signatureAlgo.getJCEId(), signatureValue);

        final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = cmsSignedDataGeneratorBuilder.getSignerInfoGeneratorBuilder(document, parameters, true);

        final CMSSignedData originalSignedData = getCmsSignedData(document, parameters);

        final X509Certificate signingCertificate = parameters.getSigningCertificate();
        final List<X509Certificate> certificateChain = parameters.getCertificateChain();
        final CMSSignedDataGenerator generator = cmsSignedDataGeneratorBuilder
              .createCMSSignedDataGenerator(certificateVerifier, signingCertificate, certificateChain, preComputedContentSigner, signerInfoGeneratorBuilder, originalSignedData);

        final CMSSignedData data;
        if (parameters.getSignaturePackaging() == SignaturePackaging.ENVELOPING && originalSignedData != null) {

            final byte[] octetString = (byte[]) originalSignedData.getSignedContent().getContent();
            final CMSProcessableByteArray content = new CMSProcessableByteArray(octetString);
            data = DSSASN1Utils.generate(generator, content, true);
        } else {

            final byte[] dssDocumentBytes = document.getBytes();
            final CMSProcessableByteArray content = new CMSProcessableByteArray(dssDocumentBytes);
            final boolean encapsulate = !packaging.equals(SignaturePackaging.DETACHED);
            data = DSSASN1Utils.generate(generator, content, encapsulate);
        }

        final DSSDocument signedDocument;
        final SignatureLevel signatureLevel = parameters.getSignatureLevel();
        if (!signatureLevel.equals(SignatureLevel.CAdES_BASELINE_B)) {

            // true: Only the last signature will be extended
            final SignatureExtension extension = getExtensionProfile(parameters, true);
            if (packaging == SignaturePackaging.DETACHED) {

                parameters.setOriginalDocument(document);
            }
            final CMSSignedDocument cmsSignedDocument = new CMSSignedDocument(data);
            signedDocument = extension.extendSignatures(cmsSignedDocument, parameters);
        } else {

            signedDocument = new CMSSignedDocument(data);
        }
        return signedDocument;
    }

    /**
     * Signs the document in the single operation
     *
     * @param dssDocument   - document to sign
     * @param parameters
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws DSSException
     */
    @Override
    public DSSDocument signDocument(final DSSDocument dssDocument, final SignatureParameters parameters) throws DSSException {

        final SignatureTokenConnection token = parameters.getSigningToken();
        if (token == null) {

            throw new DSSNullException(SignatureTokenConnection.class, "", "The connection through available API to the SSCD must be set.");
        }
        // final DSSDocument dssDocument = getSignedContent(document);
        final byte[] dataToSign = getDataToSign(dssDocument, parameters);
        byte[] signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), parameters.getPrivateKeyEntry());
        return signDocument(dssDocument, parameters, signatureValue);
    }

    /**
     * This method returns the signed content of CMSSignedData if the dss document is a cms message.
     *
     * @param dssDocument the document to sign to already signed
     * @return the original document to sign
     */
    private DSSDocument getSignedContent(final DSSDocument dssDocument) {

        // check if the document is already a CMS Document
        byte[] documentBytes = dssDocument.getBytes();
        try {
            final CMSSignedData cmsSignedData = new CMSSignedData(documentBytes);
            final CMSTypedData signedContent = cmsSignedData.getSignedContent();
            // TODO: (Bob: 2014 Jan 22) And what do you get when the 'signedContent' variable is null? --> problem
            documentBytes = (signedContent != null) ? (byte[]) signedContent.getContent() : null;
            final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes);
            return inMemoryDocument;
        } catch (CMSException e) {
            // it is not a signed CMS Document
        }
        return dssDocument;
    }

    /**
     * @param document
     * @param parameters
     * @return the original signed data if the document is already signed. Null otherwise, or if we ask a detached signature.
     */
    private CMSSignedData getCmsSignedData(final DSSDocument document, final SignatureParameters parameters) {

        CMSSignedData originalSignedData = null;
        if (parameters.getSignaturePackaging() == SignaturePackaging.ENVELOPING) {

            try {
                // check if input document is already signed
                final InputStream input = document.openStream();
                originalSignedData = new CMSSignedData(input);
                if (originalSignedData.getSignedContent().getContent() == null) {
                    originalSignedData = null;
                }
            } catch (Exception e) {
                // not a parallel signature
            }
        }
        return originalSignedData;
    }




    @Override
    public DSSDocument extendDocument(final DSSDocument document, final SignatureParameters parameters) {

        // false: All signature are extended
        final SignatureExtension extension = getExtensionProfile(parameters, false);
        final DSSDocument dssDocument = extension.extendSignatures(document, parameters);
        return dssDocument;
    }

    /**
     * @param packaging
     * @throws IllegalArgumentException if the packaging is not supported for this kind of signature
     */

    private void assertSignaturePackaging(SignaturePackaging packaging) throws IllegalArgumentException {

        if (packaging != SignaturePackaging.ENVELOPING && packaging != SignaturePackaging.DETACHED) {
            throw new IllegalArgumentException("Unsupported signature packaging " + packaging);
        }
    }
}
