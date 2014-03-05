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

package eu.europa.ec.markt.dss.signature.pades;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSASN1Utils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.AbstractSignatureService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.cades.CAdESLevelBaselineT;
import eu.europa.ec.markt.dss.signature.cades.PreComputedContentSigner;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PdfObjFactory;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;

/**
 * PAdES implementation of the DocumentSignatureService
 *
 * @version $Revision: 3478 $ - $Date: 2014-02-19 10:45:39 +0100 (Wed, 19 Feb 2014) $
 */

public class PAdESService extends AbstractSignatureService {

    private static final Logger LOG = LoggerFactory.getLogger(PAdESService.class);

    private final PadesCMSSignedDataGeneratorBuilder cmsSignedDataGeneratorBuilder;

    private TSPSource tspSource;

    /**
     * To construct a signature service the <code>CertificateVerifier</code> must be set and cannot be null.
     *
     * @param certificateVerifier
     */
    public PAdESService(CertificateVerifier certificateVerifier) {
        super(certificateVerifier);
        cmsSignedDataGeneratorBuilder = new PadesCMSSignedDataGeneratorBuilder();
    }

    @Override
    public void setTspSource(TSPSource tspSource) {

        this.tspSource = tspSource;
    }

    private SignatureExtension getExtensionProfile(SignatureParameters parameters) {

        switch (parameters.getSignatureLevel()) {
            case PAdES_BASELINE_B:
                return null;
            case PAdES_BASELINE_T:
                return new PAdESLevelBaselineT(tspSource, certificateVerifier);
            case PAdES_BASELINE_LT:
                return new PAdESLevelBaselineLT(tspSource, certificateVerifier);
            case PAdES_BASELINE_LTA:
                return new PAdESLevelBaselineLTA(tspSource, certificateVerifier);
            default:
                throw new IllegalArgumentException("Signature format '" + parameters.getSignatureLevel() + "' not supported");
        }
    }

    @Override
    @Deprecated
    public InputStream toBeSigned(DSSDocument document, SignatureParameters parameters) throws DSSException {

        final byte[] dataToSign = getDataToSign(document, parameters);
        final InputStream inputStreamToSign = DSSUtils.toInputStream(dataToSign);
        return inputStreamToSign;
    }

    @Override
    public byte[] getDataToSign(DSSDocument document, SignatureParameters parameters) throws DSSException {

        assertSigningDateInCertificateValidityRange(parameters);

        final SignatureAlgorithm signatureAlgo = parameters.getSignatureAlgorithm();
        final DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();
        final PreComputedContentSigner preComputedContentSigner = new PreComputedContentSigner(signatureAlgo.getJCEId());

        final PDFSignatureService pdfSignatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
        final byte[] messageDigest = pdfSignatureService.digest(document.openStream(), parameters, parameters.getDigestAlgorithm());

        if (LOG.isDebugEnabled()) {
            LOG.debug("Calculated digest on byte range " + Hex.encodeHexString(messageDigest));
        }

        SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = cmsSignedDataGeneratorBuilder
              .getSignerInfoGeneratorBuilder(document, parameters, digestCalculatorProvider, messageDigest);

        final X509Certificate signingCertificate = parameters.getSigningCertificate();
        final List<X509Certificate> certificateChain = parameters.getCertificateChain();
        final CMSSignedDataGenerator generator = cmsSignedDataGeneratorBuilder
              .createCMSSignedDataGenerator(certificateVerifier, signingCertificate, certificateChain, preComputedContentSigner, signerInfoGeneratorBuilder, null);

        final CMSProcessableByteArray content = new CMSProcessableByteArray(messageDigest);

        DSSASN1Utils.generate(generator, content, false);

        final byte[] dataToSign = preComputedContentSigner.getOutputStream().toByteArray();
        return dataToSign;
    }

    @Override
    public DSSDocument signDocument(final DSSDocument document, final SignatureParameters parameters, final byte[] signatureValue) throws DSSException {
        assertSigningDateInCertificateValidityRange(parameters);
        try {
            final SignatureAlgorithm signatureAlgo = parameters.getSignatureAlgorithm();
            final DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();
            final PreComputedContentSigner preComputedContentSigner = new PreComputedContentSigner(signatureAlgo.getJCEId(), signatureValue);

            final PDFSignatureService pdfSignatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
            final byte[] messageDigest = pdfSignatureService.digest(document.openStream(), parameters, parameters.getDigestAlgorithm());
            if (LOG.isInfoEnabled()) {

                LOG.info("Calculated digest on byte range +++++ " + Hex.encodeHexString(messageDigest) + " +++++");
            }

            SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = cmsSignedDataGeneratorBuilder
                  .getSignerInfoGeneratorBuilder(document, parameters, digestCalculatorProvider, messageDigest);

            final CMSSignedDataGenerator generator = cmsSignedDataGeneratorBuilder
                  .createCMSSignedDataGenerator(certificateVerifier, parameters.getSigningCertificate(), parameters.getCertificateChain(), preComputedContentSigner,
                        signerInfoGeneratorBuilder, null);

            final CMSProcessableByteArray content = new CMSProcessableByteArray(messageDigest);
            final boolean encapsulate = false;
            CMSSignedData data = generator.generate(content, encapsulate);

            final SignatureLevel signatureLevel = parameters.getSignatureLevel();
            if (signatureLevel != SignatureLevel.PAdES_BASELINE_B) {
                // use an embedded timestamp
                CAdESLevelBaselineT cadesLevelBaselineT = new CAdESLevelBaselineT(tspSource, certificateVerifier, false);
                data = cadesLevelBaselineT.extendCMSSignatures(data, parameters);
            }

            final ByteArrayOutputStream output = new ByteArrayOutputStream();
            final byte[] encodedData = DSSASN1Utils.getEncoded(data);
            pdfSignatureService.sign(document.openStream(), encodedData, output, parameters, parameters.getDigestAlgorithm());

            DSSDocument doc = null;
            if (DSSUtils.isEmpty(document.getName())) {
                doc = new InMemoryDocument(output.toByteArray(), null, MimeType.PDF);
            } else {
                doc = new InMemoryDocument(output.toByteArray(), document.getName(), MimeType.PDF);
            }

            final SignatureExtension extension = getExtensionProfile(parameters);
            if (signatureLevel != SignatureLevel.PAdES_BASELINE_B && signatureLevel != SignatureLevel.PAdES_BASELINE_T && extension != null) {
                return extension.extendSignatures(doc, parameters);
            } else {
                return doc;
            }
        } catch (CMSException e) {
            throw new DSSException(e);
        }
    }

    @Override
    public DSSDocument extendDocument(DSSDocument document, SignatureParameters parameters) throws DSSException {

        SignatureExtension extension = getExtensionProfile(parameters);
        if (extension != null) {
            return extension.extendSignatures(document, parameters);
        }
        return document;
    }

    @Override
    public DSSDocument signDocument(final DSSDocument document, final SignatureParameters parameters) throws DSSException {

        SignatureTokenConnection token = parameters.getSigningToken();
        if (token == null) {
            throw new IllegalArgumentException("SigningToken is null, the connection through available API to the SSCD must be set.");
        }
        final byte[] dataToSign = getDataToSign(document, parameters);
        final byte[] signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), parameters.getPrivateKeyEntry());
        final DSSDocument dssDocument = signDocument(document, parameters, signatureValue);
        return dssDocument;
    }
}
