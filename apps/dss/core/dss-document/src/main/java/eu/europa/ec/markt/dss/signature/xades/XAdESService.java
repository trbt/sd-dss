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

package eu.europa.ec.markt.dss.signature.xades;

import java.io.InputStream;

import org.apache.xml.security.Init;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.AbstractSignatureService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.ProfileParameters;
import eu.europa.ec.markt.dss.signature.ProfileParameters.Operation;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;

/**
 * XAdES implementation of DocumentSignatureService
 *
 * @version $Revision: 3378 $ - $Date: 2014-01-23 00:46:55 +0100 (Thu, 23 Jan 2014) $
 */

public class XAdESService extends AbstractSignatureService {

    private TSPSource tspSource;

    static {

        Init.init();
    }

    /**
     * This is the main constructor to create an instance of the service. A certificate verifier must be provided.
     *
     * @param certificateVerifier certificate verifier (cannot be null)
     */
    public XAdESService(final CertificateVerifier certificateVerifier) {

        super(certificateVerifier);
    }

    @Override
    public void setTspSource(final TSPSource tspSource) {

        this.tspSource = tspSource;
    }

    /**
     * The choice of profile according to the passed parameter.
     *
     * @param parameters
     * @return
     */
    private SignatureExtension getExtensionProfile(final SignatureParameters parameters) {

        switch (parameters.getSignatureLevel()) {
            case XAdES_BASELINE_B:

                return null;
            case XAdES_BASELINE_T:

                final XAdESLevelBaselineT extensionT = new XAdESLevelBaselineT(certificateVerifier);
                extensionT.setTspSource(tspSource);
                return extensionT;
            case XAdES_C:

                final XAdESLevelC extensionC = new XAdESLevelC(certificateVerifier);
                extensionC.setTspSource(tspSource);
                return extensionC;
            case XAdES_X:

                final XAdESLevelX extensionX = new XAdESLevelX(certificateVerifier);
                extensionX.setTspSource(tspSource);
                return extensionX;
            case XAdES_XL:

                final XAdESLevelXL extensionXL = new XAdESLevelXL(certificateVerifier);
                extensionXL.setTspSource(tspSource);
                return extensionXL;
            case XAdES_A:

                final XAdESLevelA extensionA = new XAdESLevelA(certificateVerifier);
                extensionA.setTspSource(tspSource);
                return extensionA;
            case XAdES_BASELINE_LT:

                final XAdESLevelBaselineLT extensionLT = new XAdESLevelBaselineLT(certificateVerifier);
                extensionLT.setTspSource(tspSource);
                return extensionLT;
            case XAdES_BASELINE_LTA:

                final XAdESLevelBaselineLTA extensionLTA = new XAdESLevelBaselineLTA(certificateVerifier);
                extensionLTA.setTspSource(tspSource);
                return extensionLTA;
            default:

                throw new DSSException("Unsupported signature format " + parameters.getSignatureLevel());
        }
    }

    @Override
    @Deprecated
    public InputStream toBeSigned(final DSSDocument document, final SignatureParameters parameters) throws DSSException {

        final byte[] dataToSign = getDataToSign(document, parameters);
        final InputStream inputStreamToSign = DSSUtils.toInputStream(dataToSign);
        return inputStreamToSign;
    }

    @Override
    public byte[] getDataToSign(final DSSDocument document, final SignatureParameters parameters) throws DSSException {

        if (parameters.getSignatureLevel() == null) {
            throw new DSSNullException(SignatureParameters.class);
        }
        assertSigningDateInCertificateValidityRange(parameters);
        final XAdESLevelBaselineB profile = new XAdESLevelBaselineB(certificateVerifier);
        final byte[] dataToSign = profile.getDataToSign(document, parameters);
        parameters.getContext().setProfile(profile);
        return dataToSign;
    }

    @Override
    public DSSDocument signDocument(final DSSDocument document, final SignatureParameters parameters, final byte[] signatureValue) throws DSSException {

        if (parameters.getSignatureLevel() == null) {
            throw new DSSNullException(SignatureParameters.class);
        }
        assertSigningDateInCertificateValidityRange(parameters);
        parameters.getContext().setOperationKind(Operation.SIGNING);
        final XAdESLevelBaselineB profile;
        ProfileParameters context = parameters.getContext();
        if (context.getProfile() != null) {

            profile = context.getProfile();
        } else {

            profile = new XAdESLevelBaselineB(certificateVerifier);
        }
        final DSSDocument signedDoc = profile.signDocument(document, parameters, signatureValue);
        final SignatureExtension extension = getExtensionProfile(parameters);
        if (extension != null) {

            final DSSDocument dssExtendedDocument = extension.extendSignatures(signedDoc, parameters);
            return dssExtendedDocument;
        }
        return signedDoc;
    }

    @Override
    public DSSDocument signDocument(final DSSDocument document, final SignatureParameters parameters) throws DSSException {

        if (parameters.getSignatureLevel() == null) {
            throw new DSSNullException(SignatureParameters.class);
        }
        final SignatureTokenConnection signingToken = parameters.getSigningToken();
        if (signingToken == null) {
            throw new DSSNullException(SignatureTokenConnection.class);
        }

        parameters.getContext().setOperationKind(Operation.SIGNING);

        final XAdESLevelBaselineB profile = new XAdESLevelBaselineB(certificateVerifier);
        final byte[] dataToSign = profile.getDataToSign(document, parameters);
        parameters.getContext().setProfile(profile);

        final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
        final DSSPrivateKeyEntry dssPrivateKeyEntry = parameters.getPrivateKeyEntry();
        final byte[] signatureValue = signingToken.sign(dataToSign, digestAlgorithm, dssPrivateKeyEntry);
        final DSSDocument dssDocument = signDocument(document, parameters, signatureValue);
        return dssDocument;
    }

    @Override
    public DSSDocument extendDocument(final DSSDocument document, final SignatureParameters parameters) throws DSSException {

        parameters.getContext().setOperationKind(Operation.EXTENDING);
        final SignatureExtension extension = getExtensionProfile(parameters);
        if (extension != null) {

            final DSSDocument dssDocument = extension.extendSignatures(document, parameters);
            return dssDocument;
        }
        throw new DSSException("Cannot extend to " + parameters.getSignatureLevel().name());
    }
}
