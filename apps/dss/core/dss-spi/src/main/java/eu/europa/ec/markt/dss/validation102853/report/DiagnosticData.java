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

package eu.europa.ec.markt.dss.validation102853.report;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

/**
 * This class represents all static data extracted by the process analysing the signature. They are independent from the validation policy to be applied.
 *
 * <p> DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class DiagnosticData extends XmlDom {

    private List<String> signatureIdList;

    public DiagnosticData(final Document document) {
        super(document);
    }

    public Date getSignatureDate() {

        final Date signatureDate = getTimeValue("/DiagnosticData/Signature[1]/DateTime/text()");
        //final XMLGregorianCalendar xmlGregorianCalendar = DSSXMLUtils.createXMLGregorianCalendar(signatureDate);
        //xmlGregorianCalendar.
        return signatureDate;
    }

    public Date getSignatureDate(final String signatureId) {

        Date signatureDate = null;
        try {
            signatureDate = getTimeValue("/DiagnosticData/Signature[@Id='%s']/DateTime/text()", signatureId);
        } catch (DSSException e) {

            // returns null if not found
        }
        return signatureDate;
    }

    /**
     * This method returns the list of the signature id. The result is stored in the local variable.
     *
     * @return list of signature ids
     */
    public List<String> getSignatureId() {

        if (signatureIdList == null) {

            signatureIdList = new ArrayList<String>();

            final List<XmlDom> signatures = getElements("/DiagnosticData/Signature");
            for (final XmlDom signature : signatures) {

                final String signatureId = signature.getAttribute("Id");
                signatureIdList.add(signatureId);
            }
        }
        return signatureIdList;
    }

    public String getPolicyId() {

        final String policyId = getValue("/DiagnosticData/Signature[1]/Policy/Id/text()");
        return policyId;
    }

    public List<String> getTimestampsId(final String signatureId) {

        final List<String> timestampIdList = new ArrayList<String>();

        final List<XmlDom> timestamps = getElements("/DiagnosticData/Signature[@Id='%s']/Timestamps/Timestamp", signatureId);
        for (final XmlDom timestamp : timestamps) {

            final String timestampId = timestamp.getAttribute("Id");
            final String timestampTypeString = timestamp.getAttribute("Type");
            // final TimestampType timestampTypeFromSignature = TimestampType.valueOf(timestampTypeString);
            // if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampTypeFromSignature)) {

            timestampIdList.add(timestampId);
            // }
        }
        return timestampIdList;
    }

    /**
     * This method returns signing certificate dss id for the first signature.
     *
     * @return signing certificate dss id.
     */
    public int getSigningCertificateId() {

        final int signingCertificateId = getIntValue("/DiagnosticData/Signature[1]/SigningCertificate/@Id");
        return signingCertificateId;
    }

    /**
     * This method returns signing certificate dss id for the given signature.
     *
     * @param signatureId signature id
     * @return signing certificate dss id for the given signature.
     */
    public int getSigningCertificateId(final String signatureId) {

        final int signingCertificateId = getIntValue("/DiagnosticData/Signature[@Id='%s']/SigningCertificate/@Id", signatureId);
        return signingCertificateId;
    }

    /**
     * This method return the revocation source for the given certificate.
     *
     * @param dssCertificateId DSS certificate identifier to be checked
     * @return revocation source
     */
    public String getCertificateRevocationSource(final int dssCertificateId) {

        final String certificateRevocationSource = getValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/Revocation/Source/text()", dssCertificateId);
        return certificateRevocationSource;
    }

    /**
     * This method returns the {@code DigestAlgorithm} of the first signature.
     *
     * @return The {@code DigestAlgorithm} of the first signature
     */
    public DigestAlgorithm getSignatureDigestAlgorithm() {

        final String signatureDigestAlgorithmName = getValue("/DiagnosticData/Signature[1]/BasicSignature/DigestAlgoUsedToSignThisToken/text()");
        final DigestAlgorithm signatureDigestAlgorithm = DigestAlgorithm.forName(signatureDigestAlgorithmName, null);
        return signatureDigestAlgorithm;
    }

    /**
     * This method returns the {@code DigestAlgorithm} for the given signature.
     *
     * @param signatureId The identifier of the signature, for which the algorithm is sought.
     * @return The {@code DigestAlgorithm} for the given signature
     */
    public DigestAlgorithm getSignatureDigestAlgorithm(final String signatureId) {

        final String signatureDigestAlgorithmName = getValue("/DiagnosticData/Signature[@Id='%s']/BasicSignature/DigestAlgoUsedToSignThisToken/text()", signatureId);
        final DigestAlgorithm signatureDigestAlgorithm = DigestAlgorithm.forName(signatureDigestAlgorithmName);
        return signatureDigestAlgorithm;
    }

    /**
     * This method returns the {@code EncryptionAlgorithm} of the first signature.
     *
     * @return The {@code EncryptionAlgorithm} of the first signature
     */
    public EncryptionAlgorithm getSignatureEncryptionAlgorithm() {

        final String signatureEncryptionAlgorithmName = getValue("/DiagnosticData/Signature[1]/BasicSignature/EncryptionAlgoUsedToSignThisToken/text()");
        final EncryptionAlgorithm signatureEncryptionAlgorithm = EncryptionAlgorithm.forName(signatureEncryptionAlgorithmName, null);
        return signatureEncryptionAlgorithm;
    }

    /**
     * This method returns the {@code DigestAlgorithm} for the given signature.
     *
     * @param signatureId The identifier of the signature, for which the algorithm is sought.
     * @return The {@code DigestAlgorithm} for the given signature
     */
    public EncryptionAlgorithm getSignatureEncryptionAlgorithm(final String signatureId) {

        final String signatureEncryptionAlgorithmName = getValue("/DiagnosticData/Signature[1]/BasicSignature/EncryptionAlgoUsedToSignThisToken/text()");
        final EncryptionAlgorithm signatureEncryptionAlgorithm = EncryptionAlgorithm.forName(signatureEncryptionAlgorithmName);
        return signatureEncryptionAlgorithm;
    }

    /**
     * This method returns the revocation reason for the given certificate.
     *
     * @param dssCertificateId DSS certificate identifier to be checked
     * @return revocation reason
     */
    public String getCertificateRevocationReason(int dssCertificateId) {

        final String revocationReason = getValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/Revocation/Reason/text()", dssCertificateId);
        return revocationReason;
    }

    /**
     * Returns the result of validation of the timestamp message imprint.
     *
     * @param timestampId timestamp id
     * @return true or false
     */
    public boolean isTimestampMessageImprintIntact(final String timestampId) {

        final boolean messageImprintIntact = getBoolValue("/DiagnosticData/Signature/Timestamps/Timestamp[@Id='%s']/MessageImprintDataIntact/text()", timestampId);
        return messageImprintIntact;
    }

    /**
     * Returns the result of validation of the timestamp signature.
     *
     * @param timestampId timestamp id
     * @return
     */
    public boolean isTimestampSignatureValid(final String timestampId) {

        final boolean signatureValid = getBoolValue("/DiagnosticData/Signature/Timestamps/Timestamp[@Id='%s']/BasicSignature/SignatureValid/text()", timestampId);
        return signatureValid;
    }

    /**
     * Returns the type of the timestamp.
     *
     * @param timestampId timestamp id
     * @return
     */
    public String getTimestampType(final String timestampId) {

        final String timestampType = getValue("/DiagnosticData/Signature/Timestamps/Timestamp[@Id='%s']/@Type", timestampId);
        return timestampType;
    }
}