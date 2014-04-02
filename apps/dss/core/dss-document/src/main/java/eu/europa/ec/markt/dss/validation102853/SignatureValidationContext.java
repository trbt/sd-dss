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

package eu.europa.ec.markt.dss.validation102853;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation102853.crl.CRLSource;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;
import eu.europa.ec.markt.dss.validation102853.ocsp.OCSPSource;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

/**
 * During the validation of a signature, the software retrieves different X509 artifacts like Certificate, CRL and OCSP Response. The SignatureValidationContext is a "cache" for
 * one validation request that contains every object retrieved so far.
 *
 * @version $Revision: 1839 $ - $Date: 2013-04-04 17:40:51 +0200 (Thu, 04 Apr 2013) $
 */

public class SignatureValidationContext implements ValidationContext {

    private static final Logger LOG = LoggerFactory.getLogger(SignatureValidationContext.class);

    private final Set<CertificateToken> processedCertificates = new HashSet<CertificateToken>();
    private final Set<RevocationToken> processedRevocations = new HashSet<RevocationToken>();
    private final Set<TimestampToken> processedTimestamps = new HashSet<TimestampToken>();

    /**
     * The data loader used to access AIA certificate source.
     */
    private DataLoader dataLoader;

    /**
     * The certificate pool which encapsulates all certificates used during the validation process and extracted from all used sources
     */
    protected CertificatePool validationCertPool;

    protected AdvancedSignature signature;

    private final Map<Token, Boolean> tokensToProcess = new HashMap<Token, Boolean>();

    // External OCSP source.
    private OCSPSource ocspSource;

    // External CRL source.
    private CRLSource crlSource;

    // CRLs from the signature.
    private CRLSource signCRLSource;

    // OCSP from the signature.
    private OCSPSource signOCSPSource;

    // Enclosed content timestamps.
    private List<TimestampToken> contentTimestamps;

    // Enclosed signature timestamps.
    private List<TimestampToken> signatureTimestamps;

    // Enclosed SignAndRefs timestamps.
    private List<TimestampToken> sigAndRefsTimestamps;

    // Enclosed RefsOnly timestamps.
    private List<TimestampToken> refsOnlyTimestamps;

    // Enclosed Archive timestamps.
    private List<TimestampToken> archiveTimestamps;

    // The digest value of the certification path references and the revocation status references.
    private List<TimestampReference> timestampedReferences;

    /**
     * This constructor is used when the whole signature need to be validated.
     *
     * @param signature          The signature to be validated
     * @param certVerifier       The trusted certificates verifier (using the TSL as list of trusted certificates).
     * @param validationCertPool The pool of certificates used during the validation process
     */
    public SignatureValidationContext(final AdvancedSignature signature, final CertificateVerifier certVerifier, final CertificatePool validationCertPool) {

        if (signature == null) {

            throw new DSSException("The signature to validate cannot be null.");
        }
        if (certVerifier == null) {

            throw new DSSException("The certificate verifier cannot be null.");
        }
        if (validationCertPool == null) {

            throw new DSSException("The certificate pool cannot be null.");
        }

        // this variable need to be preserved for timestamp data computation.
        this.signature = signature;

        this.crlSource = certVerifier.getCrlSource();
        this.ocspSource = certVerifier.getOcspSource();
        this.dataLoader = certVerifier.getDataLoader();

        this.signCRLSource = signature.getCRLSource();
        this.signOCSPSource = signature.getOCSPSource();

        contentTimestamps = signature.getContentTimestamps();

        signatureTimestamps = signature.getSignatureTimestamps();

        sigAndRefsTimestamps = signature.getTimestampsX1();

        refsOnlyTimestamps = signature.getTimestampsX2();

        this.timestampedReferences = signature.getTimestampedReferences();

        this.archiveTimestamps = signature.getArchiveTimestamps();

        this.validationCertPool = validationCertPool;
        if (LOG.isInfoEnabled()) {

            LOG.info("+ New ValidationContext created.");
        }
    }

    /**
     * This constructor is used when only a certificate need to be validated.
     *
     * @param certificateVerifier The certificates verifier (eg: using the TSL as list of trusted certificates).
     */
    public SignatureValidationContext(final CertificateVerifier certificateVerifier) {

        if (certificateVerifier == null) {

            throw new DSSException("The certificate verifier cannot be null.");
        }

        this.crlSource = certificateVerifier.getCrlSource();
        this.ocspSource = certificateVerifier.getOcspSource();
        this.dataLoader = certificateVerifier.getDataLoader();
        this.validationCertPool = SignedDocumentValidator.createValidationPool(certificateVerifier);
        if (LOG.isInfoEnabled()) {

            LOG.info("+ New ValidationContext created for a certificate.");
        }
    }

    /**
     * This function sets the signing certificate to validate.
     *
     * @param certificateToValidate certificate to validate
     */
    @Override
    public void setCertificateToValidate(final CertificateToken certificateToValidate) {

        addCertificateTokenForVerification(certificateToValidate);
    }

    /**
     * This method returns a token to verify. If there is no more tokens to verify null is returned.
     *
     * @return token to verify or null
     */
    private Token getNotYetVerifiedToken() {

        for (final Entry<Token, Boolean> entry : tokensToProcess.entrySet()) {

            if (entry.getValue() == null) {

                entry.setValue(true);
                return entry.getKey();
            }
        }
        return null;
    }

    /**
     * This method returns the issuer certificate (the certificate which was used to sign the token) of the given token.
     *
     * @param token the token for which the issuer must be obtained.
     * @return the issuer certificate token of the given token or null if not found.
     * @throws eu.europa.ec.markt.dss.exception.DSSException
     */
    private CertificateToken getIssuerCertificate(final Token token) throws DSSException {

        if (token.isTrusted()) {

            // When the token is trusted the check of the issuer token is not needed so null is returned. Only a certificate token can be trusted.
            return null;
        }
        if (token.getIssuerToken() != null) {

            /**
             * The signer's certificate have been found already. This can happen in the case of:<br>
             * - multiple signatures that use the same certificate,<br>
             * - OCSPRespTokens (the issuer certificate is known from the beginning)
             */
            return token.getIssuerToken();
        }
        final X500Principal issuerX500Principal = token.getIssuerX500Principal();
        CertificateToken issuerCertificateToken = getIssuerFromPool(token, issuerX500Principal);

        if (issuerCertificateToken == null && token instanceof CertificateToken) {

            issuerCertificateToken = getIssuerFromAIA((CertificateToken) token);
        }
        if (issuerCertificateToken == null) {

            token.extraInfo().infoTheSigningCertNotFound();
        }
        if (issuerCertificateToken != null && !issuerCertificateToken.isTrusted() && !issuerCertificateToken.isSelfSigned()) {

            // The full chain is retrieved for each certificate
            getIssuerCertificate(issuerCertificateToken);
        }
        return issuerCertificateToken;
    }

    /**
     * Get the issuer's certificate from Authority Information Access through id-ad-caIssuers extension.
     *
     * @param token {@code CertificateToken} for which the issuer is sought.
     * @return {@code CertificateToken} representing the issuer certificate or null.
     */
    private CertificateToken getIssuerFromAIA(final CertificateToken token) {

        final X509Certificate issuerCert;
        try {

            LOG.info("Retrieving {} certificate's issuer using AIA.", token.getAbbreviation());
            issuerCert = DSSUtils.loadIssuerCertificate(token.getCertificate(), dataLoader);
            if (issuerCert != null) {

                final CertificateToken issuerCertToken = validationCertPool.getInstance(issuerCert, CertificateSourceType.AIA);
                if (token.isSignedBy(issuerCertToken)) {

                    return issuerCertToken;
                }
                LOG.info("The retrieved certificate using AIA does not sign the certificate {}.", token.getAbbreviation());
            } else {

                LOG.info("The issuer certificate cannot be loaded using AIA.");
            }
        } catch (DSSException e) {

            LOG.error(e.getMessage());
        }
        return null;
    }

    /**
     * This function retrieves the issuer certificate from the validation pool (this pool should contain trusted certificates). The check is made if the token is well signed by
     * the retrieved certificate.
     *
     * @param token               token for which the issuer have to be found
     * @param issuerX500Principal issuer's subject distinguished name
     * @return the corresponding {@code CertificateToken} or null if not found
     */
    private CertificateToken getIssuerFromPool(final Token token, final X500Principal issuerX500Principal) {

        final List<CertificateToken> issuerCertList = validationCertPool.get(issuerX500Principal);
        for (final CertificateToken issuerCertToken : issuerCertList) {

            // We keep the first issuer that signs the certificate
            if (token.isSignedBy(issuerCertToken)) {

                return issuerCertToken;
            }
        }
        return null;
    }

    /**
     * Adds a new token to the list of tokes to verify only if it was not already verified.
     *
     * @param token token to verify
     * @return true if the token was not yet verified, false otherwise.
     */
    private boolean addTokenForVerification(final Token token) {

        if (token == null) {

            return false;
        }
        if (tokensToProcess.containsKey(token)) {

            LOG.debug("Token was already in the list {}:{}", new Object[]{token.getClass().getSimpleName(), token.getAbbreviation()});
            return false;
        }
        tokensToProcess.put(token, null);
        LOG.debug("+ New {} to check: {}", new Object[]{token.getClass().getSimpleName(), token.getAbbreviation()});
        return true;
    }

    /**
     * Adds a new revocation token to the list of tokes to verify. only if it was not already verified.
     *
     * @param revocationToken revocation token to verify
     */
    private void addRevocationTokenForVerification(final RevocationToken revocationToken) {

        if (addTokenForVerification(revocationToken)) {

            final boolean added = processedRevocations.add(revocationToken);
            if (LOG.isTraceEnabled()) {
                if (added) {
                    LOG.trace("RevocationToken added to processedRevocations: {} ", revocationToken);
                } else {
                    LOG.trace("RevocationToken already present processedRevocations: {} ", revocationToken);
                }
            }
        }
    }

    /**
     * Adds a new certificate token to the list of tokes to verify. only if it was not already verified.
     *
     * @param certificateToken certificate token to verify
     */
    private void addCertificateTokenForVerification(final CertificateToken certificateToken) {

        if (addTokenForVerification(certificateToken)) {

            final boolean added = processedCertificates.add(certificateToken);
            if (LOG.isTraceEnabled()) {
                if (added) {
                    LOG.trace("CertificateToken added to processedRevocations: {} ", certificateToken);
                } else {
                    LOG.trace("CertificateToken already present processedRevocations: {} ", certificateToken);
                }
            }
        }
    }

    /**
     * Adds a new timestamp token to the list of tokes to verify. only if it was not already verified.
     *
     * @param timestampToken
     */
    private void addTimestampTokenForVerification(final TimestampToken timestampToken) {

        if (addTokenForVerification(timestampToken)) {

            final boolean added = processedTimestamps.add(timestampToken);
            if (LOG.isTraceEnabled()) {
                if (added) {
                    LOG.trace("TimestampToken added to processedRevocations: {} ", processedTimestamps);
                } else {
                    LOG.trace("TimestampToken already present processedRevocations: {} ", processedTimestamps);
                }
            }
        }
    }

    @Override
    public void validate() throws DSSException {

        runValidation();

        if (signature == null) {

            // Only a certificate is validated
            return;
        }

        /*
         * This validates the signature timestamp tokensToProcess present in the signature.
         */
        for (final TimestampToken timestampToken : contentTimestamps) {

            final byte[] timestampBytes = signature.getContentTimestampData(timestampToken);
            timestampToken.matchData(timestampBytes);

            addTimestampTokenForVerification(timestampToken);
            runValidation();
        }

        /*
         * This validates the signature timestamp tokensToProcess present in the signature.
         */
        for (final TimestampToken timestampToken : signatureTimestamps) {

            final byte[] timestampBytes = signature.getSignatureTimestampData(timestampToken);
            timestampToken.matchData(timestampBytes);

            addTimestampTokenForVerification(timestampToken);
            runValidation();
        }

        /*
         * This validates the SigAndRefs timestamp tokensToProcess present in the signature.
         */
        for (final TimestampToken timestampToken : sigAndRefsTimestamps) {

            final byte[] timestampBytes = signature.getTimestampX1Data(timestampToken);
            timestampToken.matchData(timestampBytes);

            addTimestampTokenForVerification(timestampToken);
            runValidation();
        }

        /*
         * This validates the RefsOnly timestamp tokensToProcess present in the signature.
         */
        for (final TimestampToken timestampToken : refsOnlyTimestamps) {

            final byte[] timestampBytes = signature.getTimestampX2Data(timestampToken);
            timestampToken.matchData(timestampBytes);

            addTimestampTokenForVerification(timestampToken);
            runValidation();
        }

      /*
       * This validates the archive timestamp tokensToProcess present in the signature.
       */
        for (final TimestampToken timestampToken : archiveTimestamps) {

            final byte[] timestampData = signature.getArchiveTimestampData(timestampToken);
            timestampToken.matchData(timestampData);

            addTimestampTokenForVerification(timestampToken);
            runValidation();
        }
    }

    /*
     * Executes the validation process for not yet validated tokensToProcess.
     */
    private void runValidation() throws DSSException {

        final Token token = getNotYetVerifiedToken();
        if (token == null) {

            return;
        }
      /*
       * Gets the issuer certificate of the Token and checks its signature
       */
        final CertificateToken issuerCertToken = getIssuerCertificate(token);
        if (issuerCertToken != null) {

            addCertificateTokenForVerification(issuerCertToken);
        }
        if (token instanceof CertificateToken) {

            final RevocationToken revocationToken = getRevocationData((CertificateToken) token);
            addRevocationTokenForVerification(revocationToken);
        }
        runValidation();
    }

    /**
     * Retrieves the revocation data from signature (if exists) or from the online sources.
     *
     * @param certToken
     * @return
     */
    private RevocationToken getRevocationData(final CertificateToken certToken) {

        if (certToken.isSelfSigned() || certToken.isTrusted() || certToken.getIssuerToken() == null) {

            // It is not possible to check the revocation data without its signing certificate or this is not needed for the trust anchor.
            return null;
        }
        if (certToken.isOCSPSigning() && certToken.hasIdPkixOcspNoCheckExtension()) {

            certToken.extraInfo().add("OCSP check not needed: id-pkix-ocsp-nocheck extension present.");
            return null;
        }
        //certToken.isOCSPSigning() &&

        boolean checkOnLine = shouldCheckOnLine(certToken);
        if (checkOnLine) {

            final OCSPAndCRLCertificateVerifier onlineVerifier = new OCSPAndCRLCertificateVerifier(crlSource, ocspSource, validationCertPool);
            final RevocationToken revocationToken = onlineVerifier.check(certToken);
            if (revocationToken != null) {

                return revocationToken;
            }
        }
        final OCSPAndCRLCertificateVerifier offlineVerifier = new OCSPAndCRLCertificateVerifier(signCRLSource, signOCSPSource, validationCertPool);
        final RevocationToken revocationToken = offlineVerifier.check(certToken);
        return revocationToken;
    }

    private boolean shouldCheckOnLine(final CertificateToken certificateToken) {

        final boolean expired = certificateToken.isExpired();
        if (!expired) {

            return true;
        }
        final CertificateToken issuerCertToken = certificateToken.getIssuerToken();
        // issuerCertToken cannot be null
        final boolean expiredCertOnCRLExtension = issuerCertToken.hasExpiredCertOnCRLExtension();
        if (expiredCertOnCRLExtension) {

            certificateToken.extraInfo().add("Certificate is expired but the issuer certificate has ExpiredCertOnCRL extension.");
            return true;
        }
        final Date expiredCertsRevocationFromDate = getExpiredCertsRevocationFromDate(certificateToken);
        if (expiredCertsRevocationFromDate != null) {

            certificateToken.extraInfo().add("Certificate is expired but the TSL extension 'expiredCertsRevocationInfo' is present: " + expiredCertsRevocationFromDate);
            return true;
        }
        return false;
    }

    private Date getExpiredCertsRevocationFromDate(final CertificateToken certificateToken) {

        final CertificateToken trustAnchor = certificateToken.getTrustAnchor();
        if (trustAnchor != null) {

            final List<ServiceInfo> serviceInfoList = trustAnchor.getAssociatedTSPS();
            if (serviceInfoList != null) {

                final Date notAfter = certificateToken.getNotAfter();
                for (final ServiceInfo serviceInfo : serviceInfoList) {

                    final Date date = serviceInfo.getExpiredCertsRevocationInfo();
                    if (date != null && date.before(notAfter)) {

                        if (serviceInfo.getStatusEndDate() == null) {

                            /**
                             * Service is still active (operational)
                             */
                            // if(serviceInfo.getStatus().equals())
                            return date;
                        }
                    }
                }
            }
        }
        return null;
    }

    @Override
    public Set<CertificateToken> getProcessedCertificates() {

        return Collections.unmodifiableSet(processedCertificates);
    }

    @Override
    public Set<RevocationToken> getProcessedRevocations() {

        return Collections.unmodifiableSet(processedRevocations);
    }

    @Override
    public Set<TimestampToken> getProcessedTimestamps() {

        return Collections.unmodifiableSet(processedTimestamps);
    }

    @Override
    public List<TimestampToken> getContentTimestamps() {
        return Collections.unmodifiableList(contentTimestamps);
    }

    @Override
    public List<TimestampToken> getTimestampTokens() {

        return Collections.unmodifiableList(signatureTimestamps);
    }

    @Override
    public List<TimestampToken> getSigAndRefsTimestamps() {

        return Collections.unmodifiableList(sigAndRefsTimestamps);
    }

    @Override
    public List<TimestampToken> getRefsOnlyTimestamps() {

        return Collections.unmodifiableList(refsOnlyTimestamps);
    }

    @Override
    public List<TimestampToken> getArchiveTimestamps() {

        return Collections.unmodifiableList(archiveTimestamps);
    }

    /**
     * Returns certificate and revocation references.
     *
     * @return
     */
    public List<TimestampReference> getTimestampedReferences() {
        return timestampedReferences;
    }

    /**
     * This method returns the human readable representation of the ValidationContext.
     *
     * @param indentStr
     * @return
     */

    public String toString(String indentStr) {

        try {

            final StringBuilder builder = new StringBuilder();
            builder.append(indentStr).append("ValidationContext[").append('\n');
            indentStr += "\t";
            // builder.append(indentStr).append("Validation time:").append(validationDate).append('\n');
            builder.append(indentStr).append("Certificates[").append('\n');
            indentStr += "\t";
            for (CertificateToken certToken : processedCertificates) {

                builder.append(certToken.toString(indentStr));
            }
            indentStr = indentStr.substring(1);
            builder.append(indentStr).append("],\n");
            indentStr = indentStr.substring(1);
            builder.append(indentStr).append("],\n");
            return builder.toString();
        } catch (Exception e) {

            return super.toString();
        }
    }

    @Override
    public String toString() {

        return toString("");
    }
}
