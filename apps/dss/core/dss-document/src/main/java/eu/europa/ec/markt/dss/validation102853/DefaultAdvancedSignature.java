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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import eu.europa.ec.markt.dss.DSSRevocationUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.validation102853.crl.CRLToken;
import eu.europa.ec.markt.dss.validation102853.crl.OfflineCRLSource;
import eu.europa.ec.markt.dss.validation102853.ocsp.OfflineOCSPSource;
import eu.europa.ec.markt.dss.validation102853.bean.SigningCertificateValidity;

/**
 * TODO <p/> <p/> DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public abstract class DefaultAdvancedSignature implements AdvancedSignature {

	protected static int signatureCounter = 0;

	/**
	 * The reference to the signing certificate object. If the signing certificate is an input provided by the DA then getSigningCert MUST be called.
	 */
	protected SigningCertificateValidity signingCertificateValidity;
	/**
	 * This list contains the detail information collected during the check. It is reset for each call of {@code isDataForSignatureLevelPresent}
	 */
	protected List<String> info;

	/**
	 * This variable contains the list of archive signature timestamps.
	 */
	protected List<TimestampToken> archiveTimestamps;

	/**
	 * @return the upper level for which data have been found. Doesn't mean any validity of the data found. Null if unknown.
	 */
	@Override
	public SignatureLevel getDataFoundUpToLevel() {
		final SignatureLevel[] signatureLevels = getSignatureLevels();
		final SignatureLevel dataFoundUpToProfile = getDataFoundUpToProfile(signatureLevels);
		return dataFoundUpToProfile;
	}

	private SignatureLevel getDataFoundUpToProfile(SignatureLevel... signatureLevels) {

		for (int ii = signatureLevels.length - 1; ii >= 0; ii--) {

			final SignatureLevel signatureLevel = signatureLevels[ii];
			if (isDataForSignatureLevelPresent(signatureLevel)) {
				return signatureLevel;
			}
		}
		return null;
	}

	/**
	 * This method validates the signing certificate and all timestamps.
	 *
	 * @return signature validation context containing all certificates and revocation data used during the validation process.
	 */
	public SignatureValidationContext getSignatureValidationContext(final CertificateVerifier certificateVerifier) {

		final CertificatePool validationPool = SignedDocumentValidator.createValidationPool(certificateVerifier);
		final SignatureValidationContext validationContext = new SignatureValidationContext(this, certificateVerifier, validationPool);
		final CertificateToken signingCertificateToken = getSigningCertificateToken();
		validationContext.setCertificateToValidate(signingCertificateToken);
		validationContext.validate();
		return validationContext;
	}

	/**
	 * This method returns all certificates used during the validation process. If a certificate is already present within the signature then it is ignored.
	 *
	 * @param validationContext validation context containing all information about the validation process of the signing certificate and time-stamps
	 * @return set of certificates not yet present within the signature
	 */
	public Set<CertificateToken> getCertificatesForInclusion(final SignatureValidationContext validationContext) {

		final Set<CertificateToken> certificates = new HashSet<CertificateToken>();
		final List<CertificateToken> certWithinSignatures = getCertificatesWithinSignatureAndTimestamps();
		for (final CertificateToken certificateToken : validationContext.getProcessedCertificates()) {
			if (certWithinSignatures.contains(certificateToken)) {
				continue;
			}
			certificates.add(certificateToken);
		}
		return certificates;
	}

	public List<CertificateToken> getCertificatesWithinSignatureAndTimestamps() {
		final List<CertificateToken> certWithinSignatures = new ArrayList<CertificateToken>();
		certWithinSignatures.addAll(getCertificates());
		//TODO (2013-12-11 Nicolas -> Bob): Create a convenient method to get all the timestamptokens // to get all the certificates
		for (final TimestampToken timestampToken : getSignatureTimestamps()) {
			certWithinSignatures.addAll(timestampToken.getCertificates());
		}
		for (final TimestampToken timestampToken : getArchiveTimestamps()) {
			certWithinSignatures.addAll(timestampToken.getCertificates());
		}
		for (final TimestampToken timestampToken : getContentTimestamps()) {
			certWithinSignatures.addAll(timestampToken.getCertificates());
		}
		for (final TimestampToken timestampToken : getTimestampsX1()) {
			certWithinSignatures.addAll(timestampToken.getCertificates());
		}
		for (final TimestampToken timestampToken : getTimestampsX2()) {
			certWithinSignatures.addAll(timestampToken.getCertificates());
		}
		return certWithinSignatures;
	}

	/**
	 * This method returns revocation values (ocsp and crl) that will be included in the LT profile
	 *
	 * @param validationContext
	 * @return
	 */
	public RevocationDataForInclusion getRevocationDataForInclusion(final SignatureValidationContext validationContext) {

		//TODO: there can be also CRL and OCSP in TimestampToken CMS data
		final Set<RevocationToken> revocationTokens = validationContext.getProcessedRevocations();
		final OfflineCRLSource crlSource = getCRLSource();
		final List<CRLToken> containedCRLs = crlSource.getContainedCRLTokens();
		final OfflineOCSPSource ocspSource = getOCSPSource();
		final List<BasicOCSPResp> containedBasicOCSPResponses = ocspSource.getContainedOCSPResponses();
		final List<CRLToken> crlTokens = new ArrayList<CRLToken>();
		final List<OCSPToken> ocspTokens = new ArrayList<OCSPToken>();
		for (final RevocationToken revocationToken : revocationTokens) {

			if (revocationToken instanceof CRLToken) {

				final boolean tokenIn = containedCRLs.contains(revocationToken);
				if (!tokenIn) {

					final CRLToken crlToken = (CRLToken) revocationToken;
					crlTokens.add(crlToken);
				}
			} else if (revocationToken instanceof OCSPToken) {

				final boolean tokenIn = DSSRevocationUtils.isTokenIn(revocationToken, containedBasicOCSPResponses);
				if (!tokenIn) {

					final OCSPToken ocspToken = (OCSPToken) revocationToken;
					ocspTokens.add(ocspToken);
				}
			} else {
				throw new DSSException("Unknown type for revocationToken: " + revocationToken.getClass().getName());
			}
		}
		return new RevocationDataForInclusion(crlTokens, ocspTokens);
	}

	/**
	 * This list contains the detail information collected during the check. It is reset for each call.
	 *
	 * @return
	 */
	@Override
	public List<String> getInfo() {

		return Collections.unmodifiableList(info);
	}

	public static class RevocationDataForInclusion {

		public final List<CRLToken> crlTokens;
		public final List<OCSPToken> ocspTokens;

		public RevocationDataForInclusion(final List<CRLToken> crlTokens, final List<OCSPToken> ocspTokens) {

			this.crlTokens = crlTokens;
			this.ocspTokens = ocspTokens;
		}

		public boolean isEmpty() {

			return crlTokens.isEmpty() && ocspTokens.isEmpty();
		}
	}

	@Override
	public CertificateToken getSigningCertificateToken() {

		signingCertificateValidity = getSigningCertificateValidity();
		if (signingCertificateValidity.isValid()) {

			final CertificateToken signingCertificateToken = signingCertificateValidity.getCertToken();
			return signingCertificateToken;
		}
		return null;
	}
}

