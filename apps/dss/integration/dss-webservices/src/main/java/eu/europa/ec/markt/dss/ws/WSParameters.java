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

package eu.europa.ec.markt.dss.ws;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.DSSReference;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;

/**
 * Representation of a <i>SignedProperties</i> Element.
 *
 * @version $Revision: 3797 $ - $Date: 2014-04-24 21:42:30 +0200 (Thu, 24 Apr 2014) $
 */

public class WSParameters {

	/**
	 * {@code SignatureLevel}
	 */
	private SignatureLevel signatureLevel; // ok

	private SignaturePackaging signaturePackaging; // ok

	/**
	 * The encryption algorithm shall be automatically extracted from the signing token.
	 */
	private EncryptionAlgorithm encryptionAlgorithm; // ok

	/**
	 * XAdES: The digest algorithm used to hash ds:SignedInfo.
	 */
	private DigestAlgorithm digestAlgorithm; // ok

	private String deterministicId; // ok

	private Date signingDate; // ok

	private byte[] signingCertificateBytes; // ok

	private List<byte[]> certificateChainByteArrayList = new ArrayList<byte[]>(); // ok

	private BLevelParameters.Policy signaturePolicy; // ok

	private DigestAlgorithm signingCertificateDigestAlgorithm = DigestAlgorithm.SHA1; // ok

	private List<String> claimedSignerRole; // ok

	private List<String> certifiedSignerRoles; // ok

	private String contentIdentifierPrefix; // ok
	private String contentIdentifierSuffix; // ok

	private List<String> commitmentTypeIndication; // ok
	private BLevelParameters.SignerLocation signerLocation; // ok

	private DigestAlgorithm timestampDigestAlgorithm; // ok

	private List<DSSReference> references;


	/**
	 * @return
	 */
	public SignatureLevel getSignatureLevel() {
		return signatureLevel;
	}

	/**
	 * @param signatureLevel
	 */
	public void setSignatureLevel(final SignatureLevel signatureLevel) {
		this.signatureLevel = signatureLevel;
	}

	/**
	 * @return
	 */
	public SignaturePackaging getSignaturePackaging() {
		return signaturePackaging;
	}

	/**
	 * @param signaturePackaging
	 */
	public void setSignaturePackaging(final SignaturePackaging signaturePackaging) {
		this.signaturePackaging = signaturePackaging;
	}

	/**
	 * @return
	 */
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return encryptionAlgorithm;
	}

	/**
	 * @param encryptionAlgorithm
	 */
	public void setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
		this.encryptionAlgorithm = encryptionAlgorithm;
	}

	/**
	 * @return
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	/**
	 * @param digestAlgorithm
	 */
	public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}

	/**
	 * @return
	 */
	public String getDeterministicId() {
		return deterministicId;
	}

	/**
	 * @param deterministicId
	 */
	public void setDeterministicId(String deterministicId) {
		this.deterministicId = deterministicId;
	}

	/**
	 * @return
	 */
	public Date getSigningDate() {
		return signingDate;
	}

	/**
	 * @param signingDate
	 */
	public void setSigningDate(final Date signingDate) {
		this.signingDate = signingDate;
	}

	/**
	 * @return
	 */
	public byte[] getSigningCertificateBytes() {
		return signingCertificateBytes;
	}

	/**
	 * @param signingCertificateBytes
	 */
	public void setSigningCertificateBytes(final byte[] signingCertificateBytes) {
		this.signingCertificateBytes = signingCertificateBytes;
	}

	/**
	 * @return
	 */
	public List<byte[]> getCertificateChainByteArrayList() {
		return certificateChainByteArrayList;
	}

	/**
	 * @param certificateChainByteArrayList
	 */
	public void setCertificateChainByteArrayList(final List<byte[]> certificateChainByteArrayList) {
		this.certificateChainByteArrayList = certificateChainByteArrayList;
	}

	/**
	 * @return
	 */
	public BLevelParameters.Policy getSignaturePolicy() {
		return signaturePolicy;
	}

	/**
	 * @param signaturePolicy
	 */
	public void setSignaturePolicy(final BLevelParameters.Policy signaturePolicy) {
		this.signaturePolicy = signaturePolicy;
	}

	public DigestAlgorithm getSigningCertificateDigestAlgorithm() {
		return signingCertificateDigestAlgorithm;
	}

	public void setSigningCertificateDigestAlgorithm(DigestAlgorithm signingCertificateDigestAlgorithm) {
		this.signingCertificateDigestAlgorithm = signingCertificateDigestAlgorithm;
	}

	public List<String> getClaimedSignerRole() {
		return claimedSignerRole;
	}

	public void setClaimedSignerRole(List<String> claimedSignerRole) {
		this.claimedSignerRole = claimedSignerRole;
	}

	public List<String> getCertifiedSignerRoles() {
		return certifiedSignerRoles;
	}

	public void setCertifiedSignerRoles(List<String> certifiedSignerRoles) {
		this.certifiedSignerRoles = certifiedSignerRoles;
	}

	public String getContentIdentifierPrefix() {
		return contentIdentifierPrefix;
	}

	public void setContentIdentifierPrefix(String contentIdentifierPrefix) {
		this.contentIdentifierPrefix = contentIdentifierPrefix;
	}

	public String getContentIdentifierSuffix() {
		return contentIdentifierSuffix;
	}

	public void setContentIdentifierSuffix(String contentIdentifierSuffix) {
		this.contentIdentifierSuffix = contentIdentifierSuffix;
	}

	public List<String> getCommitmentTypeIndication() {
		return commitmentTypeIndication;
	}

	public void setCommitmentTypeIndication(List<String> commitmentTypeIndication) {
		this.commitmentTypeIndication = commitmentTypeIndication;
	}

	public BLevelParameters.SignerLocation getSignerLocation() {
		return signerLocation;
	}

	public void setSignerLocation(BLevelParameters.SignerLocation signerLocation) {
		this.signerLocation = signerLocation;
	}

	public DigestAlgorithm getTimestampDigestAlgorithm() {
		return timestampDigestAlgorithm;
	}

	public void setTimestampDigestAlgorithm(DigestAlgorithm timestampDigestAlgorithm) {
		this.timestampDigestAlgorithm = timestampDigestAlgorithm;
	}

	public List<DSSReference> getReferences() {
		return references;
	}

	public void setReferences(List<DSSReference> references) {

		// System.out.println("@@@@@@@@@@@@@@@@@@ " + references);
		this.references = references;
	}
}