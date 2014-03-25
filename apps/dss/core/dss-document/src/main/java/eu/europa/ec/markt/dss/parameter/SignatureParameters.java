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

package eu.europa.ec.markt.dss.parameter;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignature;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.ProfileParameters;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;

/**
 * Parameters for a Signature creation/extension
 *
 * @version $Revision: 2686 $ - $Date: 2013-10-02 14:02:33 +0200 (Wed, 02 Oct 2013) $
 */

public class SignatureParameters {

    /**
     * This parameter is used in one shot signature process. Cannot be used with 3-steps signature process.
     */
    private SignatureTokenConnection signingToken;

    /**
     * This parameter is used in one shot signature process. Cannot be used with 3-steps signature process.
     */
    private DSSPrivateKeyEntry privateKeyEntry;

    /**
     * This field contains the signing certificate.
     */
    private X509Certificate signingCertificate;

    /**
     * This field contains the chain of certificates. It includes the signing certificate.
     */
    private List<X509Certificate> certificateChain = new ArrayList<X509Certificate>();

    ProfileParameters context;
    private SignatureLevel signatureLevel;
    private SignaturePackaging signaturePackaging;

    /**
     * The default signature form to use within the ASiC containers.
     */
    private SignatureForm asicSignatureForm = SignatureForm.XAdES;

    /**
     * XAdES: The ds:SignatureMethod indicates the algorithms used to sign ds:SignedInfo.
     */
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSA_SHA256;

    /**
     * The encryption algorithm shall be automatically extracted from the signing token.
     */
    private EncryptionAlgorithm encryptionAlgorithm = signatureAlgorithm.getEncryptionAlgo();

    /**
     * XAdES: The digest algorithm used to hash ds:SignedInfo.
     */
    private DigestAlgorithm digestAlgorithm = signatureAlgorithm.getDigestAlgo();
    private List<DSSReference> references;

    /**
     * The object representing the parameters related to B- level.
     */
    private BLevelParameters bLevelParams = new BLevelParameters();

    private boolean asicComment = false;

    private String reason;
    private String contactInfo;
    private String deterministicId;

    private DigestAlgorithm timestampDigestAlgorithm = DigestAlgorithm.SHA256;
    private DigestAlgorithm archiveTimestampDigestAlgorithm = DigestAlgorithm.SHA256;

    public SignatureParameters() {

    }

    private DSSDocument originalDocument;

    /**
     * Copy constructor (used by ASiC)
     */
    public SignatureParameters(final SignatureParameters source) {

        if (source == null) {

            throw new DSSNullException(SignatureParameters.class);
        }
        bLevelParams = new BLevelParameters(source.bLevelParams);
        asicComment = source.asicComment;
        asicSignatureForm = source.asicSignatureForm;

        if (certificateChain != null) {

            certificateChain = new ArrayList<X509Certificate>(source.certificateChain);
        }
        contactInfo = source.contactInfo;
        deterministicId = source.getDeterministicId();
        digestAlgorithm = source.digestAlgorithm;
        encryptionAlgorithm = source.encryptionAlgorithm;
        originalDocument = source.originalDocument;
        privateKeyEntry = source.privateKeyEntry;
        reason = source.reason;
        signatureAlgorithm = source.signatureAlgorithm;
        signaturePackaging = source.signaturePackaging;
        signatureLevel = source.signatureLevel;
        signingToken = source.signingToken;
        signingCertificate = source.signingCertificate;
        signingToken = source.signingToken;
        timestampDigestAlgorithm = source.timestampDigestAlgorithm;
        // This is a simple copy of reference and not of the object content!
        context = source.context;
    }

    public boolean isAsicComment() {
        return asicComment;
    }

    public void setAsicComment(final boolean asicComment) {
        this.asicComment = asicComment;
    }

    public SignatureForm getAsicSignatureForm() {
        return asicSignatureForm;
    }

    /**
     * Sets the signature form associated with an ASiC container. Only two forms are acceptable: XAdES and CAdES.
     *
     * @param asicSignatureForm signature form to associate with the ASiC container.
     */
    public void setAsicSignatureForm(final SignatureForm asicSignatureForm) {
        this.asicSignatureForm = asicSignatureForm;
    }

    public DSSDocument getOriginalDocument() {
        return originalDocument;
    }

    /**
     * This is the document to sign. In the case of the DETACHED signature this is detached  document.
     *
     * @param document
     */
    public void setOriginalDocument(final DSSDocument document) {
        this.originalDocument = document;
    }

    /**
     * XAdES: The ID of xades:SignedProperties is contained in the signed content of the xades Signature. We must create this ID in a deterministic way.
     *
     * @return
     */
    public String getDeterministicId() {

        if (deterministicId != null) {

            return deterministicId;
        }
        final int dssId = signingCertificate == null ? 0 : CertificateIdentifier.getId(signingCertificate);
        deterministicId = DSSUtils.getDeterministicId(bLevelParams.getSigningDate(), dssId);
        return deterministicId;
    }

    /**
     * This method allows to set the XAdES signature id. Be careful, if you change this id between the call to eu.europa.ec.markt.dss.signature.xades.XAdESService#toBeSigned(eu
     * .europa.ec.markt.dss.signature.DSSDocument, eu.europa.ec.markt.dss.parameter.SignatureParameters) and eu.europa.ec.markt.dss.signature.xades.XAdESService#signDocument(eu
     * .europa.ec.markt.dss.signature.DSSDocument, eu.europa.ec.markt.dss.parameter.SignatureParameters, byte[]) the created signature will be corrupted.
     *
     * @param deterministicId
     */
    public void setDeterministicId(final String deterministicId) {

        this.deterministicId = deterministicId;
    }

    public ProfileParameters getContext() {
        if (context == null) {
            context = new ProfileParameters();
        }
        return context;
    }

    /**
     * Get the signing certificate
     *
     * @return the value
     */
    public X509Certificate getSigningCertificate() {
        return signingCertificate;
    }

    /**
     * Set the signing certificate. If this certificate is not a part of the certificate chain then it's added as the first one of the chain.
     *
     * @param signingCertificate the value
     */
    public void setSigningCertificate(final X509Certificate signingCertificate) {

        this.signingCertificate = signingCertificate;
        if (!this.certificateChain.contains(signingCertificate)) {

            this.certificateChain.add(0, signingCertificate);
        }
    }

    /**
     * Set the certificate chain
     *
     * @return the value
     */
    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    /**
     * Set the certificate chain
     *
     * @param certificateChain the value
     */
    public void setCertificateChain(final List<X509Certificate> certificateChain) {
        this.certificateChain = certificateChain;
    }

    /**
     * This method sets the list of certificates which constitute the chain. If the certificate is already present in the array then it is ignored.
     *
     * @param certificateChainArray the array containing all certificates composing the chain
     */
    public void setCertificateChain(final X509Certificate... certificateChainArray) {

        if (certificateChainArray == null) {
            return;
        }
        for (final X509Certificate certificate : certificateChainArray) {

            if (!certificateChain.contains(certificate)) {
                certificateChain.add(certificate);
            }
        }
    }

    /**
     * This method sets the private key entry used to create the signature. Note that the certificate chain is reset, the encryption algorithm is set and the signature algorithm
     * is updated.
     *
     * @param privateKeyEntry the private key entry used to sign?
     */
    public void setPrivateKeyEntry(final DSSPrivateKeyEntry privateKeyEntry) {

        this.privateKeyEntry = privateKeyEntry;
        // When the private key entry is set the certificate chain is reset
        certificateChain.clear();
        setSigningCertificate(privateKeyEntry.getCertificate());
        setCertificateChain(privateKeyEntry.getCertificateChain());
        final String encryptionAlgoName = this.signingCertificate.getPublicKey().getAlgorithm();
        this.encryptionAlgorithm = EncryptionAlgorithm.forName(encryptionAlgoName);
        this.signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm);
    }

    /**
     * Returns the private key entry
     *
     * @return the value
     */
    public DSSPrivateKeyEntry getPrivateKeyEntry() {
        return privateKeyEntry;
    }

    /**
     * Returns the connection through available API to the SSCD (SmartCard, MSCAPI, PKCS#12)
     *
     * @return the value
     */
    public SignatureTokenConnection getSigningToken() {
        return signingToken;
    }

    /**
     * Sets the connection through available API to the SSCD (SmartCard, MSCAPI, PKCS#12)
     *
     * @param signingToken the value
     */
    public void setSigningToken(final SignatureTokenConnection signingToken) {
        this.signingToken = signingToken;
    }

    /**
     * Get signature format: XAdES_BES, XAdES_EPES, XAdES_BASELINE_T ../.. CAdES_BES...
     *
     * @return the value
     */
    public SignatureLevel getSignatureLevel() {
        return signatureLevel;
    }

    /**
     * Set signature level
     *
     * @param signatureLevel the value
     * @deprecated Use the {@link eu.europa.ec.markt.dss.signature.SignatureLevel} enumeration instead
     */
    @Deprecated
    public void setSignatureProfile(final String signatureLevel) {
        setSignatureLevel(SignatureLevel.valueByName(signatureLevel));
    }

    /**
     * Set signature level
     *
     * @param signatureLevel the value
     */
    public void setSignatureLevel(final SignatureLevel signatureLevel) {
        this.signatureLevel = signatureLevel;
    }

    /**
     * Get Signature packaging
     *
     * @return the value
     */
    public SignaturePackaging getSignaturePackaging() {
        return signaturePackaging;
    }

    /**
     * Set Signature packaging
     *
     * @param signaturePackaging the value
     */
    public void setSignaturePackaging(SignaturePackaging signaturePackaging) {
        this.signaturePackaging = signaturePackaging;
    }

    /**
     * @return the digest algorithm
     */
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * @param digestAlgorithm the digest algorithm to set
     */
    public void setDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {

        this.digestAlgorithm = digestAlgorithm;
        if (this.digestAlgorithm != null && this.encryptionAlgorithm != null) {

            signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm);
        }
    }

    /**
     * @return the encryption algorithm. It's determined by the privateKeyEntry and is null until the privateKeyEntry is set.
     */
    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    /**
     * Gets the signature algorithm.
     *
     * @return the value
     */
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public List<DSSReference> getReferences() {

        if (references == null) {

            references = new ArrayList<DSSReference>();

            DSSReference dssReference = new DSSReference();
            dssReference.setId("xml_ref_id");
            dssReference.setUri("");
            /// dssReference.setType("");

            final List<DSSTransform> transforms = dssReference.getTransforms();

            DSSTransform dssTransform = new DSSTransform();
            dssTransform.setAlgorithm(CanonicalizationMethod.ENVELOPED);
            transforms.add(dssTransform);

            dssTransform = new DSSTransform();
            dssTransform.setAlgorithm(CanonicalizationMethod.EXCLUSIVE);
            transforms.add(dssTransform);

            // For double signatures
            dssTransform = new DSSTransform();
            dssTransform.setAlgorithm("http://www.w3.org/TR/1999/REC-xpath-19991116");
            dssTransform.setElementName("ds:XPath");
            // TODO: (Bob: 2014 Feb 18) xPathQueryHolder.XMLDSIG_NAMESPACE
            dssTransform.setNamespace(XMLSignature.XMLNS);
            dssTransform.setTextContent("not(ancestor-or-self::ds:Signature)");
            transforms.add(dssTransform);

            references.add(dssReference);
        }
        return references;
    }

    public void setReferences(List<DSSReference> references) {
        this.references = references;
    }

    /**
     * @return the reason (used by PAdES)
     */
    public String getReason() {
        return reason;
    }

    /**
     * @param reason the reason to set (used by PAdES)
     */
    public void setReason(final String reason) {
        this.reason = reason;
    }

    /**
     * @return the contactInfo (used by PAdES)
     */
    public String getContactInfo() {
        return contactInfo;
    }

    /**
     * @param contactInfo the contactInfo to set (used by PAdES)
     */
    public void setContactInfo(final String contactInfo) {
        this.contactInfo = contactInfo;
    }

    public BLevelParameters bLevel() {

        return bLevelParams;
    }

    public DigestAlgorithm getTimestampDigestAlgorithm() {
        return timestampDigestAlgorithm;
    }

    public void setTimestampDigestAlgorithm(final DigestAlgorithm timestampDigestAlgorithm) {
        this.timestampDigestAlgorithm = timestampDigestAlgorithm;
    }
}
