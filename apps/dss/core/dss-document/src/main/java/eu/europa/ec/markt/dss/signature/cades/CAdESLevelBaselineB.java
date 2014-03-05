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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Random;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;
import org.bouncycastle.asn1.esf.SignerAttribute;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.asn1.ess.ContentIdentifier;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.OID;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.BLevelParameters.Policy;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.MimeType;

/**
 * This class holds the CAdES-B signature profile; it supports the inclusion of the mandatory signed
 * id_aa_ets_sigPolicyId attribute as specified in ETSI TS 101 733 V1.8.1, clause 5.8.1.
 * <p/>
 *
 * @version $Revision: 3515 $ - $Date: 2014-02-26 07:19:34 +0100 (Wed, 26 Feb 2014) $
 */
public class CAdESLevelBaselineB {

    private static final Logger LOG = LoggerFactory.getLogger(CAdESLevelBaselineB.class);

    private final boolean padesUsage;

    /**
     * The default constructor for CAdESLevelBaselineB.
     */
    public CAdESLevelBaselineB() {
        this(false);
    }

    /**
     * The default constructor for CAdESLevelBaselineB.
     */
    public CAdESLevelBaselineB(boolean padesUsage) {

        this.padesUsage = padesUsage;
    }

    /**
     * Return the table of unsigned properties.
     *
     * @param document
     * @param parameters
     * @return
     */
    public AttributeTable getUnsignedAttributes(DSSDocument document, SignatureParameters parameters) {
        return new AttributeTable(new Hashtable<ASN1ObjectIdentifier, ASN1Encodable>());
    }

    public AttributeTable getSignedAttributes(DSSDocument document, SignatureParameters parameters) {
        AttributeTable signedAttributes = new AttributeTable(new Hashtable<ASN1ObjectIdentifier, ASN1Encodable>());
        signedAttributes = addSigningCertificateAttribute(parameters, signedAttributes);
        signedAttributes = addSigningTimeAttribute(parameters, signedAttributes);
        signedAttributes = addSignerAttribute(parameters, signedAttributes);
        signedAttributes = addSignaturePolicyId(parameters, signedAttributes);
        signedAttributes = addContentIdentifier(parameters, signedAttributes);
        signedAttributes = addCommitmentType(parameters, signedAttributes);
        signedAttributes = addSignerLocation(parameters, signedAttributes);

        // mime-type attribute breaks parallels signature by adding PKCS7 as a mime-type for subsequent signers.
        // attribute is not mandatory, so it has been disabled.
        // signedAttributes = addMimeType(document, signedAttributes);
        return signedAttributes;
    }

    /**
     * 5.11.5 mime-type Attribute
     * <p/>
     * The mime-type attribute is an attribute that lets the signature generator indicate the mime-type of the signed data. It
     * is similar in spirit to the contentDescription field of the content-hints attribute, but can be used without a multilayered
     * document.
     * <p/>
     * The mime-type attribute shall be a signed attribute.
     * <p/>
     * The following object identifier identifies the mime-type attribute:
     * id-aa-ets-mimeType OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0) electronicsignature-
     * standard (1733) attributes(2) 1 }
     * <p/>
     * mime-type attribute values have ASN.1 type UTF8String:
     * <p/>
     * mimeType::= UTF8String
     * <p/>
     * The mimeType is used to indicate the encoding of the signed data, in accordance with the rules defined in
     * RFC 2045 [6]; see annex F for an example of structured contents and MIME.
     * Only a single mime-type attribute shall be present.
     * <p/>
     * The mime-type attribute shall not be used within a countersignature.
     *
     * @param document
     * @param signedAttributes
     */
    private AttributeTable addMimeType(DSSDocument document, AttributeTable signedAttributes) {

        if (!padesUsage) {
            final MimeType mimeType = document.getMimeType();
            if (mimeType != null && DSSUtils.isNotBlank(mimeType.getCode())) {

                signedAttributes = signedAttributes.add(OID.id_aa_ets_mimeType, new DERUTF8String(mimeType.getCode()));

            }
        }
        return signedAttributes;
    }

    /**
     * ETSI TS 101 733 V2.2.1 (2013-04)
     * 5.11.3 signer-attributes Attribute
     * NOTE 1: Only a single signer-attributes can be used.
     *
     * The signer-attributes attribute specifies additional attributes of the signer (e.g. role).
     * It may be either:
     * • claimed attributes of the signer; or
     * • certified attributes of the signer.
     * The signer-attributes attribute shall be a signed attribute.
     *
     * @param parameters
     * @param signedAttributes
     * @return
     */
    private AttributeTable addSignerAttribute(SignatureParameters parameters, AttributeTable signedAttributes) {
        // In PAdES, the role is in the signature dictionary
        if (!padesUsage) {

            final List<String> claimedSignerRoles = parameters.bLevel().getClaimedSignerRoles();
            if (claimedSignerRoles != null) {

                List<Attribute> claimedAttributes = new ArrayList<Attribute>(claimedSignerRoles.size());
                for (final String claimedSignerRole : claimedSignerRoles) {

                    final DERUTF8String roles = new DERUTF8String(claimedSignerRole);

                    //TODO: role attribute key (id_at_name) should be customizable
                    final Attribute id_aa_ets_signerAttr = new Attribute(X509ObjectIdentifiers.id_at_name, new DERSet(roles));
                    claimedAttributes.add(id_aa_ets_signerAttr);
                }
                signedAttributes = signedAttributes
                      .add(PKCSObjectIdentifiers.id_aa_ets_signerAttr, new SignerAttribute(claimedAttributes.toArray(new Attribute[claimedAttributes.size()])));
            }

            //TODO: hendle CertifiedAttributes ::= AttributeCertificate -- as defined in RFC 3281: see clause 4.1.
            // final List<String> certifiedSignerRoles = parameters.bLevel().getCertifiedSignerRoles();
        }
        return signedAttributes;
    }

    private AttributeTable addSigningTimeAttribute(SignatureParameters parameters, AttributeTable signedAttributes) {
        if (!padesUsage) {
            /*
             * In PAdES, we don't include the signing time : ETSI TS 102 778-3 V1.2.1 (2010-07): 4.5.3 signing-time
             * Attribute
             */
            final Date signingDate = parameters.bLevel().getSigningDate();
            if (signingDate != null) {
                signedAttributes = signedAttributes.add(PKCSObjectIdentifiers.pkcs_9_at_signingTime, new Time(signingDate));
            }
        }
        return signedAttributes;
    }

    /**
     * ETSI TS 101 733 V2.2.1 (2013-04)
     * 5.11.2 signer-location Attribute
     * The signer-location attribute specifies a mnemonic for an address associated with the signer at a particular
     * geographical (e.g. city) location. The mnemonic is registered in the country in which the signer is located and is used in
     * the provision of the Public Telegram Service (according to Recommendation ITU-T F.1 [11]).
     * The signer-location attribute shall be a signed attribute.
     *
     * @param parameters
     * @param signedAttributes
     * @return
     */
    private AttributeTable addSignerLocation(SignatureParameters parameters, AttributeTable signedAttributes) {
        if (!padesUsage) {
            /*
             * In PAdES, the role is in the signature dictionary
             */
            final BLevelParameters.SignerLocation signerLocationParameter = parameters.bLevel().getSignerLocation();
            if (signerLocationParameter != null) {

                final DERUTF8String country = new DERUTF8String(signerLocationParameter.getCountry());
                final DERUTF8String locality = new DERUTF8String(signerLocationParameter.getLocality());
                final ASN1EncodableVector postalAddress = new ASN1EncodableVector();
                final List<String> postalAddressParameter = signerLocationParameter.getPostalAddress();
                if (postalAddressParameter != null) {

                    for (final String addressLine : postalAddressParameter) {

                        postalAddress.add(new DERUTF8String(addressLine));
                    }
                }
                final DERSequence derSequencePostalAddress = new DERSequence(postalAddress);
                SignerLocation signerLocation = new SignerLocation(country, locality, derSequencePostalAddress);
                signedAttributes = signedAttributes.add(PKCSObjectIdentifiers.id_aa_ets_signerLocation, signerLocation);
            }
        }
        return signedAttributes;
    }

    /**
     * ETSI TS 101 733 V2.2.1 (2013-04)
     * <p/>
     * 5.11.1 commitment-type-indication Attribute
     * There may be situations where a signer wants to explicitly indicate to a verifier that by signing the data, it illustrates a
     * type of commitment on behalf of the signer. The commitment-type-indication attribute conveys such
     * information.
     *
     * @param parameters
     * @param signedAttributes
     */
    private AttributeTable addCommitmentType(SignatureParameters parameters, AttributeTable signedAttributes) {
        // commitmentTypeQualifier are not implemented
        final BLevelParameters bLevelParameters = parameters.bLevel();

        if (bLevelParameters.getCommitmentTypeIndications() != null && !bLevelParameters.getCommitmentTypeIndications().isEmpty()) {

            ASN1EncodableVector vector = new ASN1EncodableVector();
            for (String commitmentTypeId : bLevelParameters.getCommitmentTypeIndications()) {
                vector.add(CommitmentTypeIndication.getInstance(new ASN1ObjectIdentifier(commitmentTypeId)));
            }
            signedAttributes = signedAttributes.add(PKCSObjectIdentifiers.id_aa_ets_commitmentType, new DERSequence(vector));
        }
        return signedAttributes;
    }

    /**
     * ETSI TS 101 733 V2.2.1 (2013-04)
     * <p/>
     * 5.10.2 content-identifier Attribute
     * The content-identifier attribute provides an identifier for the signed content, for use when a reference may be
     * later required to that content; for example, in the content-reference attribute in other signed data sent later. The
     * content-identifier shall be a signed attribute.
     * content-identifier attribute type values for the ES have an ASN.1 type ContentIdentifier, as defined in
     * ESS (RFC 2634 [5]).
     * <p/>
     * The minimal content-identifier attribute should contain a concatenation of user-specific identification
     * information (such as a user name or public keying material identification information), a GeneralizedTime string,
     * and a random number.
     *
     * @param parameters
     * @param signedAttributes
     */
    private AttributeTable addContentIdentifier(SignatureParameters parameters, AttributeTable signedAttributes) {
        /* this attribute is prohibited in PAdES B */
        if (!padesUsage) {
            final String contentIdentifierPrefix = parameters.bLevel().getContentIdentifierPrefix();
            if (DSSUtils.isNotBlank(contentIdentifierPrefix)) {
                final String contentIdentifierSuffix;
                if (DSSUtils.isBlank(parameters.bLevel().getContentIdentifierSuffix())) {
                    final Date now = new Date();
                    final String asn1GeneralizedTimeString = new ASN1GeneralizedTime(now).getTimeString();
                    final long randomNumber = new Random(now.getTime()).nextLong();
                    contentIdentifierSuffix = asn1GeneralizedTimeString + randomNumber;
                    parameters.bLevel().setContentIdentifierSuffix(contentIdentifierSuffix);
                } else {
                    contentIdentifierSuffix = parameters.bLevel().getContentIdentifierSuffix();
                }
                final String contentIdentifierString = contentIdentifierPrefix + contentIdentifierSuffix;
                ContentIdentifier contentIdentifier = new ContentIdentifier(contentIdentifierString.getBytes());
                signedAttributes = signedAttributes.add(PKCSObjectIdentifiers.id_aa_contentIdentifier, contentIdentifier);
            }
        }
        return signedAttributes;
    }

    private AttributeTable addSignaturePolicyId(final SignatureParameters parameters, AttributeTable signedAttributes) {

        Policy policy = parameters.bLevel().getSignaturePolicy();
        if (policy != null && policy.getId() != null) {

            final String policyId = policy.getId();
            SignaturePolicyIdentifier sigPolicy = null;
            if (!"".equals(policyId)) { // explicit

                final ASN1ObjectIdentifier derOIPolicyId = new ASN1ObjectIdentifier(policyId);
                final ASN1ObjectIdentifier oid = policy.getDigestAlgorithm().getOid();
                final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(oid);
                OtherHashAlgAndValue otherHashAlgAndValue = new OtherHashAlgAndValue(algorithmIdentifier, new DEROctetString(policy.getDigestValue()));
                sigPolicy = new SignaturePolicyIdentifier(new SignaturePolicyId(derOIPolicyId, otherHashAlgAndValue));
            } else {// implicit
                sigPolicy = new SignaturePolicyIdentifier();
            }
            signedAttributes = signedAttributes.add(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId, sigPolicy);
        }
        return signedAttributes;
    }

    private AttributeTable addSigningCertificateAttribute(final SignatureParameters parameters, AttributeTable signedAttributes) throws DSSException {

        final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
        final X509Certificate signingCertificate = parameters.getSigningCertificate();
        final byte[] encoded = DSSUtils.getEncoded(signingCertificate);
        final byte[] certHash = DSSUtils.digest(digestAlgorithm, encoded);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Adding Certificate Hash {} with algorithm {}", Hex.encodeHexString(certHash), digestAlgorithm.getName());
        }
        final IssuerSerial issuerSerial = DSSUtils.getIssuerSerial(signingCertificate);
        if (digestAlgorithm == DigestAlgorithm.SHA1) {

            final ESSCertID essCertId = new ESSCertID(certHash, issuerSerial);
            final SigningCertificate cadesSigningCertificate = new SigningCertificate(essCertId);
            signedAttributes = signedAttributes.add(PKCSObjectIdentifiers.id_aa_signingCertificate, cadesSigningCertificate);
        } else {

            final ESSCertIDv2 essCertIDv2 = new ESSCertIDv2(digestAlgorithm.getAlgorithmIdentifier(), certHash, issuerSerial);
            final ESSCertIDv2[] essCertIDv2Array = new ESSCertIDv2[]{essCertIDv2};
            final SigningCertificateV2 cadesSigningCertificateV2 = new SigningCertificateV2(essCertIDv2Array);
            signedAttributes = signedAttributes.add(PKCSObjectIdentifiers.id_aa_signingCertificateV2, cadesSigningCertificateV2);
        }
        return signedAttributes;
    }

}
