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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.datatype.XMLGregorianCalendar;

import org.w3c.dom.Element;
import org.w3c.dom.Text;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;

/**
 * This class implements all the necessary mechanisms to build each form of the XML signature. <p/> <p/> DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 */
public abstract class SignatureBuilder extends XAdESBuilder {

    /*
     * Indicates if the signature was already built. (Two steps building)
     */
    protected boolean built = false;

    /*
     * This is the reference to the original document to sign
     */
    protected DSSDocument originalDocument;

    protected String signedInfoCanonicalizationMethod;
    protected String reference2CanonicalizationMethod;

    protected String deterministicId;

    /*
     * This variable represents the current DOM signature object.
     */
    protected Element signatureDom;

    protected Element signedInfoDom;
    protected Element signatureValueDom;
    protected Element qualifyingPropertiesDom;
    protected Element signedPropertiesDom;
    protected Element signedSignaturePropertiesDom;
    protected Element signedDataObjectPropertiesDom;

    /**
     * Creates the signature according to the packaging
     *
     * @param params   The set of parameters relating to the structure and process of the creation or extension of the electronic signature.
     * @param document The original document to sign.
     * @return
     */
    public static SignatureBuilder getSignatureBuilder(final SignatureParameters params, final DSSDocument document) {

        switch (params.getSignaturePackaging()) {
            case ENVELOPED:
                return new EnvelopedSignatureBuilder(params, document);
            case ENVELOPING:
                return new EnvelopingSignatureBuilder(params, document);
            case DETACHED:
                return new DetachedSignatureBuilder(params, document);
            default:

                throw new DSSException("Unsupported packaging " + params.getSignaturePackaging());
        }
    }

    /**
     * The default constructor for SignatureBuilder.
     *
     * @param params           The set of parameters relating to the structure and process of the creation or extension of the electronic signature.
     * @param originalDocument The original document to sign.
     */
    public SignatureBuilder(final SignatureParameters params, final DSSDocument originalDocument) {

        this.params = params;
        this.originalDocument = originalDocument;    }

    /**
     * This is the main method which is called to build the XML signature
     *
     * @return A byte array is returned with XML that represents the canonicalized <ds:SignedInfo> segment of signature. This data are used to define the <ds:SignatureValue>
     * element.
     * @throws DSSException
     */
    public byte[] build() throws DSSException {

        documentDom = DSSXMLUtils.buildDOM();

        deterministicId = params.getDeterministicId();

        incorporateSignatureDom();

        incorporateSignedInfo();

        incorporateSignatureValue();

        incorporateKeyInfo();

        incorporateObject();

        /**
         * We create <ds:Reference> segment only now, because we need first to define the SignedProperties segment to
         * calculate the digest of references.
         */
        incorporateReference1();
        incorporateReference2();

        // Preparation of SignedInfo
        byte[] canonicalizedSignedInfo = DSSXMLUtils.canonicalizeSubtree(signedInfoCanonicalizationMethod, signedInfoDom);
        if (LOG.isInfoEnabled()) {
            LOG.info("Canonicalized SignedInfo         -->" + new String(canonicalizedSignedInfo));
        }
        built = true;
        return canonicalizedSignedInfo;
    }

    /**
     * This method creates a new instance of Signature element.
     */
    private void incorporateSignatureDom() {

        signatureDom = documentDom.createElementNS(xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:Signature");
        signatureDom.setAttribute("xmlns:ds", xPathQueryHolder.XMLDSIG_NAMESPACE);
        signatureDom.setAttribute("Id", deterministicId);
        documentDom.appendChild(signatureDom);
    }

    private void incorporateSignedInfo() {

        // <ds:SignedInfo>
        signedInfoDom = DSSXMLUtils.addElement(documentDom, signatureDom, xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:SignedInfo");
        incorporateCanonicalizationMethod(signedInfoDom, signedInfoCanonicalizationMethod);

        //<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        final Element signatureMethod = DSSXMLUtils.addElement(documentDom, signedInfoDom, xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:SignatureMethod");
        final EncryptionAlgorithm encryptionAlgorithm = params.getEncryptionAlgorithm();
        final DigestAlgorithm digestAlgorithm = params.getDigestAlgorithm();
        final SignatureAlgorithm signatureAlgo = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm);
        final String signatureAlgoXMLId = signatureAlgo.getXMLId();
        signatureMethod.setAttribute("Algorithm", signatureAlgoXMLId);
    }

    private void incorporateCanonicalizationMethod(final Element parentDom, final String signedInfoCanonicalizationMethod) {

        //<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        final Element canonicalizationMethodDom = DSSXMLUtils.addElement(documentDom, parentDom, xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:CanonicalizationMethod");
        canonicalizationMethodDom.setAttribute("Algorithm", signedInfoCanonicalizationMethod);
    }

    protected abstract void incorporateReference1() throws DSSException;

    /**
     * Creates KeyInfoType JAXB object
     *
     * @throws DSSException
     */
    protected void incorporateKeyInfo() throws DSSException {

        // <ds:KeyInfo>
        final Element keyInfoDom = DSSXMLUtils.addElement(documentDom, signatureDom, xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:KeyInfo");
        // <ds:X509Data>
        final Element x509DataDom = DSSXMLUtils.addElement(documentDom, keyInfoDom, xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:X509Data");

        for (final X509Certificate x509Certificate : params.getCertificateChain()) {

            final byte[] encoded = DSSUtils.getEncoded(x509Certificate);
            final String base64Encoded = DSSUtils.base64Encode(encoded);
            // <ds:X509Certificate>...</ds:X509Certificate>
            DSSXMLUtils.addTextElement(documentDom, x509DataDom, xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:X509Certificate", base64Encoded);
        }
    }

    /**
     * @throws DSSException
     */
    protected void incorporateObject() throws DSSException {

        // <ds:Object>
        final Element objectDom = DSSXMLUtils.addElement(documentDom, signatureDom, xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:Object");

        // <QualifyingProperties xmlns="http://uri.etsi.org/01903/v1.3.2#" Target="#sigId-ide5c549340079fe19f3f90f03354a5965">
        qualifyingPropertiesDom = DSSXMLUtils.addElement(documentDom, objectDom, xPathQueryHolder.XADES_NAMESPACE, "xades:QualifyingProperties");
        qualifyingPropertiesDom.setAttribute("xmlns:xades", xPathQueryHolder.XADES_NAMESPACE);
        qualifyingPropertiesDom.setAttribute("Target", "#" + deterministicId);

        incorporateSignedProperties();
    }

    /**
     * @throws DSSException
     */

    /**
     * @throws DSSException
     */
    protected void incorporateReference2() throws DSSException {

        // <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#xades-ide5c549340079fe19f3f90f03354a5965">
        final Element reference = DSSXMLUtils.addElement(documentDom, signedInfoDom, xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:Reference");
        reference.setAttribute("Type", xPathQueryHolder.XADES_SIGNED_PROPERTIES);
        reference.setAttribute("URI", "#xades-" + deterministicId);
        // <ds:Transforms>
        final Element transforms = DSSXMLUtils.addElement(documentDom, reference, xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:Transforms");
        // <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        final Element transform = DSSXMLUtils.addElement(documentDom, transforms, xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:Transform");
        transform.setAttribute("Algorithm", reference2CanonicalizationMethod);
        // </ds:Transforms>

        // <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        final DigestAlgorithm digestAlgorithm = params.getDigestAlgorithm();
        incorporateDigestMethod(reference, digestAlgorithm);

        // <ds:DigestValue>b/JEDQH2S1Nfe4Z3GSVtObN34aVB1kMrEbVQZswThfQ=</ds:DigestValue>
        final byte[] canonicalizedBytes = DSSXMLUtils.canonicalizeSubtree(reference2CanonicalizationMethod, signedPropertiesDom);
        if (LOG.isInfoEnabled()) {
            LOG.info("Canonicalization method  -->" + signedInfoCanonicalizationMethod);
            LOG.info("Canonicalised REF_2      --> " + new String(canonicalizedBytes));
        }
        incorporateDigestValue(reference, digestAlgorithm, canonicalizedBytes);
    }

    /**
     * @return
     */
    protected void incorporateSignatureValue() {

        signatureValueDom = DSSXMLUtils.addElement(documentDom, signatureDom, xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:SignatureValue");
        signatureValueDom.setAttribute("Id", "value-" + deterministicId);
    }

    /**
     * Creates the SignedProperties DOM object element.
     *
     * @throws DSSException
     */
    protected void incorporateSignedProperties() throws DSSException {

        // <SignedProperties Id="xades-ide5c549340079fe19f3f90f03354a5965">
        signedPropertiesDom = DSSXMLUtils.addElement(documentDom, qualifyingPropertiesDom, xPathQueryHolder.XADES_NAMESPACE, "xades:SignedProperties");
        signedPropertiesDom.setAttribute("Id", "xades-" + deterministicId);

        incorporateSignedSignatureProperties();
    }

    /**
     * Creates the SignedSignatureProperties DOM object element.
     *
     * @throws DSSException
     */
    protected void incorporateSignedSignatureProperties() throws DSSException {

        // <SignedSignatureProperties>
        signedSignaturePropertiesDom = DSSXMLUtils.addElement(documentDom, signedPropertiesDom, xPathQueryHolder.XADES_NAMESPACE, "xades:SignedSignatureProperties");

        incorporateSigningTime();

        incorporateSigningCertificate();

        incorporateSignedDataObjectProperties();

        incorporateSignerRole();

        incorporateSignatureProductionPlace();

        incorporateCommitmentTypeIndications();

        incorporatePolicy();
    }

    private void incorporatePolicy() {

        final BLevelParameters.Policy signaturePolicy = params.bLevel().getSignaturePolicy();
        if (signaturePolicy != null && signaturePolicy.getId() != null) {

            final Element signaturePolicyIdentifierDom = DSSXMLUtils
                  .addElement(documentDom, signedSignaturePropertiesDom, xPathQueryHolder.XADES_NAMESPACE, "xades:SignaturePolicyIdentifier");
            final Element signaturePolicyIdDom = DSSXMLUtils.addElement(documentDom, signaturePolicyIdentifierDom, xPathQueryHolder.XADES_NAMESPACE, "xades:SignaturePolicyId");
            if ("".equals(signaturePolicy.getId())) { // implicit

                final Element signaturePolicyImpliedDom = DSSXMLUtils
                      .addElement(documentDom, signaturePolicyIdDom, xPathQueryHolder.XADES_NAMESPACE, "xades:SignaturePolicyImplied");
            } else { // explicit

                final Element sigPolicyIdDom = DSSXMLUtils.addElement(documentDom, signaturePolicyIdDom, xPathQueryHolder.XADES_NAMESPACE, "xades:SigPolicyId");

                final String signaturePolicyId = signaturePolicy.getId();
                DSSXMLUtils.addTextElement(documentDom, sigPolicyIdDom, xPathQueryHolder.XADES_NAMESPACE, "xades:Identifier", signaturePolicyId);

                if (signaturePolicy.getDigestAlgorithm() != null && signaturePolicy.getDigestValue() != null) {

                    final Element sigPolicyHashDom = DSSXMLUtils.addElement(documentDom, signaturePolicyIdDom, xPathQueryHolder.XADES_NAMESPACE, "xades:SigPolicyHash");

                    // <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    final DigestAlgorithm digestAlgorithm = signaturePolicy.getDigestAlgorithm();
                    incorporateDigestMethod(sigPolicyHashDom, digestAlgorithm);

                    final byte[] hashValue = signaturePolicy.getDigestValue();
                    final String bas64EncodedHashValue = DSSUtils.base64Encode(hashValue);
                    DSSXMLUtils.addTextElement(documentDom, sigPolicyHashDom, xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:DigestValue", bas64EncodedHashValue);
                }
            }
        }
    }

    /**
     * Creates SigningTime DOM object element.
     */
    private void incorporateSigningTime() {

        final Date signingDate = params.bLevel().getSigningDate();
        final XMLGregorianCalendar xmlGregorianCalendar = DSSXMLUtils.createXMLGregorianCalendar(signingDate);
        final String xmlSigningTime = xmlGregorianCalendar.toXMLFormat();

        // <SigningTime>2013-11-23T11:22:52Z</SigningTime>
        final Element signingTimeDom = documentDom.createElementNS(xPathQueryHolder.XADES_NAMESPACE, "xades:SigningTime");
        signedSignaturePropertiesDom.appendChild(signingTimeDom);
        final Text textNode = documentDom.createTextNode(xmlSigningTime);
        signingTimeDom.appendChild(textNode);
    }

    /**
     * Creates SigningCertificate building block DOM object:
     *
     * <SigningCertificate> <Cert> <CertDigest> <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/> <ds:DigestValue>fj8SJujSXU4fi342bdtiKVbglA0=</ds:DigestValue>
     * </CertDigest> <IssuerSerial> <ds:X509IssuerName>CN=ICA A,O=DSS,C=AA</ds:X509IssuerName> <ds:X509SerialNumber>4</ds:X509SerialNumber> </IssuerSerial> </Cert>
     * </SigningCertificate>
     */
    private void incorporateSigningCertificate() {

        final Element signingCertificateDom = DSSXMLUtils.addElement(documentDom, signedSignaturePropertiesDom, xPathQueryHolder.XADES_NAMESPACE, "xades:SigningCertificate");

        final List<X509Certificate> certificates = new ArrayList<X509Certificate>();

        final X509Certificate signingCertificate = params.getSigningCertificate();
        certificates.add(signingCertificate);

        incorporateCertificateRef(signingCertificateDom, certificates);
    }

    /**
     * This method incorporates the SignedDataObjectProperties DOM element <SignedDataObjectProperties> ...<DataObjectFormat ObjectReference="#detached-ref-id">
     * ......<MimeType>text/plain</MimeType> ...</DataObjectFormat> </SignedDataObjectProperties>
     */
    private void incorporateSignedDataObjectProperties() {

        final String dataObjectFormatObjectReference = getDataObjectFormatObjectReference();
        final String dataObjectFormatMimeType = getDataObjectFormatMimeType();

        signedDataObjectPropertiesDom = DSSXMLUtils.addElement(documentDom, signedPropertiesDom, xPathQueryHolder.XADES_NAMESPACE, "xades:SignedDataObjectProperties");

        final Element dataObjectFormatDom = DSSXMLUtils.addElement(documentDom, signedDataObjectPropertiesDom, xPathQueryHolder.XADES_NAMESPACE, "xades:DataObjectFormat");
        dataObjectFormatDom.setAttribute("ObjectReference", dataObjectFormatObjectReference);

        final Element mimeTypeDom = DSSXMLUtils.addElement(documentDom, dataObjectFormatDom, xPathQueryHolder.XADES_NAMESPACE, "xades:MimeType");
        DSSXMLUtils.setTextNode(documentDom, mimeTypeDom, dataObjectFormatMimeType);
    }

    /**
     * This method incorporates the signer claimed roleType into signed signature properties.
     */
    private void incorporateSignerRole() {

        final List<String> claimedSignerRoles = params.bLevel().getClaimedSignerRoles();
        final List<String> certifiedSignerRoles = params.bLevel().getCertifiedSignerRoles();
        if (claimedSignerRoles != null || certifiedSignerRoles != null) {

            final Element signerRoleDom = DSSXMLUtils.addElement(documentDom, signedSignaturePropertiesDom, xPathQueryHolder.XADES_NAMESPACE, "xades:SignerRole");

            if (claimedSignerRoles != null && !claimedSignerRoles.isEmpty()) {

                final Element claimedRolesDom = DSSXMLUtils.addElement(documentDom, signerRoleDom, xPathQueryHolder.XADES_NAMESPACE, "xades:ClaimedRoles");
                addRoles(claimedSignerRoles, claimedRolesDom, "xades:ClaimedRole");
            }

            if (certifiedSignerRoles != null && !certifiedSignerRoles.isEmpty()) {

                final Element certifiedRolesDom = DSSXMLUtils.addElement(documentDom, signerRoleDom, xPathQueryHolder.XADES_NAMESPACE, "xades:CertifiedRoles");
                addRoles(certifiedSignerRoles, certifiedRolesDom, "xades:CertifiedRole");
            }
        }

    }

    private void addRoles(final List<String> signerRoles, final Element rolesDom, final String roleType) {

        for (final String signerRole : signerRoles) {

            final Element roleDom = DSSXMLUtils.addElement(documentDom, rolesDom, xPathQueryHolder.XADES_NAMESPACE, roleType);
            DSSXMLUtils.setTextNode(documentDom, roleDom, signerRole);
        }
    }

    private void incorporateSignatureProductionPlace() {

        final BLevelParameters.SignerLocation signatureProductionPlace = params.bLevel().getSignerLocation();
        if (signatureProductionPlace != null) {

            final Element signatureProductionPlaceDom = DSSXMLUtils
                  .addElement(documentDom, signedSignaturePropertiesDom, xPathQueryHolder.XADES_NAMESPACE, "xades:SignatureProductionPlace");

            final String city = signatureProductionPlace.getCity();
            DSSXMLUtils.addTextElement(documentDom, signatureProductionPlaceDom, xPathQueryHolder.XADES_NAMESPACE, "xades:City", city);

            final String postalCode = signatureProductionPlace.getPostalCode();
            DSSXMLUtils.addTextElement(documentDom, signatureProductionPlaceDom, xPathQueryHolder.XADES_NAMESPACE, "xades:PostalCode", postalCode);

            final String stateOrProvince = signatureProductionPlace.getStateOrProvince();
            DSSXMLUtils.addTextElement(documentDom, signatureProductionPlaceDom, xPathQueryHolder.XADES_NAMESPACE, "xades:StateOrProvince", stateOrProvince);

            final String country = signatureProductionPlace.getCountry();
            DSSXMLUtils.addTextElement(documentDom, signatureProductionPlaceDom, xPathQueryHolder.XADES_NAMESPACE, "xades:CountryName", country);
        }
    }

    /**
     * Below follows the schema definition for this element. <xsd:element name="CommitmentTypeIndication" type="CommitmentTypeIndicationType"/>
     *
     * <xsd:complexType name="CommitmentTypeIndicationType"> ...<xsd:sequence> ......<xsd:element name="CommitmentTypeId" type="ObjectIdentifierType"/> ......<xsd:choice>
     * .........<xsd:element name="ObjectReference" type="xsd:anyURI" maxOccurs="unbounded"/> .........< xsd:element name="AllSignedDataObjects"/> ......</xsd:choice>
     * ......<xsd:element name="CommitmentTypeQualifiers" type="CommitmentTypeQualifiersListType" minOccurs="0"/> ...</xsd:sequence> </xsd:complexType> <xsd:complexType
     * name="CommitmentTypeQualifiersListType"> ...<xsd:sequence> ......<xsd:element name="CommitmentTypeQualifier" type="AnyType" minOccurs="0" maxOccurs="unbounded"/>
     * ...</xsd:sequence> </xsd:complexType>
     */
    private void incorporateCommitmentTypeIndications() {

        final List<String> commitmentTypeIndications = params.bLevel().getCommitmentTypeIndications();
        if (commitmentTypeIndications != null) {

            final Element commitmentTypeIndicationDom = DSSXMLUtils
                  .addElement(documentDom, signedDataObjectPropertiesDom, xPathQueryHolder.XADES_NAMESPACE, "xades:CommitmentTypeIndication");

            final Element commitmentTypeIdDom = DSSXMLUtils.addElement(documentDom, commitmentTypeIndicationDom, xPathQueryHolder.XADES_NAMESPACE, "xades:CommitmentTypeId");

            for (final String commitmentTypeIndication : commitmentTypeIndications) {

                DSSXMLUtils.addTextElement(documentDom, commitmentTypeIdDom, xPathQueryHolder.XADES_NAMESPACE, "xades:Identifier", commitmentTypeIndication);
            }
            //final Element objectReferenceDom = DSSXMLUtils.addElement(documentDom, commitmentTypeIndicationDom, XADES, "ObjectReference");
            // or
            final Element allSignedDataObjectsDom = DSSXMLUtils
                  .addElement(documentDom, commitmentTypeIndicationDom, xPathQueryHolder.XADES_NAMESPACE, "xades:AllSignedDataObjects");

            //final Element commitmentTypeQualifiersDom = DSSXMLUtils.addElement(documentDom, commitmentTypeIndicationDom, XADES, "CommitmentTypeQualifiers");
        }
    }

    /**
     * Adds signature value to the signature and returns XML signature (InMemoryDocument)
     *
     * @param signatureValue - Encoded value of the signature
     * @return
     * @throws DSSException
     */
    public abstract DSSDocument signDocument(final byte[] signatureValue) throws DSSException;

    /**
     * This method returns data format reference.
     *
     * @return
     */
    protected abstract String getDataObjectFormatObjectReference();

    /**
     * This method returns data format mime type.
     *
     * @return
     */
    protected abstract String getDataObjectFormatMimeType();
}