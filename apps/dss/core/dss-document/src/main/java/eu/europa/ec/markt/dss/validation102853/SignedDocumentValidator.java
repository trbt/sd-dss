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

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.DSSASN1Utils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.OID;
import eu.europa.ec.markt.dss.PublicKeyUtils;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNotETSICompliantException;
import eu.europa.ec.markt.dss.exception.DSSNotETSICompliantException.MSG;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.ProfileException;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.validation.SignaturePolicy;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCXMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.bean.CertifiedRole;
import eu.europa.ec.markt.dss.validation102853.bean.CommitmentType;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureProductionPlace;
import eu.europa.ec.markt.dss.validation102853.bean.SigningCertificateValidity;
import eu.europa.ec.markt.dss.validation102853.cades.CMSDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.condition.Condition;
import eu.europa.ec.markt.dss.validation102853.condition.PolicyIdCondition;
import eu.europa.ec.markt.dss.validation102853.condition.QcStatementCondition;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.ObjectFactory;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlBasicSignatureType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlCertificate;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlCertificateChainType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlCertifiedRolesType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlChainCertificate;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlClaimedRoles;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlCommitmentTypeIndication;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlDigestAlgAndValueType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlDistinguishedName;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlInfoType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlMessage;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlPolicy;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlQCStatement;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlQualifiers;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlRevocationType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignature;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignatureProductionPlace;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignedObjectsType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignedSignature;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSigningCertificateType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlTimestampType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlTimestamps;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlTrustedServiceProviderType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlUsedCertificates;
import eu.europa.ec.markt.dss.validation102853.pades.PDFDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.DetailedReport;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import eu.europa.ec.markt.dss.validation102853.xades.XMLDocumentValidator;

/**
 * Validate the signed document. The content of the document is determined automatically. It can be: XML, CAdES(p7m), PDF or ASiC(zip).
 *
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
public abstract class SignedDocumentValidator implements DocumentValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SignedDocumentValidator.class);

    private static final String MIMETYPE = "mimetype";

    // private static final String MIMETYPE_ASIC_S = "application/vnd.etsi.asic-s+zip";
    private static final String PATTERN_SIGNATURES_XML = "META-INF/(.*)(?i)signature(.*).xml";

    private static final String PATTERN_SIGNATURES_P7S = "META-INF/(.*)(?i)signature(.*).p7s";

    /*
     * The factory used to create DiagnosticData
     */
    protected static final ObjectFactory DIAGNOSTIC_DATA_OBJECT_FACTORY = new ObjectFactory();

    /**
     * This is the pool of certificates used in the validation process. The pools present in the certificate verifier are merged and added to this pool.
     */
    protected CertificatePool validationCertPool;

    /**
     * This is the unique timestamp Id. It is unique within one validation process.
     */
    private int timestampIndex = 1;

    /**
     * The document to validated (with the signature(s))
     */
    protected DSSDocument document;

    /**
     * In case of a detached signature this is the signed document.
     */
    protected DSSDocument externalContent;

    /**
     * The reference to the certificate verifier. The current DSS implementation proposes {@link eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier}. This verifier
     * encapsulates the references to different sources used in the signature validation process.
     */
    private CertificateVerifier certVerifier;

    /**
     * This list contains the list of signatures
     */
    protected List<AdvancedSignature> signatures = null;

    /**
     * This variable contains the reference to the diagnostic data.
     */
    protected eu.europa.ec.markt.dss.validation102853.data.diagnostic.DiagnosticData jaxbDiagnosticData; // JAXB object
    protected DiagnosticData diagnosticData; // XmlDom object

    /**
     * This is the simple report generated at the end of the validation process.
     */
    protected SimpleReport simpleReport;

    /**
     * This is the detailed report of the validation.
     */
    protected DetailedReport detailedReport;

    private final Condition qcp = new PolicyIdCondition(OID.id_etsi_qcp_public.getId());

    private final Condition qcpPlus = new PolicyIdCondition(OID.id_etsi_qcp_public_with_sscd.getId());

    private final Condition qcCompliance = new QcStatementCondition(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance);

    private final Condition qcsscd = new QcStatementCondition(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD);

    // Single policy document to use with all signatures.
    private File policyDocument;

    private HashMap<String, File> policyDocuments;

    /**
     * This method guesses the document format and returns an appropriate document validator.
     *
     * @param dssDocument The instance of {@code DSSDocument} to validate
     * @return returns the specific instance of SignedDocumentValidator in terms of the document type
     */
    public static SignedDocumentValidator fromDocument(final DSSDocument dssDocument) {

        BufferedInputStream input = null;
        try {

            if (dssDocument.getName() != null && dssDocument.getName().toLowerCase().endsWith(".xml")) {

                return new XMLDocumentValidator(dssDocument);
            }

            input = new BufferedInputStream(dssDocument.openStream());
            input.mark(5);
            byte[] preamble = new byte[5];
            int read = input.read(preamble);
            input.reset();
            if (read < 5) {

                throw new DSSException("Not a signed document");
            }
            String preambleString = new String(preamble);
            byte[] xmlPreamble = new byte[]{'<', '?', 'x', 'm', 'l'};
            byte[] xmlUtf8 = new byte[]{-17, -69, -65, '<', '?'};
            if (Arrays.equals(preamble, xmlPreamble) || Arrays.equals(preamble, xmlUtf8)) {

                return new XMLDocumentValidator(dssDocument);
            } else if (preambleString.equals("%PDF-")) {

                return new PDFDocumentValidator(dssDocument);
            } else if (preamble[0] == 'P' && preamble[1] == 'K') {

                DSSUtils.closeQuietly(input);
                input = null;
                return getInstanceForAsics(dssDocument);
            } else if (preambleString.getBytes()[0] == 0x30) {

                return new CMSDocumentValidator(dssDocument);
            } else {
                throw new DSSException("Document format not recognized/handled");
            }
        } catch (IOException e) {
            throw new DSSException(e);
        } finally {
            DSSUtils.closeQuietly(input);
        }
    }

    /**
     * @param document The instance of {@code DSSDocument} to validate
     * @return
     * @throws eu.europa.ec.markt.dss.exception.DSSException
     */
    private static SignedDocumentValidator getInstanceForAsics(final DSSDocument document) throws DSSException {

        ZipInputStream asics = null;
        try {

            asics = new ZipInputStream(document.openStream());

            String dataFileName = "";
            ByteArrayOutputStream dataFile = null;
            ByteArrayOutputStream signatures = null;
            ZipEntry entry;

            boolean cadesSigned = false;
            boolean xadesSigned = false;

            while ((entry = asics.getNextEntry()) != null) {
                if (entry.getName().matches(PATTERN_SIGNATURES_P7S)) {
                    if (xadesSigned) {
                        throw new DSSNotETSICompliantException(MSG.MORE_THAN_ONE_SIGNATURE);
                    }
                    signatures = new ByteArrayOutputStream();
                    DSSUtils.copy(asics, signatures);
                    signatures.close();
                    cadesSigned = true;
                } else if (entry.getName().matches(PATTERN_SIGNATURES_XML)) {
                    if (cadesSigned) {
                        throw new DSSNotETSICompliantException(MSG.MORE_THAN_ONE_SIGNATURE);
                    }
                    signatures = new ByteArrayOutputStream();
                    DSSUtils.copy(asics, signatures);
                    signatures.close();
                    xadesSigned = true;
                } else if (entry.getName().equalsIgnoreCase(MIMETYPE)) {
                    ByteArrayOutputStream mimetype = new ByteArrayOutputStream();
                    DSSUtils.copy(asics, mimetype);
                    mimetype.close();
                    // Mime type implementers MAY use
                    // "application/vnd.etsi.asic-s+zip" to identify this format
                    // or MAY
                    // maintain the original mimetype of the signed data object.
                } else if (entry.getName().indexOf("/") == -1) {
                    if (dataFile == null) {

                        dataFile = new ByteArrayOutputStream();
                        DSSUtils.copy(asics, dataFile);
                        dataFile.close();
                        dataFileName = entry.getName();
                    } else {
                        throw new ProfileException("ASiC-S profile support only one data file");
                    }
                }
            }

            if (xadesSigned) {

                final InMemoryDocument doc = new InMemoryDocument(signatures.toByteArray());
                final ASiCXMLDocumentValidator xmlValidator = new ASiCXMLDocumentValidator(doc, dataFile.toByteArray(), dataFileName);
                return xmlValidator;
            } else if (cadesSigned) {

                final CMSDocumentValidator cmsDocumentValidator = new CMSDocumentValidator(new InMemoryDocument(signatures.toByteArray()));
                cmsDocumentValidator.setExternalContent(new InMemoryDocument(dataFile.toByteArray()));
                return cmsDocumentValidator;
            } else {
                throw new DSSException("Is not xades nor cades signed");
            }

        } catch (Exception ex) {
            throw new DSSException(ex);
        } finally {
            DSSUtils.closeQuietly(asics);
        }

    }

    /**
     * In case of ASiC, this is the signature
     */
    @Override
    public DSSDocument getDocument() {

        return document;
    }

    /**
     * @return the externalContent
     */
    @Override
    public DSSDocument getExternalContent() {

        return externalContent;
    }

    /**
     * This method creates the validation pool of certificates which is used during the validation process.
     *
     * @param certificateVerifier
     */
    public static CertificatePool createValidationPool(final CertificateVerifier certificateVerifier) {

        final CertificatePool validationPool = new CertificatePool();
        final TrustedCertificateSource trustedCertSource = certificateVerifier.getTrustedCertSource();
        if (trustedCertSource != null) {

            validationPool.merge(trustedCertSource.getCertificatePool());
        }
        final CertificateSource adjunctCertSource = certificateVerifier.getAdjunctCertSource();
        if (adjunctCertSource != null) {

            validationPool.merge(adjunctCertSource.getCertificatePool());
        }
        return validationPool;
    }

    /**
     * To carry out the validation process of the signature(s) some external sources of certificates and of revocation data can be needed. The certificate verifier is used to pass
     * these values. Note that once this setter is called any change in the content of the <code>CommonTrustedCertificateSource</code> or in adjunct certificate source is not
     * taken into account.
     *
     * @param certVerifier
     */
    @Override
    public void setCertificateVerifier(final CertificateVerifier certVerifier) {

        this.certVerifier = certVerifier;
        validationCertPool = createValidationPool(certVerifier);
    }

    /**
     * Sets the Document containing the original content to sign, for detached signature scenarios.
     *
     * @param externalContent the externalContent to set
     */
    @Override
    public void setExternalContent(final DSSDocument externalContent) {

        this.externalContent = externalContent;
    }

    /**
     * This method allows to provide an external policy document to be used with all signatures within the document to validate.
     *
     * @param policyDocument
     */
    @Override
    public void setPolicyFile(final File policyDocument) {

        this.policyDocument = policyDocument;
    }

    /**
     * This method allows to provide an external policy document to be used with a given signature id.
     *
     * @param signatureId    signature id
     * @param policyDocument
     */
    @Override
    public void setPolicyFile(final String signatureId, final File policyDocument) {

        if (policyDocuments == null) {

            policyDocuments = new HashMap<String, File>();
        }
        policyDocuments.put(signatureId, policyDocument);
    }

    /**
     * Validates the document and all its signatures. The default constraint file is used.
     */
    @Override
    public DetailedReport validateDocument() {

        return validateDocument((InputStream) null);
    }

    /**
     * Validates the document and all its signatures. If the validation policy URL is set then the policy constraints are retrieved from this location. If null or empty the
     * default file is used.
     *
     * @param validationPolicyURL
     * @return
     */
    @Override
    public DetailedReport validateDocument(URL validationPolicyURL) {
        if (validationPolicyURL == null) {
            return validateDocument((InputStream) null);
        } else {
            try {
                return validateDocument(validationPolicyURL.openStream());
            } catch (IOException e) {
                throw new DSSException(e);
            }
        }
    }

    /**
     * Validates the document and all its signatures. The policyResourcePath specifies the constraint file. If null or empty the default file is used.
     *
     * @param policyResourcePath is located against the classpath (getClass().getResourceAsStream), and NOT the filesystem
     */
    @Override
    public DetailedReport validateDocument(final String policyResourcePath) {

        if (policyResourcePath == null) {
            return validateDocument((InputStream) null);
        } else {
            return validateDocument(getClass().getResourceAsStream(policyResourcePath));
        }
    }

    /**
     * Validates the document and all its signatures. The {@code policyFile} specifies the constraint file. If null or empty the default file is used.
     *
     * @param policyFile contains the validation policy (xml)
     */
    @Override
    public DetailedReport validateDocument(final File policyFile) {

        if (policyFile == null || !policyFile.exists()) {
            return validateDocument((InputStream) null);
        } else {
            final InputStream inputStream = DSSUtils.toInputStream(policyFile);
            return validateDocument(inputStream);
        }
    }

    /**
     * Validates the document and all its signatures. The policyDataStream contains the constraint file. If null or empty the default file is used.
     *
     * @param policyDataStream
     */
    @Override
    public DetailedReport validateDocument(final InputStream policyDataStream) {

        LOG.info("Document validation...");

        if (certVerifier == null) {

            throw new DSSNullException(CertificateVerifier.class);
        }

        final eu.europa.ec.markt.dss.validation102853.data.diagnostic.DiagnosticData jaxbDiagnosticData = generateDiagnosticData();

        final Document diagnosticDataDom = ValidationResourceManager.convert(jaxbDiagnosticData);

        final Document validationPolicyDom = ValidationResourceManager.loadPolicyData(policyDataStream);
        final ProcessExecutor executor = getProcessExecutor(diagnosticDataDom, validationPolicyDom);

        executor.execute();

        this.diagnosticData = executor.getDiagnosticData();
        detailedReport = executor.getDetailedReport();
        simpleReport = executor.getSimpleReport();

        return detailedReport;
    }

    protected ProcessExecutor getProcessExecutor(final Document diagnosticDataDom, final Document validationPolicyDom) {

        return new ProcessExecutor(diagnosticDataDom, validationPolicyDom);
    }

    /**
     * This method generates the diagnostic data. This is the set of all data extracted from the signature, associated certificates and trusted lists. The diagnostic data contains
     * also the results of basic computations (hash check, signature integrity, certificates chain...
     */
    private eu.europa.ec.markt.dss.validation102853.data.diagnostic.DiagnosticData generateDiagnosticData() {

        jaxbDiagnosticData = DIAGNOSTIC_DATA_OBJECT_FACTORY.createDiagnosticData();
        jaxbDiagnosticData.setDocumentName(document.getAbsolutePath());
        final Set<DigestAlgorithm> usedCertificatesDigestAlgorithms = new HashSet<DigestAlgorithm>();

        final Set<CertificateToken> usedCertPool = new HashSet<CertificateToken>();
      /*
       * For each signature present in the file to be validated the extraction of diagnostic data is launched.
       */
        for (final AdvancedSignature signature : getSignatures()) {

            final ValidationContext valContext = new SignatureValidationContext(signature, certVerifier, validationCertPool);
            final XmlSignature xmlSignature = validateSignature(signature, valContext);
            final Set<CertificateToken> signatureCertPool = valContext.getProcessedCertificates();
            usedCertPool.addAll(signatureCertPool);
            usedCertificatesDigestAlgorithms.addAll(signature.getUsedCertificatesDigestAlgorithms());
            jaxbDiagnosticData.getSignature().add(xmlSignature);
        }
        dealUsedCertificates(usedCertificatesDigestAlgorithms, usedCertPool);

        return jaxbDiagnosticData;
    }

    /**
     * Main method for validating a signature. The diagnostic data is extracted.
     *
     * @param signature Signature to be validated (can be XAdES, CAdES, PAdES.
     * @return The JAXB object containing all diagnostic data pertaining to the signature
     */
    private XmlSignature validateSignature(final AdvancedSignature signature, final ValidationContext valContext) throws DSSException {

      /*
       * TODO: (Bob 20130424) The the "signing certificate" list parameter must be added. It will allow to provide sc from outside.
       */
        final XmlSignature xmlSignature = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSignature();

        try {

            final CertificateToken signingToken = dealSignature(signature, xmlSignature);

            valContext.setCertificateToValidate(signingToken);

            valContext.validate();

            dealPolicy(signature, xmlSignature);

            dealCertificateChain(xmlSignature, signingToken);

            XmlTimestamps xmlTimestamps = null;

            xmlTimestamps = dealTimestamps(xmlTimestamps, valContext.getContentTimestamps());

            xmlTimestamps = dealTimestamps(xmlTimestamps, valContext.getTimestampTokens());

            xmlTimestamps = dealTimestamps(xmlTimestamps, valContext.getSigAndRefsTimestamps());

            xmlTimestamps = dealTimestamps(xmlTimestamps, valContext.getRefsOnlyTimestamps());

            xmlTimestamps = dealTimestamps(xmlTimestamps, valContext.getArchiveTimestamps());

            xmlSignature.setTimestamps(xmlTimestamps);
        } catch (Exception e) {

            // Any raised error is just logged and the process continues with the next signature.
            LOG.warn(e.getMessage(), e);
            String errorMessage = xmlSignature.getErrorMessage();
            if (errorMessage == null || errorMessage.isEmpty()) {

                xmlSignature.setErrorMessage(e.toString());
            } else {

                errorMessage += "<br />" + e.toString();
            }
            xmlSignature.setErrorMessage(errorMessage);
        }
        return xmlSignature;
    }

    /**
     * @param xmlTimestamps
     * @param timestampTokens
     */
    private XmlTimestamps dealTimestamps(XmlTimestamps xmlTimestamps, final List<TimestampToken> timestampTokens) {

        if (!timestampTokens.isEmpty()) {

            for (final TimestampToken timestampToken : timestampTokens) {

                final XmlTimestampType xmlTimestampToken = xmlForTimestamp(timestampToken);
                if (xmlTimestamps == null) {

                    xmlTimestamps = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlTimestamps();
                }
                xmlTimestamps.getTimestamp().add(xmlTimestampToken);
            }
        }
        return xmlTimestamps;
    }

    /**
     * @param timestampToken
     * @return
     */
    private XmlTimestampType xmlForTimestamp(final TimestampToken timestampToken) {

        final XmlTimestampType xmlTimestampToken = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlTimestampType();
        xmlTimestampToken.setId(timestampIndex++);
        final TimestampType timestampType = timestampToken.getTimeStampType();
        xmlTimestampToken.setType(timestampType.name());
        xmlTimestampToken.setProductionTime(DSSXMLUtils.createXMLGregorianCalendar(timestampToken.getGenerationTime()));

        xmlTimestampToken.setSignedDataDigestAlgo(timestampToken.getSignedDataDigestAlgo().getName());
        xmlTimestampToken.setEncodedSignedDataDigestValue(timestampToken.getEncodedSignedDataDigestValue());
        xmlTimestampToken.setMessageImprintDataFound(timestampToken.isMessageImprintDataFound());
        xmlTimestampToken.setMessageImprintDataIntact(timestampToken.isMessageImprintDataIntact());

        final SignatureAlgorithm signatureAlgorithm = timestampToken.getSignatureAlgo();
        final XmlBasicSignatureType xmlBasicSignatureType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlBasicSignatureType();
        if (signatureAlgorithm != null) {

            xmlBasicSignatureType.setEncryptionAlgoUsedToSignThisToken(signatureAlgorithm.getEncryptionAlgo().getName());
            xmlBasicSignatureType.setDigestAlgoUsedToSignThisToken(signatureAlgorithm.getDigestAlgo().getName());
        }
        final String keyLength = timestampToken.getKeyLength();
        xmlBasicSignatureType.setKeyLengthUsedToSignThisToken(keyLength);

        final boolean signatureValid = timestampToken.isSignatureValid();
        xmlBasicSignatureType.setReferenceDataFound(signatureValid /*timestampToken.isReferenceDataFound()*/);
        xmlBasicSignatureType.setReferenceDataIntact(signatureValid /*timestampToken.isReferenceDataIntact()*/);
        xmlBasicSignatureType.setSignatureIntact(signatureValid /*timestampToken.isSignatureIntact()*/);
        xmlBasicSignatureType.setSignatureValid(signatureValid);
        xmlTimestampToken.setBasicSignature(xmlBasicSignatureType);

        final CertificateToken issuerToken = timestampToken.getIssuerToken();

        XmlSigningCertificateType xmlTSSignCert = xmlForSigningCertificate(issuerToken, timestampToken.isSignatureValid());
        xmlTimestampToken.setSigningCertificate(xmlTSSignCert);

        final XmlCertificateChainType xmlCertChainType = xmlForCertificateChain(issuerToken);
        xmlTimestampToken.setCertificateChain(xmlCertChainType);

        final List<TimestampReference> timestampReferences = timestampToken.getTimestampedReferences();
        if (timestampReferences != null && !timestampReferences.isEmpty()) {

            final XmlSignedObjectsType xmlSignedObjectsType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSignedObjectsType();
            final List<XmlDigestAlgAndValueType> xmlDigestAlgAndValueList = xmlSignedObjectsType.getDigestAlgAndValue();

            for (final TimestampReference timestampReference : timestampReferences) {

                final TimestampReferenceCategory timestampedCategory = timestampReference.getCategory();
                if (TimestampReferenceCategory.SIGNATURE.equals(timestampedCategory)) {

                    final XmlSignedSignature xmlSignedSignature = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSignedSignature();
                    xmlSignedSignature.setId(timestampReference.getSignatureId());
                    xmlSignedObjectsType.setSignedSignature(xmlSignedSignature);
                } else {

                    final XmlDigestAlgAndValueType xmlDigestAlgAndValue = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlDigestAlgAndValueType();
                    xmlDigestAlgAndValue.setDigestMethod(timestampReference.getDigestAlgorithm());
                    xmlDigestAlgAndValue.setDigestValue(timestampReference.getDigestValue());
                    xmlDigestAlgAndValue.setCategory(timestampedCategory.name());
                    xmlDigestAlgAndValueList.add(xmlDigestAlgAndValue);
                }
            }
            xmlTimestampToken.setSignedObjects(xmlSignedObjectsType);
        }
        return xmlTimestampToken;
    }

    /**
     * @param issuerToken
     * @return
     */
    private XmlCertificateChainType xmlForCertificateChain(final CertificateToken issuerToken) {

        if (issuerToken != null) {

            CertificateToken issuerToken_ = issuerToken;
            final XmlCertificateChainType xmlCertChainType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlCertificateChainType();
            final List<XmlChainCertificate> certChainTokens = xmlCertChainType.getChainCertificate();
            do {

                final XmlChainCertificate xmlCertToken = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlChainCertificate();
                xmlCertToken.setId(issuerToken_.getDSSId());
                final CertificateSourceType mainSource = getCertificateMainSourceType(issuerToken_);
                xmlCertToken.setSource(mainSource.name());
                certChainTokens.add(xmlCertToken);
                if (issuerToken_.isTrusted() || issuerToken_.isSelfSigned()) {

                    break;
                }
                issuerToken_ = issuerToken_.getIssuerToken();
            } while (issuerToken_ != null);
            return xmlCertChainType;
        }
        return null;
    }

    private CertificateSourceType getCertificateMainSourceType(final CertificateToken issuerToken) {

        CertificateSourceType mainSource = CertificateSourceType.UNKNOWN;
        final List<CertificateSourceType> sourceList = issuerToken.getSources();
        if (sourceList.size() > 0) {

            if (sourceList.contains(CertificateSourceType.TRUSTED_LIST)) {

                mainSource = CertificateSourceType.TRUSTED_LIST;
            } else if (sourceList.contains(CertificateSourceType.TRUSTED_STORE)) {

                mainSource = CertificateSourceType.TRUSTED_STORE;
            } else {
                mainSource = sourceList.get(0);
            }
        }
        return mainSource;
    }

    /**
     * @param usedCertificatesDigestAlgorithms
     * @param usedCertTokens
     */
    private void dealUsedCertificates(final Set<DigestAlgorithm> usedCertificatesDigestAlgorithms, final Set<CertificateToken> usedCertTokens) {

        final XmlUsedCertificates xmlUsedCerts = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlUsedCertificates();
        jaxbDiagnosticData.setUsedCertificates(xmlUsedCerts);
        for (final CertificateToken certToken : usedCertTokens) {

            final XmlCertificate xmlCert = dealCertificateDetails(usedCertificatesDigestAlgorithms, certToken);
            // !!! Log the certificate
            if (LOG.isDebugEnabled()) {
                LOG.debug("PEM for certificate: " + certToken.getAbbreviation() + "--->");
                final String pem = DSSUtils.convertToPEM(certToken.getCertificate());
                LOG.debug("\n" + pem);
            }
            dealQCStatement(certToken, xmlCert);
            dealTrustedService(certToken, xmlCert);
            dealRevocationData(certToken, xmlCert);
            dealCertificateValidationInfo(certToken, xmlCert);
            xmlUsedCerts.getCertificate().add(xmlCert);
        }
    }

    /**
     * This method deals with the Qualified Certificate Statements. The retrieved information is transformed to the JAXB object.<br> Qualified Certificate Statements, the
     * following Policies are checked:<br> - Qualified Certificates Policy "0.4.0.1456.1.1” (QCP);<br> - Qualified Certificates Policy + "0.4.0.1456.1.2" (QCP+);<br> - Qualified
     * Certificates Compliance "0.4.0.1862.1.1";<br> - Qualified Certificates SCCD "0.4.0.1862.1.4";<br>
     *
     * @param certToken
     * @param xmlCert
     */
    private void dealQCStatement(final CertificateToken certToken, final XmlCertificate xmlCert) {

        if (!certToken.isTrusted()) {

            /// System.out.println("--> QCStatement for: " + certToken.getAbbreviation());
            final X509Certificate cert = certToken.getCertificate();
            final XmlQCStatement xmlQCS = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlQCStatement();
            xmlQCS.setQCP(qcp.check(cert));
            xmlQCS.setQCPPlus(qcpPlus.check(cert));
            xmlQCS.setQCC(qcCompliance.check(cert));
            xmlQCS.setQCSSCD(qcsscd.check(cert));
            xmlCert.setQCStatement(xmlQCS);
        }
    }

    /**
     * This method deals with the certificate validation extra information. The retrieved information is transformed to the JAXB object.
     *
     * @param certToken
     * @param xmlCert
     */
    private void dealCertificateValidationInfo(final CertificateToken certToken, final XmlCertificate xmlCert) {

        final List<String> list = certToken.getValidationInfo();
        if (list.size() > 0) {

            final XmlInfoType xmlInfo = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlInfoType();
            for (String message : list) {

                final XmlMessage xmlMessage = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlMessage();
                xmlMessage.setId(0);
                xmlMessage.setValue(message);
                xmlInfo.getMessage().add(xmlMessage);
            }
            xmlCert.setInfo(xmlInfo);
        }
    }

    /**
     * This method deals with the certificate's details. The retrieved information is transformed to the JAXB object.
     *
     * @param usedDigestAlgorithms set of different digest algorithms used to compute certificate digest
     * @param certToken            current certificate token
     * @return
     */
    private XmlCertificate dealCertificateDetails(final Set<DigestAlgorithm> usedDigestAlgorithms, final CertificateToken certToken) {

        final XmlCertificate xmlCert = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlCertificate();

        xmlCert.setId(certToken.getDSSId());

        XmlDistinguishedName xmlDistinguishedName = xmlForDistinguishedName(X500Principal.CANONICAL, certToken.getSubjectX500Principal());
        xmlCert.getSubjectDistinguishedName().add(xmlDistinguishedName);
        xmlDistinguishedName = xmlForDistinguishedName(X500Principal.RFC2253, certToken.getSubjectX500Principal());
        xmlCert.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = xmlForDistinguishedName(X500Principal.CANONICAL, certToken.getIssuerX500Principal());
        xmlCert.getIssuerDistinguishedName().add(xmlDistinguishedName);
        xmlDistinguishedName = xmlForDistinguishedName(X500Principal.RFC2253, certToken.getIssuerX500Principal());
        xmlCert.getIssuerDistinguishedName().add(xmlDistinguishedName);

        xmlCert.setSerialNumber(certToken.getSerialNumber());

        for (final DigestAlgorithm digestAlgorithm : usedDigestAlgorithms) {

            final XmlDigestAlgAndValueType xmlDigestAlgAndValue = new XmlDigestAlgAndValueType();
            xmlDigestAlgAndValue.setDigestMethod(digestAlgorithm.getName());
            xmlDigestAlgAndValue.setDigestValue(certToken.getDigestValue(digestAlgorithm));
            xmlCert.getDigestAlgAndValue().add(xmlDigestAlgAndValue);
        }
        xmlCert.setIssuerCertificate(certToken.getIssuerTokenDSSId());
        xmlCert.setNotAfter(DSSXMLUtils.createXMLGregorianCalendar(certToken.getNotAfter()));
        xmlCert.setNotBefore(DSSXMLUtils.createXMLGregorianCalendar(certToken.getNotBefore()));
        final PublicKey publicKey = certToken.getPublicKey();
        xmlCert.setPublicKeySize(PublicKeyUtils.getPublicKeySize(publicKey));
        xmlCert.setPublicKeyEncryptionAlgo(PublicKeyUtils.getPublicKeyEncryptionAlgo(publicKey));

        if (certToken.isOCSPSigning()) {

            xmlCert.setIdKpOCSPSigning(true);
        }
        if (certToken.hasIdPkixOcspNoCheckExtension()) {

            xmlCert.setIdPkixOcspNoCheck(true);
        }
        if (certToken.hasExpiredCertOnCRLExtension()) {

            xmlCert.setExpiredCertOnCRL(true);
        }

        final XmlBasicSignatureType xmlBasicSignatureType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlBasicSignatureType();

        final SignatureAlgorithm signatureAlgorithm = certToken.getSignatureAlgo();
        xmlBasicSignatureType.setDigestAlgoUsedToSignThisToken(signatureAlgorithm.getDigestAlgo().getName());
        xmlBasicSignatureType.setEncryptionAlgoUsedToSignThisToken(signatureAlgorithm.getEncryptionAlgo().getName());
        final String keyLength = certToken.getKeyLength();
        xmlBasicSignatureType.setKeyLengthUsedToSignThisToken(keyLength);
        final boolean signatureIntact = certToken.isSignatureValid();
        xmlBasicSignatureType.setReferenceDataFound(signatureIntact);
        xmlBasicSignatureType.setReferenceDataIntact(signatureIntact);
        xmlBasicSignatureType.setSignatureIntact(signatureIntact);
        xmlBasicSignatureType.setSignatureValid(signatureIntact);
        xmlCert.setBasicSignature(xmlBasicSignatureType);

        final CertificateToken issuerToken = certToken.getIssuerToken();
        final XmlSigningCertificateType xmlSigningCertificate = xmlForSigningCertificate(issuerToken, certToken.isSignatureValid());
        xmlCert.setSigningCertificate(xmlSigningCertificate);

        final XmlCertificateChainType xmlCertChainType = xmlForCertificateChain(issuerToken);
        xmlCert.setCertificateChain(xmlCertChainType);

        xmlCert.setSelfSigned(certToken.isSelfSigned());
        xmlCert.setTrusted(certToken.isTrusted());

        return xmlCert;
    }

    private XmlDistinguishedName xmlForDistinguishedName(final String x500PrincipalFormat, final X500Principal X500PrincipalName) {

        final XmlDistinguishedName xmlDistinguishedName = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlDistinguishedName();
        xmlDistinguishedName.setFormat(x500PrincipalFormat);
        xmlDistinguishedName.setValue(X500PrincipalName.getName(x500PrincipalFormat));
        return xmlDistinguishedName;
    }

    /**
     * This method deals with the certificate chain. The retrieved information is transformed to the JAXB object.
     *
     * @param xmlSignature
     * @param signToken
     */
    private void dealCertificateChain(final XmlSignature xmlSignature, final CertificateToken signToken) {

        if (signToken != null) {

            final XmlCertificateChainType xmlCertChainType = xmlForCertificateChain(signToken);
            xmlSignature.setCertificateChain(xmlCertChainType);
        }
    }

    /**
     * This method deals with the trusted service information in case of trusted certificate. The retrieved information is transformed to the JAXB object.
     *
     * @param certToken
     * @param xmlCert
     */
    private void dealTrustedService(final CertificateToken certToken, final XmlCertificate xmlCert) {

        if (certToken.isTrusted()) {

            return;
        }
        final CertificateToken trustAnchor = certToken.getTrustAnchor();
        if (trustAnchor == null) {

            return;
        }

        final Date notBefore = certToken.getNotBefore();

        final XmlTrustedServiceProviderType xmlTSP = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlTrustedServiceProviderType();
        final List<ServiceInfo> services = trustAnchor.getAssociatedTSPS();
        if (services == null) {

            return;
        }
        boolean first = true;
        for (final ServiceInfo serviceInfo : services) {

            if (first) {

                xmlTSP.setTSPName(serviceInfo.getTspName());
                xmlTSP.setTSPServiceName(serviceInfo.getServiceName());
                xmlTSP.setTSPServiceType(serviceInfo.getType());
                xmlTSP.setWellSigned(serviceInfo.isTlWellSigned());
                first = false;
            }
            final Date statusStartDate = serviceInfo.getStatusStartDate();
            Date statusEndDate = serviceInfo.getStatusEndDate();
            if (statusEndDate == null) {

                // TODO: Should be changed in the case it would be possible to carry out the validation process at a specific moment in the time (validation date)
                statusEndDate = new Date();
            }
            // The issuing time of the certificate should be into the validity period of the associated service
            if (notBefore.after(statusStartDate) && notBefore.before(statusEndDate)) {

                xmlTSP.setStatus(serviceInfo.getStatus());
                xmlTSP.setStartDate(DSSXMLUtils.createXMLGregorianCalendar(statusStartDate));
                xmlTSP.setEndDate(DSSXMLUtils.createXMLGregorianCalendar(serviceInfo.getStatusEndDate()));
                xmlTSP.setExpiredCertsRevocationInfo(DSSXMLUtils.createXMLGregorianCalendar(serviceInfo.getExpiredCertsRevocationInfo()));

                // Check of the associated conditions to identify the qualifiers
                final List<String> qualifiers = serviceInfo.getQualifiers(certToken.getCertificate());
                if (!qualifiers.isEmpty()) {

                    final XmlQualifiers xmlQualifiers = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlQualifiers();
                    for (String qualifier : qualifiers) {

                        xmlQualifiers.getQualifier().add(qualifier);
                    }
                    xmlTSP.setQualifiers(xmlQualifiers);
                }
                break;
            }
        }
        xmlCert.setTrustedServiceProvider(xmlTSP);
    }

    /**
     * This method deals with the revocation data of a certificate. The retrieved information is transformed to the JAXB object.
     *
     * @param certToken
     * @param xmlCert
     */
    private void dealRevocationData(final CertificateToken certToken, final XmlCertificate xmlCert) {

        final XmlRevocationType xmlRevocation = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlRevocationType();
        final RevocationToken revocationToken = certToken.getRevocationToken();
        if (revocationToken != null) {

            final Boolean revocationTokenStatus = revocationToken.getStatus();
            // revocationTokenStatus can be null when OCSP return Unknown. In this case we set status to false.
            xmlRevocation.setStatus(revocationTokenStatus == null ? false : revocationTokenStatus);
            xmlRevocation.setDateTime(DSSXMLUtils.createXMLGregorianCalendar(revocationToken.getRevocationDate()));
            xmlRevocation.setReason(revocationToken.getReason());
            xmlRevocation.setIssuingTime(DSSXMLUtils.createXMLGregorianCalendar(revocationToken.getIssuingTime()));
            xmlRevocation.setNextUpdate(DSSXMLUtils.createXMLGregorianCalendar(revocationToken.getNextUpdate()));
            xmlRevocation.setSource(revocationToken.getClass().getSimpleName());
            xmlRevocation.setSourceAddress(revocationToken.getSourceURL());

            final XmlBasicSignatureType xmlBasicSignatureType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlBasicSignatureType();
            final SignatureAlgorithm revocationSignatureAlgo = revocationToken.getSignatureAlgo();
            final boolean unknownAlgorithm = revocationSignatureAlgo == null || revocationSignatureAlgo.getEncryptionAlgo() == null;
            final String encryptionAlgorithmName = unknownAlgorithm ? "?" : revocationSignatureAlgo.getEncryptionAlgo().getName();
            xmlBasicSignatureType.setEncryptionAlgoUsedToSignThisToken(encryptionAlgorithmName);
            final String keyLength = revocationToken.getKeyLength();
            xmlBasicSignatureType.setKeyLengthUsedToSignThisToken(keyLength);
            xmlBasicSignatureType.setDigestAlgoUsedToSignThisToken(revocationSignatureAlgo.getDigestAlgo().getName());
            final boolean signatureValid = revocationToken.isSignatureValid();
            xmlBasicSignatureType.setReferenceDataFound(signatureValid);
            xmlBasicSignatureType.setReferenceDataIntact(signatureValid);
            xmlBasicSignatureType.setSignatureIntact(signatureValid);
            xmlBasicSignatureType.setSignatureValid(signatureValid);
            xmlRevocation.setBasicSignature(xmlBasicSignatureType);

            final CertificateToken issuerToken = revocationToken.getIssuerToken();
            final XmlSigningCertificateType xmlRevocationSignCert = xmlForSigningCertificate(issuerToken, revocationToken.isSignatureValid());
            xmlRevocation.setSigningCertificate(xmlRevocationSignCert);

            final XmlCertificateChainType xmlCertChainType = xmlForCertificateChain(issuerToken);
            xmlRevocation.setCertificateChain(xmlCertChainType);

            final List<String> list = revocationToken.getValidationInfo();
            if (list.size() > 0) {

                final XmlInfoType xmlInfo = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlInfoType();
                for (String message : list) {

                    final XmlMessage xmlMessage = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlMessage();
                    xmlMessage.setId(0);
                    xmlMessage.setValue(message);
                    xmlInfo.getMessage().add(xmlMessage);
                }
                xmlRevocation.setInfo(xmlInfo);
            }
            xmlCert.setRevocation(xmlRevocation);
        }
    }

    /**
     * This method deals with the signature policy. The retrieved information is transformed to the JAXB object.
     *
     * @param signature
     * @param xmlSignature
     */
    private void dealPolicy(final AdvancedSignature signature, final XmlSignature xmlSignature) {

        final SignaturePolicy signaturePolicy = signature.getPolicyId();
        if (signaturePolicy == null) {

            return;
        }

        final XmlPolicy xmlPolicy = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlPolicy();
        xmlSignature.setPolicy(xmlPolicy);

        final String policyId = signaturePolicy.getPolicyId();
        xmlPolicy.setId(policyId);

        final String policyUrl = signaturePolicy.getUrl();
        xmlPolicy.setUrl(policyUrl);

        final String notice = signaturePolicy.getNotice();
        xmlPolicy.setNotice(notice);

        /**
         * ETSI 102 853:
         * 3) Obtain the digest of the resulting document against which the digest value present in the property/attribute will be checked:
         */
        if (policyDocument == null && (policyUrl == null || policyUrl.isEmpty())) {

            xmlPolicy.setIdentified(false);
            if (policyId.isEmpty()) {

                xmlPolicy.setStatus(true);
            } else {

                xmlPolicy.setStatus(false);
            }
            return;
        }
        xmlPolicy.setIdentified(true);

        byte[] policyBytes = null;
        try {

            if (policyDocument == null) {

                final HTTPDataLoader dataLoader = certVerifier.getDataLoader();
                policyBytes = dataLoader.get(policyUrl);
            } else {

                policyBytes = DSSUtils.toByteArray(policyDocument);
            }
        } catch (Exception e) {
            // When any error (communication) we just set the status to false
            xmlPolicy.setStatus(false);
            xmlPolicy.setProcessingError(e.toString());
            //Do nothing
            LOG.warn(e.toString());
            return;
        }

        DigestAlgorithm signPolicyHashAlgFromPolicy = null;
        String policyDigestHexValueFromPolicy = null;
        String recalculatedDigestHexValue = null;
        /**
         * a)
         * If the resulting document is based on TR 102 272 [i.2] (ESI: ASN.1 format for signature policies), use the digest value present in the
         * SignPolicyDigest element from the resulting document. Check that the digest algorithm indicated
         * in the SignPolicyDigestAlg from the resulting document is equal to the digest algorithm indicated in the property.
         * // TODO: (Bob: 2013 Dec 10) ETSI to be notified: it is signPolicyHashAlg and not SignPolicyDigestAlg
         */
        try {

            final ASN1Sequence asn1Sequence = DSSASN1Utils.toASN1Primitive(policyBytes);
            final ASN1Sequence signPolicyHashAlgObject = (ASN1Sequence) asn1Sequence.getObjectAt(0);
            final AlgorithmIdentifier signPolicyHashAlgIdentifier = AlgorithmIdentifier.getInstance(signPolicyHashAlgObject);
            final String signPolicyHashAlgOID = signPolicyHashAlgIdentifier.getAlgorithm().getId();
            signPolicyHashAlgFromPolicy = DigestAlgorithm.forOID(signPolicyHashAlgOID);

            final ASN1Sequence signPolicyInfo = (ASN1Sequence) asn1Sequence.getObjectAt(1);
            //signPolicyInfo.getObjectAt(1);

            final ASN1OctetString signPolicyHash = (ASN1OctetString) asn1Sequence.getObjectAt(2);
            final byte[] policyDigestValueFromPolicy = signPolicyHash.getOctets();
            policyDigestHexValueFromPolicy = DSSUtils.toHex(policyDigestValueFromPolicy);

            final byte[] hashAlgorithmDEREncoded = DSSASN1Utils.getEncoded(signPolicyHashAlgIdentifier);
            final byte[] signPolicyInfoDEREncoded = DSSASN1Utils.getEncoded(signPolicyInfo);
            final byte[] recalculatedDigestValue = DSSUtils.digest(signPolicyHashAlgFromPolicy, hashAlgorithmDEREncoded, signPolicyInfoDEREncoded);
            recalculatedDigestHexValue = DSSUtils.toHex(recalculatedDigestValue);

            /**
             * b)
             * If the resulting document is based on TR 102 038 [i.3] ((ESI) XML format for signature policies), use the digest value present in
             * signPolicyHash element from the resulting document. Check that the digest
             * algorithm indicated in the signPolicyHashAlg from the resulting document is equal to the digest algorithm indicated in the attribute.
             */

            /**
             * c)
             * In all other cases, compute the digest using the digesting algorithm indicated in the children of the property/attribute.
             */

            String policyDigestValueFromSignature = signaturePolicy.getDigestValue();
            policyDigestValueFromSignature = policyDigestValueFromSignature.toUpperCase();

            /**
             * The use of a zero-sigPolicyHash value is to ensure backwards compatibility with earlier versions of the
             * current document. If sigPolicyHash is zero, then the hash value should not be checked against the
             * calculated hash value of the signature policy.
             */

            final DigestAlgorithm signPolicyHashAlgFromSignature = signaturePolicy.getDigestAlgorithm();
            if (!signPolicyHashAlgFromPolicy.equals(signPolicyHashAlgFromSignature)) {

                xmlPolicy.setProcessingError(
                      "The digest algorithm indicated in the SignPolicyHashAlg from the resulting document (" + signPolicyHashAlgFromPolicy + ") is not equal to the digest " +
                            "algorithm (" + signPolicyHashAlgFromSignature + ").");
                xmlPolicy.setDigestAlgorithmsEqual(false);
                xmlPolicy.setStatus(false);
                return;
            }
            xmlPolicy.setDigestAlgorithmsEqual(true);

            boolean equal = policyDigestValueFromSignature.equals(recalculatedDigestHexValue);
            xmlPolicy.setStatus(equal);
            if (!equal) {

                xmlPolicy.setProcessingError(
                      "The policy digest value (" + policyDigestValueFromSignature + ") does not match the re-calculated digest value (" + recalculatedDigestHexValue + ").");
            }
        } catch (RuntimeException e) {
            // When any error (communication) we just set the status to false
            xmlPolicy.setStatus(false);
            xmlPolicy.setProcessingError(e.toString());
            //Do nothing
            LOG.warn(e.toString());
        }
    }

    /**
     * This method deals with the basic signature data. The retrieved information is transformed to the JAXB object. The signing certificate token is returned if found.
     *
     * @param signature
     * @param xmlSignature
     * @return
     */
    private CertificateToken dealSignature(final AdvancedSignature signature, final XmlSignature xmlSignature) {

        final SigningCertificateValidity signingCertificate = dealSigningCertificate(signature, xmlSignature);
        dealSignatureCryptographicIntegrity(signature, xmlSignature);
        xmlSignature.setId(signature.getId());
        xmlSignature.setDateTime(DSSXMLUtils.createXMLGregorianCalendar(signature.getSigningTime()));
        final SignatureLevel dataFoundUpToLevel = signature.getDataFoundUpToLevel();
        final String value = dataFoundUpToLevel == null ? "UNKNOWN" : dataFoundUpToLevel.name();
        xmlSignature.setSignatureFormat(value);
        final SignatureProductionPlace signatureProductionPlace = signature.getSignatureProductionPlace();
        if (signatureProductionPlace != null) {

            final XmlSignatureProductionPlace xmlSignatureProductionPlace = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSignatureProductionPlace();
            xmlSignatureProductionPlace.setCountryName(signatureProductionPlace.getCountryName());
            xmlSignatureProductionPlace.setStateOrProvince(signatureProductionPlace.getStateOrProvince());
            xmlSignatureProductionPlace.setPostalCode(signatureProductionPlace.getPostalCode());
            xmlSignatureProductionPlace.setAddress(signatureProductionPlace.getAddress());
            xmlSignatureProductionPlace.setCity(signatureProductionPlace.getCity());
            xmlSignature.setSignatureProductionPlace(xmlSignatureProductionPlace);
        }

        final CommitmentType commitmentTypeIndication = signature.getCommitmentTypeIndication();
        if (commitmentTypeIndication != null) {

            final XmlCommitmentTypeIndication xmlCommitmentTypeIndication = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlCommitmentTypeIndication();
            final List<String> xmlIdentifiers = xmlCommitmentTypeIndication.getIdentifier();

            final List<String> identifiers = commitmentTypeIndication.getIdentifiers();
            for (final String identifier : identifiers) {

                xmlIdentifiers.add(identifier);
            }
            xmlSignature.setCommitmentTypeIndication(xmlCommitmentTypeIndication);
        }

        final String[] claimedRoles = signature.getClaimedSignerRoles();
        if (claimedRoles != null && claimedRoles.length > 0) {

            final XmlClaimedRoles xmlClaimedRoles = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlClaimedRoles();
            for (final String claimedRole : claimedRoles) {

                xmlClaimedRoles.getClaimedRole().add(claimedRole);
            }
            xmlSignature.setClaimedRoles(xmlClaimedRoles);
        }

        final String contentType = signature.getContentType();
        xmlSignature.setContentType(contentType);

        final String contentIdentifier = signature.getContentIdentifier();
        xmlSignature.setContentIdentifier(contentIdentifier);

        final String contentHints = signature.getContentHints();
        xmlSignature.setContentHints(contentHints);

        final List<CertifiedRole> certifiedRoles = signature.getCertifiedSignerRoles();
        if (certifiedRoles != null && !certifiedRoles.isEmpty()) {

            for (final CertifiedRole certifiedRole : certifiedRoles) {

                final XmlCertifiedRolesType xmlCertifiedRolesType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlCertifiedRolesType();

                xmlCertifiedRolesType.setCertifiedRole(certifiedRole.getRole());
                xmlCertifiedRolesType.setNotBefore(DSSXMLUtils.createXMLGregorianCalendar(certifiedRole.getNotBefore()));
                xmlCertifiedRolesType.setNotAfter(DSSXMLUtils.createXMLGregorianCalendar(certifiedRole.getNotAfter()));
                xmlSignature.getCertifiedRoles().add(xmlCertifiedRolesType);
            }
        }

        final XmlBasicSignatureType xmlBasicSignature = getXmlBasicSignatureType(xmlSignature);
        final EncryptionAlgorithm encryptionAlgorithm = signature.getEncryptionAlgo();
        final String encryptionAlgorithmString = encryptionAlgorithm == null ? "?" : encryptionAlgorithm.getName();
        xmlBasicSignature.setEncryptionAlgoUsedToSignThisToken(encryptionAlgorithmString);
        final CertificateToken signingCertificateToken = signingCertificate.getCertToken();
        final int keyLength = signingCertificateToken.getPublicKeyLength();
        xmlBasicSignature.setKeyLengthUsedToSignThisToken(String.valueOf(keyLength));
        final DigestAlgorithm digestAlgorithm = signature.getDigestAlgo();
        final String digestAlgorithmString = digestAlgorithm == null ? "?" : digestAlgorithm.getName();
        xmlBasicSignature.setDigestAlgoUsedToSignThisToken(digestAlgorithmString);
        xmlSignature.setBasicSignature(xmlBasicSignature);
        return signingCertificateToken;
    }

    private XmlBasicSignatureType getXmlBasicSignatureType(XmlSignature xmlSignature) {
        XmlBasicSignatureType xmlBasicSignature = xmlSignature.getBasicSignature();
        if (xmlBasicSignature == null) {

            xmlBasicSignature = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlBasicSignatureType();
        }
        return xmlBasicSignature;
    }

    /**
     * This method verifies the cryptographic integrity of the signature: the references are identified, their digest is checked and then the signature itself. The result of these
     * verifications is transformed to the JAXB representation.
     *
     * @param signature
     * @param xmlSignature
     */
    private void dealSignatureCryptographicIntegrity(final AdvancedSignature signature, final XmlSignature xmlSignature) {

        final SignatureCryptographicVerification scv = signature.checkIntegrity(this.externalContent);
        final XmlBasicSignatureType xmlBasicSignature = getXmlBasicSignatureType(xmlSignature);
        xmlBasicSignature.setReferenceDataFound(scv.isReferenceDataFound());
        xmlBasicSignature.setReferenceDataIntact(scv.isReferenceDataIntact());
        xmlBasicSignature.setSignatureIntact(scv.isSignatureIntact());
        xmlBasicSignature.setSignatureValid(scv.isSignatureValid());
        xmlSignature.setBasicSignature(xmlBasicSignature);
        if (!scv.getErrorMessage().isEmpty()) {

            xmlSignature.setErrorMessage(scv.getErrorMessage());
        }
    }

    /**
     * This method finds the signing certificate and creates its JAXB object representation. The signing certificate used to produce the main signature (signature being analysed).
     * If the signToken is null (the signing certificate was not found) then Id is set to 0.
     *
     * @param signature
     * @param xmlSignature
     * @return
     */
    private SigningCertificateValidity dealSigningCertificate(final AdvancedSignature signature, final XmlSignature xmlSignature) {

        final SigningCertificateValidity signingCertificateValidity = signature.getSigningCertificateValidity();
        final XmlSigningCertificateType xmlSignCertType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSigningCertificateType();
        final CertificateToken signingCertificateToken = signingCertificateValidity.getCertToken();
        if (signingCertificateToken != null) {

            xmlSignCertType.setId(signingCertificateToken.getDSSId());
        }
        xmlSignCertType.setDigestValueMatch(signingCertificateValidity.isDigestMatch());
        final boolean issuerSerialMatch = signingCertificateValidity.isSerialNumberMatch() && signingCertificateValidity.isNameMatch();
        xmlSignCertType.setIssuerSerialMatch(issuerSerialMatch);
        xmlSignature.setSigningCertificate(xmlSignCertType);
        return signingCertificateValidity;
    }

/*
    TODO: (Bob) Old code to be adapted when we are ready to handle the countersignatures.

    protected SignatureVerification[] verifyCounterSignatures(final AdvancedSignature signature, final ValidationContext ctx) {

        final List<AdvancedSignature> counterSignatures = signature.getCounterSignatures();

        if (counterSignatures == null) {
            return null;
        }

        final List<SignatureVerification> counterSigVerifs = new ArrayList<SignatureVerification>();
        for (final AdvancedSignature counterSig : counterSignatures) {

            final Result counterSigResult;
            try {

                final SignatureCryptographicVerification scv = counterSig.checkIntegrity(getExternalContent());
                counterSigResult = new Result(scv.signatureValid());
            } catch (DSSException e) {
                throw new RuntimeException(e);
            }
            final String counterSigAlg = counterSig.getEncryptionAlgo().getName();
            counterSigVerifs.add(new SignatureVerification(counterSigResult, counterSigAlg, signature.getId()));
        }

        final SignatureVerification[] ret = new SignatureVerification[counterSigVerifs.size()];
        return counterSigVerifs.toArray(ret);
    }
*/

    protected XmlSigningCertificateType xmlForSigningCertificate(final CertificateToken certificateToken, boolean signatureValid) {

        if (certificateToken != null) {

            final XmlSigningCertificateType xmlSignCertType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSigningCertificateType();

            xmlSignCertType.setId(certificateToken.getDSSId());
            /**
             * FIXME: The fact that it is not possible to validate the CAdES signature following the ETSI TS 102 853 standard
             * requires us set the DigestValueMatch and IssuerSerialMatch to the same value as the result of the signature
             * validation.
             */
            xmlSignCertType.setDigestValueMatch(signatureValid);
            xmlSignCertType.setIssuerSerialMatch(signatureValid);
            return xmlSignCertType;
        }
        return null;
    }

    /**
     * @return The diagnostic data generated by the validateDocument method
     */
    @Override
    public DiagnosticData getDiagnosticData() {

        return diagnosticData;
    }

    /**
     * Returns the simple report. The method {@link #validateDocument()} or {@link #validateDocument(String)} must be called first.
     *
     * @return
     */
    @Override
    public SimpleReport getSimpleReport() {
        return simpleReport;
    }

    /**
     * Returns the detailed report. The method {@link #validateDocument()} or {@link #validateDocument(String)} must be called first.
     *
     * @return
     */
    @Override
    public DetailedReport getDetailedReport() {
        return detailedReport;
    }

    /**
     * Output to System.out the diagnosticData, detailedReport and SimpleReport.
     */
    @Override
    public void printReports() {

        System.out.println("----------------Diagnostic data-----------------");
        System.out.println(getDiagnosticData());

        System.out.println("----------------Validation report---------------");
        System.out.println(getDetailedReport());

        System.out.println("----------------Simple report-------------------");
        System.out.println(getSimpleReport());

        System.out.println("------------------------------------------------");
    }
}
