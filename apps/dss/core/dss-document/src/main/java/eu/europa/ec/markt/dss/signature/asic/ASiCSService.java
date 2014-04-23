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

/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/trunk/buildtools/src/main/resources/eclipse/dss-java-code-template.xml $
 * $Revision: 672 $
 * $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 * $Author: hiedelch $
 */
package eu.europa.ec.markt.dss.signature.asic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.FileNameMap;
import java.net.URL;
import java.net.URLConnection;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.exception.DSSUnsupportedOperationException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.AbstractSignatureService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

/**
 * Implementation of DocumentSignatureService for ASiC-S documents.
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 */
public class ASiCSService extends AbstractSignatureService {

	private final static String ZIP_ENTRY_DETACHED_FILE = "detached-file";
	private final static String ZIP_ENTRY_MIMETYPE = "mimetype";
	private final static String ZIP_ENTRY_METAINF_XADES_SIGNATURE = "META-INF/signatures.xml";
	private final static String ZIP_ENTRY_METAINF_CADES_SIGNATURE = "META-INF/signature.p7s";

	private final static String ASICS_EXTENSION = ".asics";
	private final static String ASICS_NS = "asic:XAdESSignatures";
	private final static String ASICS_URI = "http://uri.etsi.org/2918/v1.2.1#";

	private TSPSource tspSource;

	/**
	 * To construct a signature service the <code>CertificateVerifier</code> must be set and cannot be null.
	 *
	 * @param certificateVerifier
	 */
	public ASiCSService(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	/**
	 * Creates a specific XAdES signature parameters on base of the provided parameters. Forces the signature packaging to
	 * DETACHED
	 *
	 * @param parameters must provide signingToken, PrivateKeyEntry and date
	 * @return new specific instance for XAdES
	 */
	private SignatureParameters getParameters(final SignatureParameters parameters) {

		final SignatureParameters specificParameters = new SignatureParameters(parameters);
		final SignatureLevel asicProfile = parameters.getSignatureLevel();
		final SignatureForm asicSignatureForm = parameters.aSiC().getAsicSignatureForm();
		SignatureLevel specificLevel;
		switch (asicProfile) {

			case ASiC_S_BASELINE_B:
				specificLevel = asicSignatureForm == SignatureForm.XAdES ? SignatureLevel.XAdES_BASELINE_B : SignatureLevel.CAdES_BASELINE_B;
				break;
			case ASiC_S_BASELINE_T:
				specificLevel = asicSignatureForm == SignatureForm.XAdES ? SignatureLevel.XAdES_BASELINE_T : SignatureLevel.CAdES_BASELINE_T;
				break;
			case ASiC_S_BASELINE_LT:
				specificLevel = asicSignatureForm == SignatureForm.XAdES ? SignatureLevel.XAdES_BASELINE_LT : SignatureLevel.CAdES_BASELINE_LT;
				break;
			case ASiC_S_BASELINE_LTA:
				specificLevel = asicSignatureForm == SignatureForm.XAdES ? SignatureLevel.XAdES_BASELINE_LTA : SignatureLevel.CAdES_BASELINE_LTA;
				break;
			case ASiC_E_BASELINE_B:
				specificLevel = asicSignatureForm == SignatureForm.XAdES ? SignatureLevel.XAdES_BASELINE_B : SignatureLevel.CAdES_BASELINE_B;
				break;
			case ASiC_E_BASELINE_T:
				specificLevel = asicSignatureForm == SignatureForm.XAdES ? SignatureLevel.XAdES_BASELINE_T : SignatureLevel.CAdES_BASELINE_T;
				break;
			case ASiC_E_BASELINE_LT:
				specificLevel = asicSignatureForm == SignatureForm.XAdES ? SignatureLevel.XAdES_BASELINE_LT : SignatureLevel.CAdES_BASELINE_LT;
				break;
			default:
				throw new DSSException("Unsupported format: " + asicProfile.name());
		}
		specificParameters.setSignatureLevel(specificLevel);
		specificParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		return specificParameters;
	}

	@Override
	public void setTspSource(TSPSource tspSource) {

		this.tspSource = tspSource;
	}

	/**
	 * ETSI TS 102 918 v1.2.1 (2012-02) <br />
	 * <p>
	 * Contents of Container ( 6.2.2 )
	 * </p>
	 * <ul>
	 * <li>The file extension ".asics" should be used .</li>
	 * <li>The root element of each signature content shall be either &lt;asic:XadESSignatures&gt; as specified in clause
	 * A.5. Its the recommended format</li>
	 * <li>The comment field in the ZIP header may be used to identify the type of the data object within the container.
	 * <br />
	 * If this field is present, it should be set with "mimetype=" followed by the mime type of the data object held in
	 * the signed data object</li>
	 * <li>The mimetype file can be used to support operating systems that rely on some content in specific positions in
	 * a file.<br />
	 * <ul>
	 * <li>It has to be the first entry in the archive.</li>
	 * <li>It cannot contain "Extra fields".</li>
	 * <li>It cannot be compressed or encrypted inside the ZIP file</li>
	 * </ul>
	 * </li>
	 * </ul>
	 */
	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters, final byte[] signatureValue) throws DSSException {

		assertSigningDateInCertificateValidityRange(parameters);

		// Signs the toSignDocument first
		final SignatureParameters specificParameters = getParameters(parameters);
		specificParameters.setOriginalDocument(toSignDocument);

		final DocumentSignatureService underlyingService = getSpecificService(specificParameters);
		final DSSDocument signature = underlyingService.signDocument(toSignDocument, specificParameters, signatureValue);

		final SignatureForm asicSignatureForm = specificParameters.aSiC().getAsicSignatureForm();


		final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
		final ZipOutputStream outZip = new ZipOutputStream(outBytes);

		// Zip comment
		if (specificParameters.aSiC().isAsicComment() && DSSUtils.isNotEmpty(toSignDocument.getName())) {

			if (!System.getProperties().containsKey("content.types.user.table")) {
				final URL contentTypeURL = this.getClass().getResource("/custom-content-types.properties");
				if (contentTypeURL != null) {
					System.setProperty("content.types.user.table", contentTypeURL.getPath());
				}
			}

			final FileNameMap fileNameMap = URLConnection.getFileNameMap();
			final String containedFileMimeType = fileNameMap.getContentTypeFor(toSignDocument.getName());
			outZip.setComment("mimetype=" + containedFileMimeType);
		}

		// Stores the ASiC mime-type
		final String aSiCMimeType = MimeType.ASICS.getCode();
		final ZipEntry entryMimetype = new ZipEntry(ZIP_ENTRY_MIMETYPE);
		entryMimetype.setMethod(ZipEntry.STORED);
		entryMimetype.setSize(aSiCMimeType.getBytes().length);
		entryMimetype.setCompressedSize(aSiCMimeType.getBytes().length);
		final CRC32 crc = new CRC32();
		crc.update(aSiCMimeType.getBytes());
		entryMimetype.setCrc(crc.getValue());
		try {
			outZip.putNextEntry(entryMimetype);
			outZip.write(aSiCMimeType.getBytes());

			// Stores the original toSignDocument
			final ZipEntry entryDocument = new ZipEntry(toSignDocument.getName() != null ? toSignDocument.getName() : ZIP_ENTRY_DETACHED_FILE);
			outZip.setLevel(ZipEntry.DEFLATED);
			outZip.putNextEntry(entryDocument);
			DSSUtils.copy(toSignDocument.openStream(), outZip);

			// Stores the signature
			if (SignatureForm.XAdES.equals(asicSignatureForm)) {

				final ZipEntry entrySignature = new ZipEntry(ZIP_ENTRY_METAINF_XADES_SIGNATURE);
				outZip.putNextEntry(entrySignature);
				// Creates the XAdES signature
				final Document xmlSignatureDoc = DSSXMLUtils.buildDOM(signature);
				final Element documentElement = xmlSignatureDoc.getDocumentElement();
				final Element xmlSignatureElement = (Element) xmlSignatureDoc.removeChild(documentElement);

				final Document xmlXAdESDoc = DSSXMLUtils.createDocument(ASICS_URI, ASICS_NS, xmlSignatureElement);
				TransformerFactory.newInstance().newTransformer().transform(new DOMSource(xmlXAdESDoc), new StreamResult(outZip));
			} else if (SignatureForm.CAdES.equals(asicSignatureForm)) {

				final ZipEntry entrySignature = new ZipEntry(ZIP_ENTRY_METAINF_CADES_SIGNATURE);
				outZip.putNextEntry(entrySignature);
				DSSUtils.copy(signature.openStream(), outZip);
			} else {
				throw new DSSUnsupportedOperationException(asicSignatureForm.name() + ": This form of the signature is not supported.");
			}
			// Finishes the ZIP (with implicit finish/flush)
			outZip.close();

			// return the new toSignDocument = ASiC-S
			final byte[] documentBytes = outBytes.toByteArray();
			final String name = toSignDocument.getName() != null ? toSignDocument.getName() + ASICS_EXTENSION : null;
			final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes, name, MimeType.ASICS);
			return inMemoryDocument;
		} catch (Exception e) {

			throw new DSSException(e);
		}

	}

	@Override
	@Deprecated
	public InputStream toBeSigned(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		final byte[] dataToSign = getDataToSign(toSignDocument, parameters);
		final InputStream toSignInputStream = DSSUtils.toInputStream(dataToSign);
		return toSignInputStream;
	}

	@Override
	public byte[] getDataToSign(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		final SignatureParameters specificParameters = getParameters(parameters);
		final DocumentSignatureService signatureService = getSpecificService(specificParameters);
		return signatureService.getDataToSign(toSignDocument, specificParameters);
	}

	protected DocumentSignatureService getSpecificService(final SignatureParameters specificParameters) {

		final SignatureForm asicSignatureForm = specificParameters.aSiC().getAsicSignatureForm();
		final DocumentSignatureService underlyingASiCService = specificParameters.getContext().getUnderlyingASiCService(certificateVerifier, asicSignatureForm);
		underlyingASiCService.setTspSource(tspSource);
		return underlyingASiCService;
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		final byte[] dataToSign = getDataToSign(toSignDocument, parameters);
		final SignatureTokenConnection signingToken = parameters.getSigningToken();
		if (signingToken == null) {

			throw new DSSNullException(SignatureTokenConnection.class);
		}
		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		final DSSPrivateKeyEntry privateKeyEntry = parameters.getPrivateKeyEntry();
		final byte[] signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKeyEntry);
		final DSSDocument dssDocument = signDocument(toSignDocument, parameters, signatureValue);
		return dssDocument;
	}

	@Override
	public DSSDocument extendDocument(final DSSDocument toExtendDocument, final SignatureParameters parameters) throws DSSException {

		try {

			final SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(toExtendDocument);
			final DSSDocument signature = validator.getDocument();
			DSSDocument originalDocument = parameters.getOriginalDocument();
			if (validator.getExternalContent() == null) {

				validator.setExternalContent(originalDocument);
			} else {
				originalDocument = validator.getExternalContent();
			}

			final DocumentSignatureService specificService = getSpecificService(parameters);
			specificService.setTspSource(tspSource);

			final SignatureParameters xadesParameters = getParameters(parameters);
			xadesParameters.setOriginalDocument(originalDocument);
			final DSSDocument signedDocument = specificService.extendDocument(signature, xadesParameters);

			final ByteArrayOutputStream output = new ByteArrayOutputStream();
			final ZipOutputStream zip = new ZipOutputStream(output);

			final ZipInputStream input = new ZipInputStream(toExtendDocument.openStream());
			ZipEntry entry = null;
			while ((entry = input.getNextEntry()) != null) {

				ZipEntry newEntry = new ZipEntry(entry.getName());
				if (ZIP_ENTRY_METAINF_XADES_SIGNATURE.equals(entry.getName())) {

					zip.putNextEntry(newEntry);
					DSSUtils.copy(signedDocument.openStream(), zip);
				} else {

					zip.putNextEntry(newEntry);
					DSSUtils.copy(input, zip);
				}

			}
			zip.close();
			return new InMemoryDocument(output.toByteArray());
		} catch (IOException e) {

			throw new DSSException(e);
		}
	}
}
