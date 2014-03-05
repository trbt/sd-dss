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

package eu.europa.ec.markt.dss.validation102853.asic;

import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import eu.europa.ec.markt.dss.validation102853.xades.XMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;

/**
 * Validator for ASiC document
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 */
public class ASiCXMLDocumentValidator extends XMLDocumentValidator {

    /**
     * The default constructor for ASiCXMLDocumentValidator.
     *
     * @param document
     * @param signedContent
     * @param dataFileName
     * @throws DSSException
     */
    public ASiCXMLDocumentValidator(final DSSDocument document, final byte[] signedContent, final String dataFileName) throws DSSException {

        super(document);
        externalContent = new InMemoryDocument(signedContent, dataFileName);
    }

    @Override
    public List<AdvancedSignature> getSignatures() {

        if (signatures != null) {
            return signatures;
        }
        signatures = new ArrayList<AdvancedSignature>();
        final NodeList signatureNodeList = rootElement.getElementsByTagNameNS(XMLSignature.XMLNS, XPathQueryHolder.XMLE_SIGNATURE);
        for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

            final Element signatureEl = (Element) signatureNodeList.item(ii);
            final XAdESSignature xadesSignature = new XAdESSignature(signatureEl, xPathQueryHolders, validationCertPool);
            signatures.add(xadesSignature);
        }
        return signatures;
    }

}
