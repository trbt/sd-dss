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

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;

public abstract class ExtensionBuilder extends XAdESBuilder {

    /**
     * Reference to the object in charge of certificates validation
     */
    protected CertificateVerifier certificateVerifier;

    /*
     * This object allows to access DOM signature representation using XPATH
     */
    protected XAdESSignature xadesSignature;

    /**
     * This field represents the current signature being extended.
     */
    protected Element currentSignatureDom;

    /**
     * This field represents the signature qualifying properties
     */
    protected Element qualifyingPropertiesDom;

    /**
     * This field represents the unsigned properties
     */
    protected Element unsignedPropertiesDom;

    /**
     * This field contains unsigned signature properties
     */
    protected Element unsignedSignaturePropertiesDom;

    protected ExtensionBuilder(CertificateVerifier certificateVerifier) {

        this.certificateVerifier = certificateVerifier;
    }

    /**
     * Returns or creates (if it does not exist) the UnsignedPropertiesType DOM object.
     *
     * @return
     * @throws DSSException
     */
    protected void ensureUnsignedProperties() throws DSSException {

        final NodeList qualifyingPropertiesNodeList = currentSignatureDom.getElementsByTagNameNS(xPathQueryHolder.XADES_NAMESPACE, "QualifyingProperties");
        if (qualifyingPropertiesNodeList.getLength() != 1) {

            throw new DSSException("The signature does not contain QualifyingProperties element (or contains more than one)! Extension is not possible.");
        }

        final int firstIndex = 0;
        qualifyingPropertiesDom = (Element) qualifyingPropertiesNodeList.item(firstIndex);

        final NodeList unsignedPropertiesNodeList = currentSignatureDom.getElementsByTagNameNS(xPathQueryHolder.XADES_NAMESPACE, "UnsignedProperties");
        if (unsignedPropertiesNodeList.getLength() == 1) {

            unsignedPropertiesDom = (Element) qualifyingPropertiesNodeList.item(firstIndex);
        } else if (unsignedPropertiesNodeList.getLength() == 0) {

            unsignedPropertiesDom = DSSXMLUtils.addElement(documentDom, qualifyingPropertiesDom, xPathQueryHolder.XADES_NAMESPACE, "xades:UnsignedProperties");
        } else {

            throw new DSSException("The signature contains more then one UnsignedProperties element! Extension is not possible.");
        }
    }

    /**
     * Returns or creates (if it does not exist) the UnsignedSignaturePropertiesType DOM object.
     *
     * @return
     * @throws DSSException
     */
    protected void ensureUnsignedSignatureProperties() throws DSSException {

        final NodeList unsignedSignaturePropertiesNodeList = currentSignatureDom.getElementsByTagNameNS(xPathQueryHolder.XADES_NAMESPACE, "UnsignedSignatureProperties");
        if (unsignedSignaturePropertiesNodeList.getLength() == 1) {

            final int firstIndex = 0;
            unsignedSignaturePropertiesDom = (Element) unsignedSignaturePropertiesNodeList.item(firstIndex);
        } else if (unsignedSignaturePropertiesNodeList.getLength() == 0) {

            unsignedSignaturePropertiesDom = DSSXMLUtils.addElement(documentDom, unsignedPropertiesDom, xPathQueryHolder.XADES_NAMESPACE, "xades:UnsignedSignatureProperties");
        } else {

            throw new DSSException("The signature contains more then one UnsignedSignatureProperties element! Extension is not possible.");
        }
    }

    /**
     * To be implemented a mechanism to determine whether it is possible to add the extension. In some cases it is
     * necessary to remove the existing extensions. This mechanism can be controlled by a flag (SigantureParameters).<br>
     * When the signature includes already an -A extension the fact to add a -T extension will temper the -A extension.
     *
     * @return
     */
    protected boolean canAddExtension() {

        // TODO: (Bob)
        return true;
    }
}
