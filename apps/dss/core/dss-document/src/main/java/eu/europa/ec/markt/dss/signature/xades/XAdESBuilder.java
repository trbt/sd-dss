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

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;

public class XAdESBuilder {

    /**
     * This variable holds the {@code XPathQueryHolder} which contains all constants and queries needed to cope with the default signature schema.
     */
    protected final XPathQueryHolder xPathQueryHolder = new XPathQueryHolder();

    protected static final Logger LOG = LoggerFactory.getLogger(XAdESBuilder.class);

    /*
     * This variable is a reference to the set of parameters relating to the structure and process of the creation or
     * extension of the electronic signature.
     */
    protected SignatureParameters params;

    /**
     * This is the variable which represents the root XML document root (with signature).
     */
    protected Document documentDom;

    /**
     * This method creates the ds:DigestMethod DOM object
     *
     * @param parentDom
     * @param digestAlgorithm digest algorithm xml identifier
     */
    protected void incorporateDigestMethod(final Element parentDom, final DigestAlgorithm digestAlgorithm) {

        // <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        final Element digestMethodDom = documentDom.createElementNS(xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:DigestMethod");
        final String digestAlgorithmXmlId = digestAlgorithm.getXmlId();
        digestMethodDom.setAttribute("Algorithm", digestAlgorithmXmlId);
        parentDom.appendChild(digestMethodDom);
    }

    /**
     * This method creates the ds:DigestValue DOM object.
     *
     * @param parentDom
     * @param digestAlgorithm digest algorithm
     * @param toDigestBytes   to digest array of bytes
     */
    protected void incorporateDigestValue(final Element parentDom, final DigestAlgorithm digestAlgorithm, final byte[] toDigestBytes) {

        // <ds:DigestValue>b/JEDQH2S1Nfe4Z3GSVtObN34aVB1kMrEbVQZswThfQ=</ds:DigestValue>
        final Element digestValueDom = documentDom.createElementNS(xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:DigestValue");
        final byte[] digestBytes = DSSUtils.digest(digestAlgorithm, toDigestBytes);
        final String base64EncodedDigestBytes = DSSUtils.base64Encode(digestBytes);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Digest value             --> " + base64EncodedDigestBytes);
        }
        final Text textNode = documentDom.createTextNode(base64EncodedDigestBytes);
        digestValueDom.appendChild(textNode);
        parentDom.appendChild(digestValueDom);
    }

    /**
     * Incorporates the certificate's reference as a child of the given parent node.
     *
     * @param signingCertificateDom
     * @param certificates
     */
    protected void incorporateCertificateRef(final Element signingCertificateDom, final List<X509Certificate> certificates) {

        final Element certDom = DSSXMLUtils.addElement(documentDom, signingCertificateDom, xPathQueryHolder.XADES_NAMESPACE, "xades:Cert");

        final Element certDigestDom = DSSXMLUtils.addElement(documentDom, certDom, xPathQueryHolder.XADES_NAMESPACE, "xades:CertDigest");

        final DigestAlgorithm signingCertificateDigestMethod = params.bLevel().getSigningCertificateDigestMethod();
        incorporateDigestMethod(certDigestDom, signingCertificateDigestMethod);

        for (final X509Certificate certificate : certificates) {

            final byte[] encodedSigningCertificate = DSSUtils.getEncoded(certificate);
            incorporateDigestValue(certDigestDom, signingCertificateDigestMethod, encodedSigningCertificate);

            final Element issuerSerialDom = DSSXMLUtils.addElement(documentDom, certDom, xPathQueryHolder.XADES_NAMESPACE, "xades:IssuerSerial");

            final Element x509IssuerNameDom = DSSXMLUtils.addElement(documentDom, issuerSerialDom, xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:X509IssuerName");
            final String issuerX500PrincipalName = DSSUtils.getIssuerX500PrincipalName(certificate);
            DSSXMLUtils.setTextNode(documentDom, x509IssuerNameDom, issuerX500PrincipalName);

            final Element x509SerialNumberDom = DSSXMLUtils.addElement(documentDom, issuerSerialDom, xPathQueryHolder.XMLDSIG_NAMESPACE, "ds:X509SerialNumber");
            final BigInteger serialNumber = certificate.getSerialNumber();
            final String serialNumberString = new String(serialNumber.toString());
            DSSXMLUtils.setTextNode(documentDom, x509SerialNumberDom, serialNumberString);
        }
    }
}