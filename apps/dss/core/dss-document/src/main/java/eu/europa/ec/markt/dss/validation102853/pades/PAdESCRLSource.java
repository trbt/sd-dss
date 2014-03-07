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

package eu.europa.ec.markt.dss.validation102853.pades;

import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

import eu.europa.ec.markt.dss.DSSPDFUtils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.validation102853.crl.OfflineCRLSource;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;

/**
 * CRLSource that will retrieve the CRL from a PAdES Signature
 *
 * @version $Revision: 3564 $ - $Date: 2014-03-06 16:19:24 +0100 (Thu, 06 Mar 2014) $
 */

public class PAdESCRLSource extends OfflineCRLSource {

    private final CAdESSignature cadesSignature;
    private final PdfDict dssCatalog;

    /**
     * The default constructor for PAdESCRLSource.
     *
     * @param cadesSignature
     * @param dssCatalog
     */
    public PAdESCRLSource(final CAdESSignature cadesSignature, final PdfDict dssCatalog) {
        this.cadesSignature = cadesSignature;
        this.dssCatalog = dssCatalog;
        extract();
    }

    private void extract() {
        x509CRLList = new ArrayList<X509CRL>();

        if (cadesSignature != null) {
            final List<X509CRL> cadesCrlSource = cadesSignature.getCRLSource().getContainedX509CRLs();
            x509CRLList.addAll(cadesCrlSource);
        }

        if (dssCatalog == null) {
            return;
        }

        final PdfArray crlArray = dssCatalog.getAsArray("CRLs");
        if (crlArray != null) {

            for (int ii = 0; ii < crlArray.size(); ii++) {

                final byte[] bytes = DSSPDFUtils.getBytes(crlArray, ii);
                final X509CRL x509CRL = DSSUtils.loadCRL(bytes);
                if (!x509CRLList.contains(x509CRL)) {
                    x509CRLList.add(x509CRL);
                }
            }
        }
    }
}
