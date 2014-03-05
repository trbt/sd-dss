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

package eu.europa.ec.markt.dss.validation.pades;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.validation.ocsp.OfflineOCSPSource;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;

/**
 * OCSPSource that retrieves the OCSPResp from a PAdES Signature
 *
 * @version $Revision: 3248 $ - $Date: 2013-12-18 17:02:03 +0100 (Wed, 18 Dec 2013) $
 */

public class PAdESOCSPSource extends OfflineOCSPSource {

    private static final Logger LOG = LoggerFactory.getLogger(PAdESOCSPSource.class);

    private final CAdESSignature cadesSignature;
    private PdfDict dssCatalog;

    /**
     * The default constructor for PAdESOCSPSource.
     *
     * @param cadesSignature
     * @param dssCatalog
     */
    public PAdESOCSPSource(CAdESSignature cadesSignature, PdfDict dssCatalog) {
        this.cadesSignature = cadesSignature;
        this.dssCatalog = dssCatalog;
    }

    @Override
    public List<BasicOCSPResp> getContainedOCSPResponses() {
        List<BasicOCSPResp> result = new ArrayList<BasicOCSPResp>();

        // add OSCPs from embedded cadesSignature
        if (cadesSignature != null) {
            final List<BasicOCSPResp> containedOCSPResponses = cadesSignature.getOCSPSource().getContainedOCSPResponses();
            result.addAll(containedOCSPResponses);
        }

        try {
            if (dssCatalog != null) {
                // Add OSCPs from DSS catalog (LT level)
                PdfArray ocspArray = dssCatalog.getAsArray("OCSPs");
                if (ocspArray != null) {
                    LOG.debug("Found oscpArray of size {}", ocspArray.size());

                    for (int ii = 0; ii < ocspArray.size(); ii++) {
                        final byte[] stream = ocspArray.getBytes(ii);
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("OSCP {} data = {}", ii, Hex.encodeHexString(stream));
                        }
                        final OCSPResp ocspResp = new OCSPResp(stream);
                        final BasicOCSPResp responseObject = (BasicOCSPResp) ocspResp.getResponseObject();
                        result.add(responseObject);
                    }
                } else {
                    LOG.debug("oscpArray is null");
                }
            }
            return result;
        } catch (IOException e) {
            throw new DSSException(e);
        } catch (OCSPException e) {
            throw new DSSException(e);
        }
    }
}
