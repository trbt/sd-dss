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

package eu.europa.ec.markt.dss.validation.certificate;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSASN1Utils;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateSource;

/**
 * Implement a CertificateSource that retrieve the certificates from an OCSPResponse
 *
 * @version $Revision: 3113 $ - $Date: 2013-12-04 16:00:22 +0100 (Wed, 04 Dec 2013) $
 */

public class OCSPRespCertificateSource extends CommonCertificateSource {

    private static final Logger LOG = LoggerFactory.getLogger(OCSPRespCertificateSource.class);

    private BasicOCSPResp ocspResp;

    /**
     * The default constructor for OCSPRespCertificateSource. An independent <code>CertificatePool</code> is created.
     */
    public OCSPRespCertificateSource(BasicOCSPResp ocspResp) {

        super();
        this.ocspResp = ocspResp;
        extract();
    }

    /**
     * The default constructor for OCSPRespCertificateSource. An independent <code>CertificatePool</code> is created.
     */
    public OCSPRespCertificateSource(BasicOCSPResp ocspResp, CertificatePool certificatePool) {

        this.certPool = certificatePool;
        this.ocspResp = ocspResp;
        extract();
    }

    private List<CertificateToken> extract() {

        certificateTokens = new ArrayList<CertificateToken>();
        for (final X509CertificateHolder certificate : ocspResp.getCerts()) {

            final X509Certificate x509Certificate = DSSASN1Utils.getCertificate(certificate);
            final CertificateToken certToken = addCertificate(x509Certificate);
            certificateTokens.add(certToken);
        }
        return certificateTokens;
    }

    /**
     * This method returns the certificate source type associated to the implementation class.
     *
     * @return
     */
    protected CertificateSourceType getCertificateSourceType() {

        return CertificateSourceType.OCSP_RESPONSE;
    }
}
