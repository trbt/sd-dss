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

package eu.europa.ec.markt.dss.signature;

import java.util.Date;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;

/**
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public abstract class AbstractSignatureService implements DocumentSignatureService {

    final protected CertificateVerifier certificateVerifier;

    /**
     * To construct a signature service the <code>CertificateVerifier</code> must be set and cannot be null.
     *
     * @param certificateVerifier
     */
    protected AbstractSignatureService(final CertificateVerifier certificateVerifier) {

        if (certificateVerifier == null) {

            throw new DSSNullException(CertificateVerifier.class);
        }
        this.certificateVerifier = certificateVerifier;
    }

    protected void assertSigningDateInCertificateValidityRange(final SignatureParameters parameters) {

        final Date signingDate = parameters.bLevel().getSigningDate();
        final Date notAfter = parameters.getSigningCertificate().getNotAfter();
        final Date notBefore = parameters.getSigningCertificate().getNotBefore();
        if (signingDate.after(notAfter) || signingDate.before(notBefore)) {
            throw new DSSException(
                  String.format("Signing Date (%s) is not in certificate validity range (%s, %s).", signingDate.toString(), notBefore.toString(), notAfter.toString()));
        }
    }
}
