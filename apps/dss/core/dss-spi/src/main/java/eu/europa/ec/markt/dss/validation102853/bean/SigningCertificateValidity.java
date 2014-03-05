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
package eu.europa.ec.markt.dss.validation102853.bean;

import java.security.cert.X509Certificate;

import eu.europa.ec.markt.dss.validation102853.CertificateToken;

public class SigningCertificateValidity {

    private CertificateToken certToken;
    private boolean digestMatch;
    private boolean SerialNumberMatch;
    private boolean nameMatch;

    public CertificateToken getCertToken() {
        return certToken;
    }

    public void setCertToken(final CertificateToken certToken) {
        this.certToken = certToken;
    }

    public boolean isDigestMatch() {
        return digestMatch;
    }

    public void setDigestMatch(final boolean digestMatch) {
        this.digestMatch = digestMatch;
    }

    public boolean isSerialNumberMatch() {
        return SerialNumberMatch;
    }

    public void setSerialNumberMatch(final boolean serialNumberMatch) {
        SerialNumberMatch = serialNumberMatch;
    }

    public X509Certificate getCertificate() {
        return certToken.getCertificate();
    }

    public void setNameMatch(final boolean nameMatch) {
        this.nameMatch = nameMatch;
    }

    public boolean isNameMatch() {
        return nameMatch;
    }

    public boolean isValid() {

        final boolean valid = isDigestMatch() && isNameMatch() && isSerialNumberMatch();
        return valid;
    }
}
