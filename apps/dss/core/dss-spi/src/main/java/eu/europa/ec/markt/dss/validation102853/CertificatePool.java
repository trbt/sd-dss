/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2014 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2014 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.validation102853.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

public interface CertificatePool extends Serializable {
    List<CertificateToken> getCertificateTokens();

    int getNumberOfCertificates();

    void merge(CertificatePool certPool);

    List<CertificateToken> get(X500Principal x500Principal);

    CertificateToken getInstance(X509Certificate x509Certificate, CertificateSourceType certificateSourceType);

    CertificateToken getInstance(X509Certificate x509Certificate, CertificateSourceType certificateSourceType, ServiceInfo serviceInfo);

    CertificateToken getInstance(X509Certificate x509Certificate, List<CertificateSourceType> certificateSourceTypes, List<ServiceInfo> services);
}
