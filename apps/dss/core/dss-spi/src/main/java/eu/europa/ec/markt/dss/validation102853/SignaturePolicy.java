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

package eu.europa.ec.markt.dss.validation102853;

import eu.europa.ec.markt.dss.DigestAlgorithm;

/**
 * Represents the value of a SignaturePolicy
 *
 * @version $Revision: 3564 $ - $Date: 2014-03-06 16:19:24 +0100 (Thu, 06 Mar 2014) $
 */
public class SignaturePolicy {

    private String policyId;
    private DigestAlgorithm digestAlgorithm;
    private String digestValue;

    /**
     * Two qualifiers for the signature policy have been identified so far:
     * • a URL where a copy of the signature policy MAY be obtained;
     * • a user notice that should be displayed when the signature is verified.
     */
    private String url;
    private String notice;

    /**
     * The default constructor for SignaturePolicy.
     *
     * @param signaturePolicyId
     */
    public SignaturePolicy(final String signaturePolicyId) {
        this.policyId = signaturePolicyId;
    }

    /**
     * The default constructor for SignaturePolicy.
     */
    public SignaturePolicy() {
        this.policyId = "";
    }

    /**
     * @return the policyId
     */
    public String getPolicyId() {
        return policyId;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public String getDigestValue() {
        return digestValue;
    }

    public void setDigestValue(final String digestValue) {
        this.digestValue = digestValue;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(final String url) {
        this.url = url;
    }

    public String getNotice() {
        return notice;
    }

    public void setNotice(final String notice) {
        this.notice = notice;
    }

    @Override
    public String toString() {
        if (policyId == null) {
            return "NO_POLICY";
        } else if (policyId.equals("")) {
            return "IMPLICIT";
        } else {
            return policyId;
        }
    }

}
