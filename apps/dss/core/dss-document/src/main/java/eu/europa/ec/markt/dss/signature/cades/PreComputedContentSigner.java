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

package eu.europa.ec.markt.dss.signature.cades;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import eu.europa.ec.markt.dss.DSSUtils;

/**
 * ContentSigner using a provided pre-computed signature
 *
 * @version $Revision: 3659 $ - $Date: 2014-03-25 12:27:11 +0100 (Tue, 25 Mar 2014) $
 */

public class PreComputedContentSigner implements ContentSigner {

    private byte[] preComputedSignature;
    private final AlgorithmIdentifier algorithmIdentifier;

    private ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();

    /**
     * @param preComputedSignature the preComputedSignature to set
     */
    public PreComputedContentSigner(String algorithmIdentifier, byte[] preComputedSignature) {
        this.algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithmIdentifier);
        this.preComputedSignature = preComputedSignature;
    }

    /**
     * The default constructor for PreComputedContentSigner.
     *
     * @param algorithmIdentifier
     */
    public PreComputedContentSigner(String algorithmIdentifier) {
        this(algorithmIdentifier, DSSUtils.EMPTY_BYTE_ARRAY);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.bouncycastle.operator.ContentSigner#getAlgorithmIdentifier()
     */
    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public ByteArrayOutputStream getOutputStream() {
        return byteOutputStream;
    }

    @Override
    public byte[] getSignature() {
        return preComputedSignature;
    }

}