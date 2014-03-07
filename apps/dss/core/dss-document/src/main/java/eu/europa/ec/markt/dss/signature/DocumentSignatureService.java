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

import java.io.InputStream;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

/**
 * Interface for DocumentSignatureService. Provides operations for sign/verify a document.
 *
 * @version $Revision: 3564 $ - $Date: 2014-03-06 16:19:24 +0100 (Thu, 06 Mar 2014) $
 */
public interface DocumentSignatureService {

    /**
     * Retrieves the stream of data that need to be signed.
     *
     * @param document   document to sign
     * @param parameters set of driving parameters
     * @return
     * @throws DSSException
     * @deprecated (Added in version 4) use {@code getDataToSign}
     */
    @Deprecated
    public InputStream toBeSigned(final DSSDocument document, final SignatureParameters parameters) throws DSSException;

    /**
     * Retrieves the stream of data that need to be signed. (Added in version 4)
     *
     *
     * @param document   document to sign
     * @param parameters set of driving parameters
     * @return
     * @throws DSSException
     */
    public byte[] getDataToSign(final DSSDocument document, final SignatureParameters parameters) throws DSSException;

    /**
     * Signs the document with the provided signatureValue.
     *
     * @param document       document to sign
     * @param parameters     set of driving parameters
     * @param signatureValue
     * @return
     * @throws DSSException
     */
    public DSSDocument signDocument(final DSSDocument document, final SignatureParameters parameters, final byte[] signatureValue) throws DSSException;

    /**
     * Signs the document in the single operation. it is possible when the private key is known on the server side or everything is done on the client side.
     *
     * @param document   document to sign
     * @param parameters set of driving parameters
     * @return
     * @throws DSSException
     */
    public DSSDocument signDocument(final DSSDocument document, final SignatureParameters parameters) throws DSSException;

    /**
     * Extends the level of the signatures in the document
     *
     * @param document   document to extend
     * @param parameters set of driving parameters
     * @return
     * @throws DSSException
     */
    public DSSDocument extendDocument(final DSSDocument document, final SignatureParameters parameters) throws DSSException;

    /**
     * This setter allows to define the TSP (timestamp provider) source.
     *
     * @param tspSource The time stamp source which is used when timestamping the signature.
     */
    public void setTspSource(final TSPSource tspSource);
}