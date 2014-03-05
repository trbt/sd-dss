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

package eu.europa.ec.markt.dss.validation.ocsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;
import eu.europa.ec.markt.dss.validation.https.OCSPHttpDataLoader;

/**
 * Online OCSP repository. This implementation will contact the OCSP Responder to retrieve the OCSP response.
 *
 * @version $Revision: 3519 $ - $Date: 2014-02-27 07:49:02 +0100 (Thu, 27 Feb 2014) $
 */

public class OnlineOCSPSource implements OCSPSource {

    private static final Logger LOG = LoggerFactory.getLogger(OnlineOCSPSource.class);

    private HTTPDataLoader httpDataLoader;

    static {

        // TODO by meyerfr: shouldn't that be done once e.g. in an environment
        // initializer?
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Create an OCSP source The default constructor for OnlineOCSPSource. The default {@code OCSPHttpDataLoader} is set. It is possible to change it with {@code
     * #setHttpDataLoader}.
     */
    public OnlineOCSPSource() {

        httpDataLoader = new OCSPHttpDataLoader();
    }

    /**
     * Set the HTTPDataLoader to use for querying the OCSP server.
     *
     * @param httpDataLoader
     * @deprecated Use the {@link #setDataLoader(eu.europa.ec.markt.dss.validation.https.HTTPDataLoader)} instead
     */
    @Deprecated
    public void setHttpDataLoader(final HTTPDataLoader httpDataLoader) {

        this.httpDataLoader = httpDataLoader;
    }

    /**
     * Set the HTTPDataLoader to use for querying the OCSP server.
     *
     * @param httpDataLoader
     */
    public void setDataLoader(final HTTPDataLoader httpDataLoader) {

        this.httpDataLoader = httpDataLoader;
    }

    @Override
    public BasicOCSPResp getOCSPResponse(final X509Certificate cert, final X509Certificate issuerCert) {

        if (httpDataLoader == null) {

            throw new DSSException("The HTTPDataLoader must be set. Use setHttpDataLoader method first.");
        }
        try {

            final String ocspUri = getAccessLocation(cert);
            if (LOG.isDebugEnabled()) {
                LOG.debug("OCSP URI: " + ocspUri);
            }
            if (ocspUri == null) {

                return null;
            }
            final byte[] content = buildOCSPRequest(cert, issuerCert);

            final byte[] ocspRespBytes = httpDataLoader.post(ocspUri, content);

            //            System.out.println();
            //            System.out.println(DSSUtils.toHex(ocspRespBytes));
            //            System.out.println();

            final OCSPResp ocspResp = new OCSPResp(ocspRespBytes);
/*
            final int status = ocspResp.getStatus();
            System.out.println(status);
*/
            try {

                final BasicOCSPResp responseObject = (BasicOCSPResp) ocspResp.getResponseObject();
                return responseObject;
            } catch (NullPointerException e) {

                LOG.error(
                      "OCSP error: Encountered a case when the OCSPResp is initialised with a null OCSP response... (and there are no nullity checks in the OCSPResp implementation)",
                      e);
            }
        } catch (OCSPException e) {

            LOG.error("OCSP error: " + e.getMessage(), e);
        } catch (IOException e) {

            throw new DSSException(e);
        }
        return null;
    }

    private byte[] buildOCSPRequest(final X509Certificate cert, final X509Certificate issuerCert) throws DSSException {

        try {

            final CertificateID certId = DSSUtils.getOCSPCertificateID(cert, issuerCert);
            final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
            ocspReqBuilder.addRequest(certId);
            final OCSPReq ocspReq = ocspReqBuilder.build();
            final byte[] ocspReqData = ocspReq.getEncoded();
            return ocspReqData;
        } catch (OCSPException e) {
            throw new DSSException(e);
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    /**
     * Gives back the OCSP URI meta-data found within the given X509 cert.
     *
     * @param certificate the X509 cert.
     * @return the OCSP URI, or <code>null</code> if the extension is not present.
     * @throws DSSException
     */
    public String getAccessLocation(final X509Certificate certificate) throws DSSException {

        final ASN1ObjectIdentifier ocspAccessMethod = X509ObjectIdentifiers.ocspAccessMethod;
        final byte[] authInfoAccessExtensionValue = certificate.getExtensionValue(X509Extension.authorityInfoAccess.getId());
        if (null == authInfoAccessExtensionValue) {

            return null;
        }
        ASN1InputStream ais1 = null;
        ASN1InputStream ais2 = null;
        try {

            final ByteArrayInputStream bais = new ByteArrayInputStream(authInfoAccessExtensionValue);
            ais1 = new ASN1InputStream(bais);
            final DEROctetString oct = (DEROctetString) (ais1.readObject());
            ais2 = new ASN1InputStream(oct.getOctets());
            final AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(ais2.readObject());

            final AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
            for (AccessDescription accessDescription : accessDescriptions) {

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Access method: " + accessDescription.getAccessMethod());
                }
                final boolean correctAccessMethod = accessDescription.getAccessMethod().equals(ocspAccessMethod);
                if (!correctAccessMethod) {

                    continue;
                }
                final GeneralName gn = accessDescription.getAccessLocation();
                if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Not a uniform resource identifier");
                    }
                    continue;
                }
                final DERIA5String str = (DERIA5String) ((DERTaggedObject) gn.toASN1Primitive()).getObject();
                final String accessLocation = str.getString();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Access location: " + accessLocation);
                }
                return accessLocation;
            }
            return null;
        } catch (IOException e) {
            throw new DSSException(e);
        } finally {

            DSSUtils.closeQuietly(ais1);
            DSSUtils.closeQuietly(ais2);
        }
    }
}
