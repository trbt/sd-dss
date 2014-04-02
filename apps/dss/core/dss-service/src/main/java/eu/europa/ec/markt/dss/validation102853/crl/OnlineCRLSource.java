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

package eu.europa.ec.markt.dss.validation102853.crl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.https.CommonsDataLoader;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;

/**
 * Online CRL repository. This CRL repository implementation will download the CRLs from the given CRL URIs.
 * Note that for the HTTP kind of URLs you can provide dedicated data loader. If the data loader is not provided the standard load from URI is
 * provided. For FTP the standard load from URI is provided. For LDAP kind of URLs an internal implementation using apache-ldap-api is provided.
 *
 * @version $Revision: 3588 $ - $Date: 2014-03-12 16:58:44 +0100 (Wed, 12 Mar 2014) $
 */

public class OnlineCRLSource extends CommonCRLSource {

    private static final Logger LOG = LoggerFactory.getLogger(OnlineCRLSource.class);

    private String preferredProtocol;

    private DataLoader dataLoader;

    /**
     * The default constructor. A {@code CommonsDataLoader is created}.
     */
    public OnlineCRLSource() {

        dataLoader = new CommonsDataLoader();
    }

    /**
     * This constructor allows to set the {@code DataLoader}.
     *
     * @param dataLoader
     */
    public OnlineCRLSource(final DataLoader dataLoader) {

        this.dataLoader = dataLoader;
    }

    /**
     * This method allows to set the preferred protocol. This parameter is used used when retrieving the CRL to choose the canal.<br/>
     * Possible values are: http, ldap, ftp
     *
     * @param preferredProtocol
     */
    public void setPreferredProtocol(final String preferredProtocol) {

        this.preferredProtocol = preferredProtocol;
    }

    /**
     * Set the DataLoader to use for query the CRL server
     *
     * @param urlDataLoader
     */
    public void setDataLoader(final DataLoader urlDataLoader) {

        this.dataLoader = urlDataLoader;
    }

    @Override
    public CRLToken findCrl(final CertificateToken certificateToken) throws DSSException {

        if (certificateToken == null) {

            return null;
        }
        final CertificateToken issuerToken = certificateToken.getIssuerToken();
        if (issuerToken == null) {

            return null;
        }
        final String crlUrl = getCrlUrl(certificateToken);
        LOG.info("CRL's URL for " + certificateToken.getAbbreviation() + " : " + crlUrl);
        if (crlUrl == null) {

            return null;
        }
        X509CRL x509CRL = downloadCrl(crlUrl);
        if (x509CRL == null) {
            return null;
        }
        final CRLValidity crlValidity = isValidCRL(x509CRL, issuerToken);
        final CRLToken crlToken = new CRLToken(certificateToken, crlValidity);
        crlToken.setSourceURL(crlUrl);
        return crlToken;
    }

    /**
     * Download a CRL from any location with any protocol.
     *
     * @param downloadUrl
     * @return
     */
    private X509CRL downloadCrl(final String downloadUrl) {

        if (downloadUrl != null) {

            try {

                final byte[] bytes = dataLoader.get(downloadUrl);
                final X509CRL crl = DSSUtils.loadCRL(bytes);
                return crl;
            } catch (DSSException e) {
                LOG.warn(e.getMessage());
            }
        }
        return null;
    }

    /**
     * Gives back the CRL URI meta-data found within the given X509 certificate.
     *
     * @param certificateToken the X509 certificate.
     * @return the CRL URI, or <code>null</code> if the extension is not present.
     * @throws DSSException
     */
    public String getCrlUrl(final CertificateToken certificateToken) throws DSSException {

        final byte[] crlDistributionPointsValue = certificateToken.getCRLDistributionPoints();
        if (null == crlDistributionPointsValue) {

            return null;
        }
        ASN1InputStream ais1 = null;
        ASN1InputStream ais2 = null;
        try {

            List<String> urls = new ArrayList<String>();
            final ByteArrayInputStream bais = new ByteArrayInputStream(crlDistributionPointsValue);
            ais1 = new ASN1InputStream(bais);
            final DEROctetString oct = (DEROctetString) (ais1.readObject());
            ais2 = new ASN1InputStream(oct.getOctets());
            final ASN1Sequence seq = (ASN1Sequence) ais2.readObject();
            final CRLDistPoint distPoint = CRLDistPoint.getInstance(seq);
            final DistributionPoint[] distributionPoints = distPoint.getDistributionPoints();
            for (final DistributionPoint distributionPoint : distributionPoints) {

                final DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
                if (DistributionPointName.FULL_NAME != distributionPointName.getType()) {

                    continue;
                }
                final GeneralNames generalNames = (GeneralNames) distributionPointName.getName();
                final GeneralName[] names = generalNames.getNames();
                for (final GeneralName name : names) {

                    if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {

                        LOG.debug("Not a uniform resource identifier");
                        continue;
                    }
                    final String urlStr;
                    if (name.toASN1Primitive() instanceof DERTaggedObject) {

                        final DERTaggedObject taggedObject = (DERTaggedObject) name.toASN1Primitive();
                        final DERIA5String derStr = DERIA5String.getInstance(taggedObject.getObject());
                        urlStr = derStr.getString();
                    } else {

                        final DERIA5String derStr = DERIA5String.getInstance(name.toASN1Primitive());
                        urlStr = derStr.getString();
                    }
                    urls.add(urlStr);
                }
                if (preferredProtocol != null) {

                    for (final String url : urls) {

                        if (url.startsWith(preferredProtocol)) {
                            return url;
                        }
                    }
                }
                if (urls.size() > 0) {

                    final String url = urls.get(0);
                    return url;
                }
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
