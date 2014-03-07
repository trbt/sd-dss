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
import java.io.InputStream;
import java.net.URL;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.url.LdapUrl;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
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
import eu.europa.ec.markt.dss.validation102853.https.CommonsHttpDataLoader;
import eu.europa.ec.markt.dss.validation102853.loader.HTTPDataLoader;

/**
 * Online CRL repository. This CRL repository implementation will download the CRLs from the given CRL URIs.
 * Note that for the HTTP kind of URLs you can provide dedicated data loader. If the data loader is not provided the standard load from URI is
 * provided. For FTP the standard load from URI is provided. For LDAP kind of URLs an internal implementation using apache-ldap-api is provided.
 *
 * @version $Revision: 3568 $ - $Date: 2014-03-06 17:32:15 +0100 (Thu, 06 Mar 2014) $
 */

public class OnlineCRLSource extends CommonCRLSource {

    private static final Logger LOG = LoggerFactory.getLogger(OnlineCRLSource.class);

    private String preferredProtocol;

    private HTTPDataLoader dataLoader;

    /**
     * The default constructor. A {@code CommonsHttpDataLoader is created}.
     */
    public OnlineCRLSource() {

        dataLoader = new CommonsHttpDataLoader();
    }

    /**
     * This constructor allows to set the {@code HTTPDataLoader}.
     *
     * @param dataLoader
     */
    public OnlineCRLSource(final HTTPDataLoader dataLoader) {

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
     * Set the HTTPDataLoader to use for query the CRL server
     *
     * @param urlDataLoader
     */
    public void setDataLoader(final HTTPDataLoader urlDataLoader) {

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
        X509CRL x509CRL = null;
        boolean http = crlUrl.startsWith("http://") || crlUrl.startsWith("https://");
        if (dataLoader != null && http) {

            x509CRL = downloadCrlFromHTTP(crlUrl);
        } else if (http || crlUrl.startsWith("ftp://")) {

            x509CRL = downloadCRLFromURL(crlUrl);
        } else if (crlUrl.startsWith("ldap://")) {

            x509CRL = downloadCRLFromLDAP_(crlUrl);
        } else {

            LOG.warn("DSS framework only supports HTTP, HTTPS, FTP and LDAP CRL's url.");
        }
        if (x509CRL == null) {
            return null;
        }
        final CRLValidity crlValidity = isValidCRL(x509CRL, issuerToken);
        final CRLToken crlToken = new CRLToken(certificateToken, crlValidity);
        crlToken.setSourceURL(crlUrl);
        return crlToken;
    }

    private static X509CRL downloadCRLFromURL(final String crlURL) throws DSSException {

        InputStream crlStream = null;
        try {

            final URL url = new URL(crlURL);
            crlStream = url.openStream();
            return DSSUtils.loadCRL(crlStream);
        } catch (Exception e) {

            LOG.warn(e.getMessage());
        } finally {
            DSSUtils.closeQuietly(crlStream);
        }
        return null;
    }

    /**
     * Downloads a CRL from given LDAP url, e.g. ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
     *
     * @throws DSSException
     */

    private static X509CRL downloadCRLFromLDAP_(final String ldapURL) throws DSSException {

        final Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);
        try {

            final DirContext ctx = new InitialDirContext(env);
            final Attributes attributes = ctx.getAttributes("");
            final javax.naming.directory.Attribute attribute = attributes.get("certificateRevocationList;binary");
            final byte[] val = (byte[]) attribute.get();
            if (val == null || val.length == 0) {

                throw new DSSException("Can not download CRL from: " + ldapURL);
            }
            final InputStream inStream = new ByteArrayInputStream(val);
            return DSSUtils.loadCRL(inStream);
        } catch (Exception e) {

            LOG.warn(e.getMessage(), e);
        }
        return null;
    }

    /**
     * Obtains a CRL from a specified LDAP URL
     *
     * @param ldapURL The LDAP URL String
     * @return A CRL obtained from this LDAP URL if successful, otherwise NULL (if no CRL was resent) or an exception will be thrown.
     * @throws DSSException
     */
    public static X509CRL downloadCRLFromLDAP(final String ldapURL) throws DSSException {

        try {

            //final String ldapUrlStr = URLDecoder.decode(ldapURL, "UTF-8");
            final LdapUrl ldapUrl = new LdapUrl(ldapURL);
            final int port = ldapUrl.getPort() > 0 ? ldapUrl.getPort() : 389;
            final LdapConnection con = new LdapNetworkConnection(ldapUrl.getHost(), port);
            con.connect();
            final Entry entry = con.lookup(ldapUrl.getDn(), ldapUrl.getAttributes().toArray(new String[ldapUrl.getAttributes().size()]));
            final Collection<Attribute> attributes = entry.getAttributes();
            X509CRL crl = null;
            for (Attribute attr : attributes) {

                crl = DSSUtils.loadCRL(attr.getBytes());
                break;
            }
            con.close();
            return crl;
        } catch (Exception e) {

            LOG.warn(e.toString(), e);
        }
        return null;
    }

    /**
     * Download a CRL from HTTP or HTTPS location.
     *
     * @param downloadUrl
     * @return
     */
    private X509CRL downloadCrlFromHTTP(final String downloadUrl) {

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
