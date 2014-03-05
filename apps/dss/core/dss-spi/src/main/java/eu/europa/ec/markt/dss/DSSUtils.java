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
package eu.europa.ec.markt.dss;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.TimeZone;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.x509.XMLX509SKI;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

public final class DSSUtils {

    private static final Logger LOG = LoggerFactory.getLogger(DSSUtils.class);

    public static final String CERT_BEGIN = "-----BEGIN CERTIFICATE-----\n";
    public static final String CERT_END = "-----END CERTIFICATE-----";

    /**
     * FROM: Apache
     * The index value when an element is not found in a list or array: {@code -1}.
     * This value is returned by methods in this class and can also be used in comparisons with values returned by
     * various method from {@link java.util.List}.
     */
    public static final int INDEX_NOT_FOUND = -1;

    /**
     * The empty String {@code ""}.
     *
     * @since 2.0
     */
    public static final String EMPTY = "";

    /**
     * <p>The maximum size to which the padding constant(s) can expand.</p>
     */
    private static final int PAD_LIMIT = 8192;

    private static final CertificateFactory certificateFactory;

    private static MessageDigest sha1Digester;

    private static JcaDigestCalculatorProviderBuilder jcaDigestCalculatorProviderBuilder;

    static {

        try {

            Security.addProvider(new BouncyCastleProvider());

            certificateFactory = CertificateFactory.getInstance("X.509", "BC");

            sha1Digester = getMessageDigest(DigestAlgorithm.SHA1);

            jcaDigestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
            jcaDigestCalculatorProviderBuilder.setProvider("BC");

        } catch (CertificateException e) {

            LOG.error(e.toString());
            throw new DSSException("Platform does not support X509 certificate", e);
        } catch (NoSuchProviderException e) {

            LOG.error(e.toString());
            throw new DSSException("Platform does not support BouncyCastle", e);
        } catch (NoSuchAlgorithmException e) {

            LOG.error(e.toString());
            throw new DSSException("The digest algorithm is not supported", e);
        }
    }

    /**
     * The default buffer size to use.
     */
    private static final int DEFAULT_BUFFER_SIZE = 1024 * 4;

    /**
     * This class is an utility class and cannot be instantiated.
     */
    private DSSUtils() {
    }

    /**
     * Formats a date to use for internal purposes (logging, toString)
     *
     * @param date the date to be converted
     * @return the textual representation (a null date will result in "N/A")
     */
    public static String formatInternal(final Date date) {

        final String formatedDate = (date == null) ? "N/A" : new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").format(date);
        return formatedDate;
    }

    /**
     * Converts an array of bytes into a String representing the hexadecimal values of each byte in order. The returned
     * String will be double the length of the passed array, as it takes two characters to represent any given byte. If
     * the input array is null then null is returned. The obtained string is converted to uppercase.
     *
     * @param value
     * @return
     */
    public static String toHex(final byte[] value) {

        return (value != null) ? new String(Hex.encodeHex(value, false)) : null;
    }

    /**
     * Decodes a Base64 String into bytes.
     *
     * @param base64String
     * @return
     */
    public static byte[] base64Decode(final String base64String) throws DSSException {

        return Base64.decodeBase64(base64String);
    }

    /**
     * Decodes a Base64 String into bytes.
     *
     * @param binaryData
     * @return
     */
    public static byte[] base64Decode(final byte[] binaryData) {

        return Base64.decodeBase64(binaryData);
    }

    /**
     * Encodes binary data using the base64 algorithm but does not chunk the output. NOTE: We changed the behaviour of
     * this method from multi-line chunking (commons-codec-1.4) to single-line non-chunking (commons-codec-1.5).
     *
     * @param binaryData
     * @return
     */
    public static String base64Encode(final byte[] binaryData) {

        return Base64.encodeBase64String(binaryData);
    }

    /**
     * Encodes binary data using the base64 algorithm but does not chunk the output.
     *
     * @param binaryData
     * @return
     */
    public static byte[] base64BinaryEncode(final byte[] binaryData) {

        return Base64.encodeBase64(binaryData);
    }

    /**
     * This method re-encode base 64 encoded string to base 64 encoded byte array.
     *
     * @param base64String
     * @return
     */
    public static byte[] base64StringToBase64Binary(final String base64String) {

        final byte[] decodedBase64 = Base64.decodeBase64(base64String);
        final byte[] encodeBase64 = Base64.encodeBase64(decodedBase64);
        return encodeBase64;
    }

    /**
     * Encodes dss document using the base64 algorithm .
     *
     * @param dssDocument dss document to be encoded
     * @return encoded base64 string
     */
    public static String base64Encode(DSSDocument dssDocument) {

        final byte[] bytes = dssDocument.getBytes();
        final String base64EncodedBytes = base64Encode(bytes);
        return base64EncodedBytes;
    }

    /**
     * @param certificate
     * @return
     */
    public static String base64Encode(final X509Certificate certificate) throws DSSException {

        try {
            final byte[] bytes = certificate.getEncoded();
            final String base64EncodedBytes = base64Encode(bytes);
            return base64EncodedBytes;
        } catch (CertificateEncodingException e) {
            throw new DSSException(e);
        }
    }

    /**
     * FROM: Apache IOUtils
     * Get the contents of an {@code InputStream} as a String
     * using the default character encoding of the platform.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * {@code BufferedInputStream}.
     *
     * @param input the {@code InputStream} to read from
     * @return the requested String
     * @throws NullPointerException if the input is null
     * @throws DSSException         if an I/O error occurs
     */
    public static String toString(InputStream input) throws DSSException {

        StringWriter sw = new StringWriter();
        copy(input, sw);
        return sw.toString();
    }

    /**
     * FROM: Apache IOUtils
     * Get the contents of an {@code InputStream} as a String using the specified character encoding.
     * <p/>
     * Character encoding names can be found at <a href="http://www.iana.org/assignments/character-sets">IANA</a>.
     * <p/>
     * This method buffers the input internally, so there is no need to use a {@code BufferedInputStream}.
     *
     * @param input    the {@code InputStream} to read from
     * @param encoding the encoding to use, null means platform default
     * @return the requested String
     * @throws NullPointerException if the input is null
     * @throws java.io.IOException  if an I/O error occurs
     */
    public static String toString(InputStream input, String encoding) throws DSSException {

        StringWriter sw = new StringWriter();
        copy(input, sw, encoding);
        return sw.toString();
    }

    /**
     * FROM: Apache IOUtils
     * Copy bytes from an {@code InputStream} to chars on a {@code Writer} using the specified character
     * encoding.
     * <p/>
     * This method buffers the input internally, so there is no need to use a {@code BufferedInputStream}.
     * <p/>
     * Character encoding names can be found at <a href="http://www.iana.org/assignments/character-sets">IANA</a>.
     * <p/>
     * This method uses {@link java.io.InputStreamReader}.
     *
     * @param input    the {@code InputStream} to read from
     * @param output   the {@code Writer} to write to
     * @param encoding the encoding to use, null means platform default
     * @throws NullPointerException if the input or output is null
     * @throws java.io.IOException  if an I/O error occurs
     * @since Commons IO 1.1
     */
    public static void copy(InputStream input, Writer output, String encoding) throws DSSException {
        try {
            if (encoding == null) {
                copy(input, output);
            } else {
                InputStreamReader in = new InputStreamReader(input, encoding);
                copy(in, output);
            }
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    public static void copy(InputStream input, Writer output) throws DSSException {

        InputStreamReader in = new InputStreamReader(input);
        copy(in, output);
    }

    /**
     * FROM: Apache IOUtils
     * Copy chars from a {@code Reader} to a {@code Writer}.
     * <p/>
     * This method buffers the input internally, so there is no need to use a {@code BufferedReader}.
     * <p/>
     * Large streams (over 2GB) will return a chars copied value of {@code -1} after the copy has completed since
     * the correct number of chars cannot be returned as an int. For large streams use the
     * {@code copyLarge(Reader, Writer)} method.
     *
     * @param input  the {@code Reader} to read from
     * @param output the {@code Writer} to write to
     * @return the number of characters copied
     * @throws NullPointerException if the input or output is null
     * @throws java.io.IOException  if an I/O error occurs
     * @throws ArithmeticException  if the character count is too large
     * @since Commons IO 1.1
     */
    public static int copy(Reader input, Writer output) throws DSSException {

        long count = copyLarge(input, output);
        if (count > Integer.MAX_VALUE) {
            return -1;
        }
        return (int) count;
    }

    /**
     * FROM: Apache IOUtils
     * Copy chars from a large (over 2GB) {@code Reader} to a {@code Writer}.
     * <p/>
     * This method buffers the input internally, so there is no need to use a {@code BufferedReader}.
     *
     * @param input  the {@code Reader} to read from
     * @param output the {@code Writer} to write to
     * @return the number of characters copied
     * @throws NullPointerException if the input or output is null
     * @throws java.io.IOException  if an I/O error occurs
     * @since Commons IO 1.3
     */
    private
    static long copyLarge(Reader input, Writer output) throws DSSException {
        try {
            char[] buffer = new char[DEFAULT_BUFFER_SIZE];
            long count = 0;
            int n = 0;
            while (-1 != (n = input.read(buffer))) {
                output.write(buffer, 0, n);
                count += n;
            }
            return count;
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    /**
     * FROM: Apache IOUtils
     * Copy bytes from an {@code InputStream} to an
     * {@code OutputStream}.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * {@code BufferedInputStream}.
     * <p>
     * Large streams (over 2GB) will return a bytes copied value of
     * {@code -1} after the copy has completed since the correct
     * number of bytes cannot be returned as an int. For large streams
     * use the {@code copyLarge(InputStream, OutputStream)} method.
     *
     * @param input  the {@code InputStream} to read from
     * @param output the {@code OutputStream} to write to
     * @return the number of bytes copied
     * @throws NullPointerException if the input or output is null
     * @throws DSSException         if an I/O error occurs
     * @throws ArithmeticException  if the byte count is too large
     * @since Commons IO 1.1
     */
    public static int copy(final InputStream input, final OutputStream output) throws DSSException {
        long count = copyLarge(input, output);
        if (count > Integer.MAX_VALUE) {
            return -1;
        }
        return (int) count;
    }

    /**
     * FROM: Apache IOUtils
     * Copy bytes from a large (over 2GB) {@code InputStream} to an
     * {@code OutputStream}.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * {@code BufferedInputStream}.
     *
     * @param input  the {@code InputStream} to read from
     * @param output the {@code OutputStream} to write to
     * @return the number of bytes copied
     * @throws NullPointerException if the input or output is null
     * @throws DSSException         if an I/O error occurs
     * @since Commons IO 1.3
     */
    private static long copyLarge(InputStream input, OutputStream output) throws DSSException {

        try {
            byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
            long count = 0;
            int n = 0;
            while (-1 != (n = input.read(buffer))) {
                output.write(buffer, 0, n);
                count += n;
            }
            return count;
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    /**
     * Writes bytes from a {@code byte[]} to an {@code OutputStream}.
     *
     * @param data   the byte array to write, do not modify during output,
     *               null ignored
     * @param output the {@code OutputStream} to write to
     * @throws DSSException if output is null or an I/O error occurs
     * @since Commons IO 1.1
     */
    public static void write(byte[] data, OutputStream output) throws DSSException {

        try {
            if (data != null) {
                output.write(data);
            }
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    /**
     * This method replaces all \ to /.
     *
     * @param path
     * @return
     */
    private static String normalisePath(String path) {

        return path.replace('\\', '/');
    }

    /**
     * This method checks if the resource with the given path exists.
     *
     * @param path
     * @return
     */
    public static boolean resourceExists(final String path) {

        final String path_ = normalisePath(path);
        final URL url = DSSUtils.class.getResource(path_);
        return url != null;
    }

    /**
     * This method checks if the file with the given path exists.
     *
     * @param path
     * @return
     */
    public static boolean fileExists(final String path) {

        final String path_ = normalisePath(path);
        final boolean exists = new File(path).exists();
        return exists;
    }

    /**
     * This method returns a file reference. The file path is normalised (OS independent)
     *
     * @param filePath The path to the file.
     * @return
     */
    public static File getFile(final String filePath) {

        final String normalisedFolderFileName = normalisePath(filePath);
        final File file = new File(normalisedFolderFileName);
        return file;
    }

    /**
     * This method converts the given certificate into its PEM string.
     *
     * @param cert
     * @return
     * @throws java.security.cert.CertificateEncodingException
     */
    public static String convertToPEM(final X509Certificate cert) throws DSSException {

        try {

            final Base64 encoder = new Base64(64);
            final byte[] derCert = cert.getEncoded();
            final String pemCertPre = new String(encoder.encode(derCert));
            final String pemCert = CERT_BEGIN + pemCertPre + CERT_END;
            return pemCert;
        } catch (CertificateEncodingException e) {
            throw new DSSException(e);
        }
    }

    /**
     * This method loads a certificate from the given resource.  The certificate must be DER-encoded and may be supplied in binary or printable
     * (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN CERTIFICATE-----, and
     * must be bounded at the end by -----END CERTIFICATE-----. It throws an {@code DSSException} or return {@code null} when the
     * certificate cannot be loaded.
     *
     * @param path resource location.
     * @return
     */
    public static X509Certificate loadCertificate(final String path) throws DSSException {

        final InputStream inputStream = DSSUtils.class.getResourceAsStream(path);
        return loadCertificate(inputStream);
    }

    /**
     * This method loads a certificate from the given location. The certificate must be DER-encoded and may be supplied in binary or printable
     * (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN CERTIFICATE-----, and
     * must be bounded at the end by -----END CERTIFICATE-----. It throws an {@code DSSException} or return {@code null} when the
     * certificate cannot be loaded.
     *
     * @param file
     * @return
     */
    public static X509Certificate loadCertificate(final File file) throws DSSException {

        final InputStream inputStream = DSSUtils.toInputStream(file);
        final X509Certificate x509Certificate = loadCertificate(inputStream);
        return x509Certificate;
    }

    /**
     * This method loads a certificate from the given location. The certificate must be DER-encoded and may be supplied in binary or printable (Base64) encoding. If the
     * certificate
     * is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN CERTIFICATE-----, and must be bounded at the end by -----END CERTIFICATE-----. It throws
     * an
     * {@code DSSException} or return {@code null} when the certificate cannot be loaded.
     *
     * @param inputStream input stream containing the certificate
     * @return
     */
    public static X509Certificate loadCertificate(final InputStream inputStream) throws DSSException {

        try {

            final X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inputStream);
            return cert;
        } catch (CertificateException e) {
            throw new DSSException(e);
        }
    }

    /**
     * This method loads a certificate from the byte array. The certificate must be DER-encoded and may be supplied in binary or printable
     * (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN CERTIFICATE-----, and
     * must be bounded at the end by -----END CERTIFICATE-----. It throws an {@code DSSException} or return {@code null} when the
     * certificate cannot be loaded.
     *
     * @param input array of bytes containing the certificate
     * @return
     */
    public static X509Certificate loadCertificate(final byte[] input) throws DSSException {

        final ByteArrayInputStream inputStream = new ByteArrayInputStream(input);
        return loadCertificate(inputStream);
    }

    /**
     * This method loads a certificate from a base 64 encoded String
     *
     * @param base64Encoded
     * @return
     */
    public static X509Certificate loadCertificateFromBase64EncodedString(final String base64Encoded) {

        final byte[] bytes = DSSUtils.base64Decode(base64Encoded);
        return loadCertificate(bytes);
    }

    /**
     * This method loads the issuer certificate from the given location (AIA).  The certificate must be DER-encoded and may be supplied in binary or
     * printable (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN
     * CERTIFICATE-----, and must be bounded at the end by -----END CERTIFICATE-----.  It throws an
     * {@code DSSException} or return {@code null} when the certificate cannot be loaded.
     *
     * @param cert   certificate for which the issuer should be loaded
     * @param loader the loader to use
     * @return
     */
    public static X509Certificate loadIssuerCertificate(final X509Certificate cert, final HTTPDataLoader loader) {

        final String url = getAccessLocation(cert, X509ObjectIdentifiers.id_ad_caIssuers);
        if (url == null) {
            LOG.info("There is no AIA extension for certificate download.");
            return null;
        }
        LOG.debug("Loading certificate from {}", url);
        if (loader == null) {
            throw new DSSNullException(HTTPDataLoader.class);
        }
        byte[] bytes = loader.get(url);
        if (bytes == null || bytes.length <= 0) {
            LOG.error("Unable to read data from {}.", url);
            return null;
        }
        final X509Certificate issuerCert = loadCertificate(bytes);
        if (issuerCert == null) {
            LOG.error("Unable to read data from {}.", url);
            return null;
        }
        if (!cert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
            LOG.info("There is AIA extension, but the issuer subject name and subject name does not match.");
            return null;
        }
        return issuerCert;
    }

    /**
     * This method return SKI bytes from certificate or null.
     *
     * @param x509Certificate {@code X509Certificate}
     * @return ski bytes from the given certificate
     * @throws Exception
     */
    public static byte[] getSki(final X509Certificate x509Certificate) throws DSSException {

        try {

            final byte[] skiBytesFromCert = XMLX509SKI.getSKIBytesFromCert(x509Certificate);
            return skiBytesFromCert;
        } catch (XMLSecurityException e) {
            return null;
        } catch (Exception e) {
            throw new DSSException(e);
        }
        //        try {
        //            final byte[] extensionValue = x509Certificate.getExtensionValue("2.5.29.14");
        //            if (extensionValue == null) {
        //                return null;
        //            }
        //            ASN1OctetString str = ASN1OctetString.getInstance(new ASN1InputStream(new ByteArrayInputStream(extensionValue)).readObject());
        //            SubjectKeyIdentifier keyId = SubjectKeyIdentifier.getInstance(new ASN1InputStream(new ByteArrayInputStream(str.getOctets())).readObject());
        //            return keyId.getKeyIdentifier();
        //        } catch (IOException e) {
        //            throw new DSSException(e);
        //        }
    }

    private static String getAccessLocation(final X509Certificate certificate, final DERObjectIdentifier accessMethod) {

        try {

            final byte[] authInfoAccessExtensionValue = certificate.getExtensionValue(X509Extension.authorityInfoAccess.getId());
            if (null == authInfoAccessExtensionValue) {
                return null;
            }
         /* Parse the extension */
            final ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(authInfoAccessExtensionValue));
            final DEROctetString oct = (DEROctetString) (asn1InputStream.readObject());
            asn1InputStream.close();
            final ASN1InputStream asn1InputStream2 = new ASN1InputStream(oct.getOctets());
            final AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance((ASN1Sequence) asn1InputStream2.readObject());
            asn1InputStream2.close();

            final AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
            for (final AccessDescription accessDescription : accessDescriptions) {

                // LOG.debug("access method: " + accessDescription.getAccessMethod());
                final boolean correctAccessMethod = accessDescription.getAccessMethod().equals(accessMethod);
                if (!correctAccessMethod) {
                    continue;
                }
                GeneralName gn = accessDescription.getAccessLocation();
                if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {

                    // LOG.debug("not a uniform resource identifier");
                    continue;
                }
                final DERIA5String str = (DERIA5String) ((DERTaggedObject) gn.toASN1Primitive()).getObject();
                final String accessLocation = str.getString();
                // LOG.debug("access location: " + accessLocation);
                return accessLocation;
            }
        } catch (final IOException e) {

            // we do nothing
            // LOG.("IO error: " + e.getMessage(), e);
        }
        return null;
    }

    /**
     * This method loads a CRL from the given base 64 encoded string.
     *
     * @param base64Encoded
     * @return
     */
    public static X509CRL loadCRLBase64Encoded(final String base64Encoded) {

        final byte[] derEncoded = DSSUtils.base64Decode(base64Encoded);
        final X509CRL crl = loadCRL(new ByteArrayInputStream(derEncoded));
        return crl;
    }

    /**
     * This method loads a CRL from the given location.
     *
     * @param byteArray
     * @return
     */
    public static X509CRL loadCRL(final byte[] byteArray) {

        final ByteArrayInputStream inputStream = new ByteArrayInputStream(byteArray);
        final X509CRL crl = loadCRL(inputStream);
        return crl;
    }

    /**
     * This method loads a CRL from the given location.
     *
     * @param inputStream
     * @return
     */
    public static X509CRL loadCRL(final InputStream inputStream) {

        try {

            final X509CRL crl = (X509CRL) certificateFactory.generateCRL(inputStream);
            return crl;
        } catch (CRLException e) {

            throw new DSSException(e);
        }
    }

    /**
     * This method loads an OCSP response from the given base 64 encoded string.
     *
     * @param base64Encoded base 64 encoded OCSP response
     * @return {@code BasicOCSPResp}
     */
    public static BasicOCSPResp loadOCSPBase64Encoded(final String base64Encoded) {

        final byte[] derEncoded = DSSUtils.base64Decode(base64Encoded);
        try {

            final OCSPResp ocspResp = new OCSPResp(derEncoded);
            final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
            return basicOCSPResp;
        } catch (OCSPException e) {

            throw new DSSException(e);
        } catch (IOException e) {

            throw new DSSException(e);
        }
    }

    public static List<String> getPolicyIdentifiers(X509Certificate cert) {

        final byte[] certificatePolicies = cert.getExtensionValue(X509Extension.certificatePolicies.getId());
        if (certificatePolicies == null) {

            return Collections.emptyList();
        }
        ASN1InputStream input = null;
        ASN1Sequence seq = null;
        try {

            input = new ASN1InputStream(certificatePolicies);
            final DEROctetString s = (DEROctetString) input.readObject();
            final byte[] content = s.getOctets();
            input.close();
            input = new ASN1InputStream(content);
            seq = (ASN1Sequence) input.readObject();
        } catch (IOException e) {

            throw new DSSException("Error when computing certificate's extensions.", e);
        } finally {

            closeQuietly(input);
        }
        final List<String> policyIdentifiers = new ArrayList<String>();
        for (int ii = 0; ii < seq.size(); ii++) {

            final PolicyInformation policyInfo = PolicyInformation.getInstance(seq.getObjectAt(ii));
            // System.out.println("\t----> PolicyIdentifier: " + policyInfo.getPolicyIdentifier().getId());
            policyIdentifiers.add(policyInfo.getPolicyIdentifier().getId());

        }
        return policyIdentifiers;
    }

    /**
     * This method converts the {@code List} of {@code CertificateToken} to the {@code List} of {@code X509Certificate}.
     *
     * @param certTokens the list of {@code CertificateToken} to be converted
     * @return a list for {@code X509Certificate} based on the input list
     */
    public static List<X509Certificate> getX509Certificates(final List<CertificateToken> certTokens) {

        final List<X509Certificate> certificateChain = new ArrayList<X509Certificate>();
        for (final CertificateToken token : certTokens) {

            certificateChain.add(token.getCertificate());
        }
        return certificateChain;

    }

    /**
     * This method digests the given string with SHA1 algorithm and encode returned array of bytes as hex string.
     *
     * @param stringToDigest Everything in the name
     * @return hex encoded digest value
     */
    public static String getSHA1Digest(final String stringToDigest) {

        final byte[] digest = sha1Digester.digest(stringToDigest.getBytes());
        return Hex.encodeHexString(digest);
    }

    /**
     * This method digests the given {@code InputStream} with SHA1 algorithm and encode returned array of bytes as hex string.
     *
     * @param inputStream
     * @return
     */
    public static String getSHA1Digest(final InputStream inputStream) {

        final byte[] bytes = DSSUtils.toByteArray(inputStream);
        final byte[] digest = sha1Digester.digest(bytes);
        return Hex.encodeHexString(digest);
    }

    /**
     * This method replaces in a string one pattern by another one without using regexp.
     *
     * @param string
     * @param oldPattern
     * @param newPattern
     * @return
     */
    public static StringBuffer replaceStrStr(final StringBuffer string, final String oldPattern, final String newPattern) {

        if (string == null || oldPattern == null || oldPattern.equals("") || newPattern == null) {

            return string;
        }

        final StringBuffer replaced = new StringBuffer();
        int startIdx = 0;
        int idxOld;
        while ((idxOld = string.indexOf(oldPattern, startIdx)) >= 0) {

            replaced.append(string.substring(startIdx, idxOld));
            replaced.append(newPattern);
            startIdx = idxOld + oldPattern.length();
        }
        replaced.append(string.substring(startIdx));
        return replaced;
    }

    public static String replaceStrStr(final String absolutePath, final String oldPattern, final String newPattern) {

        final StringBuffer stringBuffer = replaceStrStr(new StringBuffer(absolutePath), oldPattern, newPattern);
        return stringBuffer.toString();
    }

    /**
     * This method allows to digest the data with the given algorithm.
     *
     * @param digestAlgorithm the algorithm to use
     * @param data            the data to digest
     * @return digested array of bytes
     */
    public static byte[] digest(final DigestAlgorithm digestAlgorithm, final byte[] data) throws DSSException {

        try {

            final MessageDigest messageDigest = getMessageDigest(digestAlgorithm);
            final byte[] digestValue = messageDigest.digest(data);
            return digestValue;
        } catch (NoSuchAlgorithmException e) {

            throw new DSSException("Digest algorithm error: " + e.getMessage(), e);
        }
    }

    public static MessageDigest getMessageDigest(final DigestAlgorithm digestAlgorithm) throws NoSuchAlgorithmException {
        final String digestAlgorithmOid = digestAlgorithm.getOid().getId();
        // System.out.println(">>> " + digestAlgorithmOid);
        final MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithmOid);
        // System.out.println(">>> " + messageDigest.getProvider() + "/" + messageDigest.getClass().getName());
        return messageDigest;
    }

    /**
     * This method allows to digest the data in the {@code InputStream} with the given algorithm.
     *
     * @param digestAlgo  the algorithm to use
     * @param inputStream the data to digest
     * @return digested array of bytes
     */
    public static byte[] digest(final DigestAlgorithm digestAlgo, final InputStream inputStream) throws DSSException {

        try {

            final MessageDigest messageDigest = getMessageDigest(digestAlgo);
            final byte[] buffer = new byte[4096];
            int count = 0;
            while ((count = inputStream.read(buffer)) > 0) {

                messageDigest.update(buffer, 0, count);
            }
            final byte[] digestValue = messageDigest.digest();
            return digestValue;
        } catch (NoSuchAlgorithmException e) {
            throw new DSSException("Digest algorithm error: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    public static byte[] digest(DigestAlgorithm digestAlgorithm, byte[]... data) {

        try {

            final MessageDigest messageDigest = getMessageDigest(digestAlgorithm);
            for (final byte[] bytes : data) {

                messageDigest.update(bytes);
            }
            final byte[] digestValue = messageDigest.digest();
            return digestValue;
        } catch (NoSuchAlgorithmException e) {

            throw new DSSException("Digest algorithm error: " + e.getMessage(), e);
        }
    }

    /**
     * This method digest and encrypt the given {@code InputStream} with indicated private key and signature algorithm. To find the signature object
     * the list of registered security Providers, starting with the most preferred Provider is traversed.
     * <p/>
     * This method returns an array of bytes representing the signature value. Signature object that implements the specified signature algorithm. It traverses the list of
     * registered security Providers, starting with the most preferred Provider. A new Signature object encapsulating the SignatureSpi implementation from the first Provider
     * that supports the specified algorithm is returned. The {@code NoSuchAlgorithmException} exception is wrapped in a DSSException.
     *
     * @param javaSignatureAlgorithm signature algorithm under JAVA form.
     * @param privateKey             private key to use
     * @param stream                 the data to digest
     * @return digested and encrypted array of bytes
     */
    public static byte[] encrypt(final String javaSignatureAlgorithm, final PrivateKey privateKey, final InputStream stream) {

        try {

            final Signature signature = Signature.getInstance(javaSignatureAlgorithm);

            signature.initSign(privateKey);
            final byte[] buffer = new byte[4096];
            int count = 0;
            while ((count = stream.read(buffer)) > 0) {

                signature.update(buffer, 0, count);
            }
            final byte[] signatureValue = signature.sign();
            return signatureValue;
        } catch (SignatureException e) {
            throw new DSSException(e);
        } catch (InvalidKeyException e) {
            throw new DSSException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new DSSException(e);
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    /**
     * This method digest and encrypt the given {@code InputStream} with indicated private key and signature algorithm. To find the signature object
     * the list of registered security Providers, starting with the most preferred Provider is traversed.
     * <p/>
     * This method returns an array of bytes representing the signature value. Signature object that implements the specified signature algorithm. It traverses the list of
     * registered security Providers, starting with the most preferred Provider. A new Signature object encapsulating the SignatureSpi implementation from the first Provider
     * that supports the specified algorithm is returned. The {@code NoSuchAlgorithmException} exception is wrapped in a DSSException.
     *
     * @param javaSignatureAlgorithm signature algorithm under JAVA form.
     * @param privateKey             private key to use
     * @param bytes                  the data to digest
     * @return digested and encrypted array of bytes
     */
    public static byte[] encrypt(final String javaSignatureAlgorithm, final PrivateKey privateKey, final byte[] bytes) {

        try {

            final Signature signature = Signature.getInstance(javaSignatureAlgorithm);

            signature.initSign(privateKey);
            signature.update(bytes);
            final byte[] signatureValue = signature.sign();
            return signatureValue;
        } catch (SignatureException e) {
            throw new DSSException(e);
        } catch (InvalidKeyException e) {
            throw new DSSException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new DSSException(e);
        }
    }

    /**
     * Returns the {@code CertificateID} for the given certificate and its issuer's certificate.
     *
     * @param cert       {@code X509Certificate} for which the id is created
     * @param issuerCert {@code X509Certificate} issuer certificate of the {@code cert}
     * @return {@code CertificateID}
     * @throws org.bouncycastle.cert.ocsp.OCSPException
     */
    public static CertificateID getOCSPCertificateID(final X509Certificate cert, final X509Certificate issuerCert) throws DSSException {

        try {

            final BigInteger serialNumber = cert.getSerialNumber();
            final DigestCalculator digestCalculator = getSHA1DigestCalculator();
            final X509CertificateHolder x509CertificateHolder = getX509CertificateHolder(issuerCert);
            final CertificateID certificateID = new CertificateID(digestCalculator, x509CertificateHolder, serialNumber);
            return certificateID;
        } catch (OCSPException e) {
            throw new DSSException(e);
        }
    }

    /**
     * Returns a {@code X509CertificateHolder} encapsulating the given {@code X509Certificate}.
     *
     * @param x509Certificate
     * @return a X509CertificateHolder holding this certificate
     */
    public static X509CertificateHolder getX509CertificateHolder(final X509Certificate x509Certificate) {

        try {
            return new X509CertificateHolder(x509Certificate.getEncoded());
        } catch (IOException e) {
            throw new DSSException(e);
        } catch (CertificateEncodingException e) {
            throw new DSSException(e);
        }
    }

    /**
     * Returns a {@code X509CertificateHolder} encapsulating the given {@code CertificateToken}.
     *
     * @param certificateToken
     * @return a X509CertificateHolder holding this certificate
     */
    public static X509CertificateHolder getX509CertificateHolder(final CertificateToken certificateToken) {

        final X509CertificateHolder x509CertificateHolder = getX509CertificateHolder(certificateToken.getCertificate());
        return x509CertificateHolder;
    }

    public static DigestCalculator getSHA1DigestCalculator() throws DSSException {

        try {
            // final ASN1ObjectIdentifier oid = DigestAlgorithm.SHA1.getOid();
            // final DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(oid));

            final DigestCalculatorProvider digestCalculatorProvider = jcaDigestCalculatorProviderBuilder.build();
            final DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);
            return digestCalculator;
        } catch (OperatorCreationException e) {
            throw new DSSException(e);
        }
    }

    /**
     * Returns the encoded (as ASN.1 DER) form of this X.509 certificate.
     *
     * @param cert certificate
     * @return encoded array of bytes
     */
    public static byte[] getEncoded(final X509Certificate cert) {

        try {
            byte[] encoded = cert.getEncoded();
            return encoded;
        } catch (CertificateEncodingException e) {
            throw new DSSException(e);
        }
    }

    /**
     * This method opens the {@code URLConnection} using the given URL.
     *
     * @param url URL to be accessed
     * @return {@code URLConnection}
     */
    public static URLConnection openURLConnection(final String url) {

        try {

            final URL tspUrl = new URL(url);
            return tspUrl.openConnection();
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    public static void writeToURLConnection(final URLConnection urlConnection, final byte[] bytes) throws DSSException {

        try {

            final OutputStream out = urlConnection.getOutputStream();
            out.write(bytes);
            out.close();
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    /**
     * This method returns an {@code InputStream} which does not need to be closed (based on {@code ByteArrayInputStream}.
     *
     * @param filePath The path to the file
     * @return
     * @throws DSSException
     */
    public static InputStream toInputStream(final String filePath) throws DSSException {

        final File file = getFile(filePath);
        final InputStream inputStream = toInputStream(file);
        return inputStream;
    }

    /**
     * This method returns an {@code InputStream} which does not need to be closed (based on {@code ByteArrayInputStream}.
     *
     * @param file {@code File} to read.
     * @return {@code ByteArrayInputStream} representing the contents of the file.
     * @throws DSSException
     */
    public static InputStream toInputStream(final File file) throws DSSException {

        if (file == null) {

            throw new DSSNullException(File.class);
        }
        try {
            final byte[] bytes = readFileToByteArray(file);
            final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
            return byteArrayInputStream;
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    /**
     * @param bytes
     * @return
     */
    public static InputStream toInputStream(byte[] bytes) {

        final InputStream inputStream = new ByteArrayInputStream(bytes);
        return inputStream;
    }

    /**
     * This method returns the byte array representing the contents of the file.
     *
     * @param file {@code File} to read.
     * @return
     * @throws DSSException
     */
    public static byte[] toByteArray(final File file) throws DSSException {

        if (file == null) {

            throw new DSSNullException(File.class);
        }
        try {
            final byte[] bytes = readFileToByteArray(file);
            return bytes;
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    /**
     * FROM: Apache
     *
     * Reads the contents of a file into a byte array.
     * The file is always closed.
     *
     * @param file the file to read, must not be {@code null}
     * @return the file contents, never {@code null}
     * @throws IOException in case of an I/O error
     * @since Commons IO 1.1
     */
    private static byte[] readFileToByteArray(File file) throws IOException {
        InputStream in = null;
        try {
            in = openInputStream(file);
            return toByteArray_(in);
        } finally {
            closeQuietly(in);
        }
    }

    /**
     * FROM: Apache
     *
     * Opens a {@link java.io.FileInputStream} for the specified file, providing better
     * error messages than simply calling {@code new FileInputStream(file)}.
     * <p>
     * At the end of the method either the stream will be successfully opened,
     * or an exception will have been thrown.
     * <p>
     * An exception is thrown if the file does not exist.
     * An exception is thrown if the file object exists but is a directory.
     * An exception is thrown if the file exists but cannot be read.
     *
     * @param file the file to open for input, must not be {@code null}
     * @return a new {@link java.io.FileInputStream} for the specified file
     * @throws java.io.FileNotFoundException if the file does not exist
     * @throws IOException                   if the file object is a directory
     * @throws IOException                   if the file cannot be read
     * @since Commons IO 1.3
     */
    private static FileInputStream openInputStream(File file) throws IOException {
        if (file.exists()) {
            if (file.isDirectory()) {
                throw new IOException("File '" + file + "' exists but is a directory");
            }
            if (file.canRead() == false) {
                throw new IOException("File '" + file + "' cannot be read");
            }
        } else {
            throw new FileNotFoundException("File '" + file + "' does not exist");
        }
        return new FileInputStream(file);
    }

    /**
     * Get the contents of an {@code InputStream} as a {@code byte[]}.
     *
     * @param inputStream
     * @return
     */
    public static byte[] toByteArray(final InputStream inputStream) {

        if (inputStream == null) {

            throw new DSSNullException(InputStream.class);
        }
        try {
            final byte[] bytes = toByteArray_(inputStream);
            return bytes;
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    /**
     * FROM: Apache
     * Get the contents of an {@code InputStream} as a {@code byte[]}.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * {@code BufferedInputStream}.
     *
     * @param input the {@code InputStream} to read from
     * @return the requested byte array
     * @throws NullPointerException if the input is null
     * @throws IOException          if an I/O error occurs
     */
    private static byte[] toByteArray_(InputStream input) throws IOException {

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        copy(input, output);
        return output.toByteArray();
    }

    public static byte[] toByteArray(final String string) {

        return string.getBytes();
    }

    public static String toString(final byte[] bytes) {

        if (bytes == null) {

            throw new DSSNullException(byte[].class);
        }
        final String string = new String(bytes);
        return string;
    }

    public static void saveToFile(final byte[] bytes, final File file) throws DSSException {

        try {

            final FileOutputStream fos = new FileOutputStream(file);
            final ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
            copy(inputStream, fos);
            closeQuietly(inputStream);
            closeQuietly(fos);
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    /**
     * @param certificate
     * @return
     */
    public static IssuerSerial getIssuerSerial(final X509Certificate certificate) {

        final X500Name issuerX500Name = DSSUtils.getX509CertificateHolder(certificate).getIssuer();
        final GeneralName generalName = new GeneralName(issuerX500Name);
        final GeneralNames generalNames = new GeneralNames(generalName);
        final BigInteger serialNumber = certificate.getSerialNumber();
        final IssuerSerial issuerSerial = new IssuerSerial(generalNames, serialNumber);
        return issuerSerial;
    }

    /**
     * @param certificateToken
     * @return
     */
    public static IssuerSerial getIssuerSerial(final CertificateToken certificateToken) {

        final IssuerSerial issuerSerial = getIssuerSerial(certificateToken.getCertificate());
        return issuerSerial;
    }

    public static X509Certificate getCertificate(final X509CertificateHolder x509CertificateHolder) {

        try {

            final Certificate certificate = x509CertificateHolder.toASN1Structure();
            final X509CertificateObject x509CertificateObject = new X509CertificateObject(certificate);
            return x509CertificateObject;
        } catch (CertificateParsingException e) {
            throw new DSSException(e);
        }
    }

    public static X509CRL toX509CRL(final X509CRLHolder x509CRLHolder) {

        try {

            final JcaX509CRLConverter jcaX509CRLConverter = new JcaX509CRLConverter();
            final X509CRL x509CRL = jcaX509CRLConverter.getCRL(x509CRLHolder);
            return x509CRL;
        } catch (CRLException e) {
            throw new DSSException(e);
        }
    }

    public static byte[] getEncoded(X509CRL x509CRL) {

        try {

            final byte[] encoded = x509CRL.getEncoded();
            return encoded;
        } catch (CRLException e) {
            throw new DSSException(e);
        }
    }

    public static byte[] getEncoded(BasicOCSPResp basicOCSPResp) {

        try {
            final byte[] encoded = BasicOCSPResponse.getInstance(basicOCSPResp.getEncoded()).getEncoded(ASN1Encoding.DER);
            return encoded;
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    /**
     * return a unique id for a date and the certificateToken id.
     *
     * @param signingTime
     * @param id
     * @return
     */
    public static String getDeterministicId(final Date signingTime, final int id) {

        final Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("Z"));
        Date signingTime_ = signingTime;
        if (signingTime_ == null) {

            signingTime_ = new Date();
        }
        calendar.setTime(signingTime_);

        final Date time = calendar.getTime();
        final long milliseconds = time.getTime();
        final long droppedMillis = 1000 * (milliseconds / 1000);

        final byte[] timeBytes = Long.toString(droppedMillis).getBytes();

        final ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.putInt(id);
        final byte[] certificateBytes = byteBuffer.array();

        final byte[] digestValue = DSSUtils.digest(DigestAlgorithm.MD5, timeBytes, certificateBytes);
        final String deterministicId = "id-" + DSSUtils.toHex(digestValue);
        return deterministicId;
    }

    public static Date getLocalDate(final Date gtmDate, final Date localDate) {

        final Date newLocalDate = new Date(gtmDate.getTime() + TimeZone.getDefault().getOffset(localDate.getTime()));
        return newLocalDate;
    }

    public static long toLong(final byte[] bytes) {

        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.put(bytes, 0, Long.SIZE / 8);
        // TODO: (Bob: 2014 Jan 22) To be checked if it is nit platform dependent?
        buffer.flip();//need flip
        return buffer.getLong();
    }

    public static void delete(final File file) {
        if (file != null) {
            file.delete();
        }
    }
    // Apache String Utils

    /**
     * <p>Checks if a String is empty ("") or null.</p>
     *
     * <pre>
     * DSSUtils.isEmpty(null)      = true
     * DSSUtils.isEmpty("")        = true
     * DSSUtils.isEmpty(" ")       = false
     * DSSUtils.isEmpty("bob")     = false
     * DSSUtils.isEmpty("  bob  ") = false
     * </pre>
     *
     * <p>NOTE: This method changed in Lang version 2.0.
     * It no longer trims the String.
     * That functionality is available in isBlank().</p>
     *
     * @param str the String to check, may be null
     * @return {@code true} if the String is empty or null
     */
    public static boolean isEmpty(String str) {
        return str == null || str.length() == 0;
    }

    /**
     * <p>Checks if a String is not empty ("") and not null.</p>
     *
     * <pre>
     * DSSUtils.isNotEmpty(null)      = false
     * DSSUtils.isNotEmpty("")        = false
     * DSSUtils.isNotEmpty(" ")       = true
     * DSSUtils.isNotEmpty("bob")     = true
     * DSSUtils.isNotEmpty("  bob  ") = true
     * </pre>
     *
     * @param str the String to check, may be null
     * @return {@code true} if the String is not empty and not null
     */
    public static boolean isNotEmpty(String str) {
        return !isEmpty(str);
    }

    /**
     * <p>Compares two Strings, returning {@code true} if they are equal.</p>
     *
     * <p>{@code null}s are handled without exceptions. Two {@code null}
     * references are considered to be equal. The comparison is case sensitive.</p>
     *
     * <pre>
     * DSSUtils.equals(null, null)   = true
     * DSSUtils.equals(null, "abc")  = false
     * DSSUtils.equals("abc", null)  = false
     * DSSUtils.equals("abc", "abc") = true
     * DSSUtils.equals("abc", "ABC") = false
     * </pre>
     *
     * @param str1 the first String, may be null
     * @param str2 the second String, may be null
     * @return {@code true} if the Strings are equal, case sensitive, or
     * both {@code null}
     * @see java.lang.String#equals(Object)
     */
    public static boolean equals(String str1, String str2) {
        return str1 == null ? str2 == null : str1.equals(str2);
    }

    /**
     * <p>Checks if a String is whitespace, empty ("") or null.</p>
     *
     * <pre>
     * DSSUtils.isBlank(null)      = true
     * DSSUtils.isBlank("")        = true
     * DSSUtils.isBlank(" ")       = true
     * DSSUtils.isBlank("bob")     = false
     * DSSUtils.isBlank("  bob  ") = false
     * </pre>
     *
     * @param str the String to check, may be null
     * @return {@code true} if the String is null, empty or whitespace
     * @since 2.0
     */
    public static boolean isBlank(String str) {
        int strLen;
        if (str == null || (strLen = str.length()) == 0) {
            return true;
        }
        for (int i = 0; i < strLen; i++) {
            if ((Character.isWhitespace(str.charAt(i)) == false)) {
                return false;
            }
        }
        return true;
    }

    /**
     * <p>Checks if a String is not empty (""), not null and not whitespace only.</p>
     *
     * <pre>
     * DSSUtils.isNotBlank(null)      = false
     * DSSUtils.isNotBlank("")        = false
     * DSSUtils.isNotBlank(" ")       = false
     * DSSUtils.isNotBlank("bob")     = true
     * DSSUtils.isNotBlank("  bob  ") = true
     * </pre>
     *
     * @param str the String to check, may be null
     * @return {@code true} if the String is
     * not empty and not null and not whitespace
     * @since 2.0
     */
    public static boolean isNotBlank(String str) {
        return !isBlank(str);
    }

    // Apache Collection Utils

    /**
     * <p>Checks if the object is in the given array.</p>
     *
     * <p>The method returns {@code false} if a {@code null} array is passed in.</p>
     *
     * @param array        the array to search through
     * @param objectToFind the object to find
     * @return {@code true} if the array contains the object
     */
    public static boolean contains(Object[] array, Object objectToFind) {
        return indexOf(array, objectToFind) != INDEX_NOT_FOUND;
    }

    /**
     * <p>Finds the index of the given object in the array.</p>
     *
     * <p>This method returns {@link #INDEX_NOT_FOUND} ({@code -1}) for a {@code null} input array.</p>
     *
     * @param array        the array to search through for the object, may be {@code null}
     * @param objectToFind the object to find, may be {@code null}
     * @return the index of the object within the array,
     * {@link #INDEX_NOT_FOUND} ({@code -1}) if not found or {@code null} array input
     */
    public static int indexOf(Object[] array, Object objectToFind) {
        return indexOf(array, objectToFind, 0);
    }

    /**
     * <p>Finds the index of the given object in the array starting at the given index.</p>
     *
     * <p>This method returns {@link #INDEX_NOT_FOUND} ({@code -1}) for a {@code null} input array.</p>
     *
     * <p>A negative startIndex is treated as zero. A startIndex larger than the array
     * length will return {@link #INDEX_NOT_FOUND} ({@code -1}).</p>
     *
     * @param array        the array to search through for the object, may be {@code null}
     * @param objectToFind the object to find, may be {@code null}
     * @param startIndex   the index to start searching at
     * @return the index of the object within the array starting at the index,
     * {@link #INDEX_NOT_FOUND} ({@code -1}) if not found or {@code null} array input
     */
    public static int indexOf(Object[] array, Object objectToFind, int startIndex) {
        if (array == null) {
            return INDEX_NOT_FOUND;
        }
        if (startIndex < 0) {
            startIndex = 0;
        }
        if (objectToFind == null) {
            for (int i = startIndex; i < array.length; i++) {
                if (array[i] == null) {
                    return i;
                }
            }
        } else if (array.getClass().getComponentType().isInstance(objectToFind)) {
            for (int i = startIndex; i < array.length; i++) {
                if (objectToFind.equals(array[i])) {
                    return i;
                }
            }
        }
        return INDEX_NOT_FOUND;
    }

    /**
     * Unconditionally close an {@code OutputStream}.
     * <p>
     * Equivalent to {@link OutputStream#close()}, except any exceptions will be ignored.
     * This is typically used in finally blocks.
     *
     * @param output the OutputStream to close, may be null or already closed
     */
    public static void closeQuietly(OutputStream output) {
        try {
            if (output != null) {
                output.close();
            }
        } catch (IOException ioe) {
            // ignore
        }
    }

    /**
     * Unconditionally close an {@code InputStream}.
     * <p>
     * Equivalent to {@link InputStream#close()}, except any exceptions will be ignored.
     * This is typically used in finally blocks.
     *
     * @param input the InputStream to close, may be null or already closed
     */
    public static void closeQuietly(InputStream input) {
        try {
            if (input != null) {
                input.close();
            }
        } catch (IOException ioe) {
            // ignore
        }
    }

    /**
     * Unconditionally close an {@code Reader}.
     * <p>
     * Equivalent to {@link Reader#close()}, except any exceptions will be ignored.
     * This is typically used in finally blocks.
     *
     * @param input the Reader to close, may be null or already closed
     */
    public static void closeQuietly(Reader input) {
        try {
            if (input != null) {
                input.close();
            }
        } catch (IOException ioe) {
            // ignore
        }
    }

    /**
     * Unconditionally close a {@code Writer}.
     * <p>
     * Equivalent to {@link Writer#close()}, except any exceptions will be ignored.
     * This is typically used in finally blocks.
     *
     * @param output the Writer to close, may be null or already closed
     */
    public static void closeQuietly(Writer output) {
        try {
            if (output != null) {
                output.close();
            }
        } catch (IOException ioe) {
            // ignore
        }
    }

    /**
     * Get the contents of an {@code InputStream} as a list of Strings,
     * one entry per line, using the default character encoding of the platform.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * {@code BufferedInputStream}.
     *
     * @param input the {@code InputStream} to read from, not null
     * @return the list of Strings, never null
     * @throws NullPointerException if the input is null
     * @throws DSSException         if an I/O error occurs
     * @since Commons IO 1.1
     */
    public static List readLines(InputStream input) throws DSSException {
        InputStreamReader reader = new InputStreamReader(input);
        return readLines(reader);
    }

    /**
     * Get the contents of a {@code Reader} as a list of Strings,
     * one entry per line.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * {@code BufferedReader}.
     *
     * @param input the {@code Reader} to read from, not null
     * @return the list of Strings, never null
     * @throws NullPointerException if the input is null
     * @throws DSSException         if an I/O error occurs
     * @since Commons IO 1.1
     */
    public static List readLines(Reader input) throws DSSException {

        try {
            BufferedReader reader = new BufferedReader(input);
            List list = new ArrayList();
            String line = reader.readLine();
            while (line != null) {
                list.add(line);
                line = reader.readLine();
            }
            return list;
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    /**
     * <p>Joins the elements of the provided array into a single String
     * containing the provided list of elements.</p>
     *
     * <p>No delimiter is added before or after the list.
     * A {@code null} separator is the same as an empty String ("").
     * Null objects or empty strings within the array are represented by
     * empty strings.</p>
     *
     * <pre>
     * DSSUtils.join(null, *)                = null
     * DSSUtils.join([], *)                  = ""
     * DSSUtils.join([null], *)              = ""
     * DSSUtils.join(["a", "b", "c"], "--")  = "a--b--c"
     * DSSUtils.join(["a", "b", "c"], null)  = "abc"
     * DSSUtils.join(["a", "b", "c"], "")    = "abc"
     * DSSUtils.join([null, "", "a"], ',')   = ",,a"
     * </pre>
     *
     * @param array     the array of values to join together, may be null
     * @param separator the separator character to use, null treated as ""
     * @return the joined String, {@code null} if null array input
     */
    public static String join(Object[] array, String separator) {
        if (array == null) {
            return null;
        }
        return join(array, separator, 0, array.length);
    }

    /**
     * <p>Joins the elements of the provided {@code Collection} into
     * a single String containing the provided elements.</p>
     *
     * <p>No delimiter is added before or after the list.
     * A {@code null} separator is the same as an empty String ("").</p>
     *
     * <p>See the examples here: {@link #join(Object[], String)}. </p>
     *
     * @param collection the {@code Collection} of values to join together, may be null
     * @param separator  the separator character to use, null treated as ""
     * @return the joined String, {@code null} if null iterator input
     * @since 2.3
     */
    public static String join(Collection collection, String separator) {
        if (collection == null) {
            return null;
        }
        return join(collection.iterator(), separator);
    }

    /**
     * <p>Joins the elements of the provided {@code Iterator} into
     * a single String containing the provided elements.</p>
     *
     * <p>No delimiter is added before or after the list.
     * A {@code null} separator is the same as an empty String ("").</p>
     *
     * <p>See the examples here: {@link #join(Object[], String)}. </p>
     *
     * @param iterator  the {@code Iterator} of values to join together, may be null
     * @param separator the separator character to use, null treated as ""
     * @return the joined String, {@code null} if null iterator input
     */
    public static String join(Iterator iterator, String separator) {

        // handle null, zero and one elements before building a buffer
        if (iterator == null) {
            return null;
        }
        if (!iterator.hasNext()) {
            return EMPTY;
        }
        Object first = iterator.next();
        if (!iterator.hasNext()) {
            return toString(first);
        }

        // two or more elements
        StringBuilder buf = new StringBuilder(256); // Java default is 16, probably too small
        if (first != null) {
            buf.append(first);
        }

        while (iterator.hasNext()) {
            if (separator != null) {
                buf.append(separator);
            }
            Object obj = iterator.next();
            if (obj != null) {
                buf.append(obj);
            }
        }
        return buf.toString();
    }

    /**
     * <p>Joins the elements of the provided array into a single String
     * containing the provided list of elements.</p>
     *
     * <p>No delimiter is added before or after the list.
     * A {@code null} separator is the same as an empty String ("").
     * Null objects or empty strings within the array are represented by
     * empty strings.</p>
     *
     * <pre>
     * DSSUtils.join(null, *)                = null
     * DSSUtils.join([], *)                  = ""
     * DSSUtils.join([null], *)              = ""
     * DSSUtils.join(["a", "b", "c"], "--")  = "a--b--c"
     * DSSUtils.join(["a", "b", "c"], null)  = "abc"
     * DSSUtils.join(["a", "b", "c"], "")    = "abc"
     * DSSUtils.join([null, "", "a"], ',')   = ",,a"
     * </pre>
     *
     * @param array      the array of values to join together, may be null
     * @param separator  the separator character to use, null treated as ""
     * @param startIndex the first index to start joining from.  It is
     *                   an error to pass in an end index past the end of the array
     * @param endIndex   the index to stop joining from (exclusive). It is
     *                   an error to pass in an end index past the end of the array
     * @return the joined String, {@code null} if null array input
     */
    public static String join(Object[] array, String separator, int startIndex, int endIndex) {
        if (array == null) {
            return null;
        }
        if (separator == null) {
            separator = EMPTY;
        }

        // endIndex - startIndex > 0:   Len = NofStrings *(len(firstString) + len(separator))
        //           (Assuming that all Strings are roughly equally long)
        int bufSize = (endIndex - startIndex);
        if (bufSize <= 0) {
            return EMPTY;
        }

        bufSize *= ((array[startIndex] == null ? 16 : array[startIndex].toString().length()) + separator.length());

        StringBuilder buf = new StringBuilder(bufSize);

        for (int ii = startIndex; ii < endIndex; ii++) {
            if (ii > startIndex) {
                buf.append(separator);
            }
            if (array[ii] != null) {
                buf.append(array[ii]);
            }
        }
        return buf.toString();
    }

    /**
     * <p>Gets the substring before the last occurrence of a separator.
     * The separator is not returned.</p>
     *
     * <p>A {@code null} string input will return {@code null}.
     * An empty ("") string input will return the empty string.
     * An empty or {@code null} separator will return the input string.</p>
     *
     * <p>If nothing is found, the string input is returned.</p>
     *
     * <pre>
     * DSSUtils.substringBeforeLast(null, *)      = null
     * DSSUtils.substringBeforeLast("", *)        = ""
     * DSSUtils.substringBeforeLast("abcba", "b") = "abc"
     * DSSUtils.substringBeforeLast("abc", "c")   = "ab"
     * DSSUtils.substringBeforeLast("a", "a")     = ""
     * DSSUtils.substringBeforeLast("a", "z")     = "a"
     * DSSUtils.substringBeforeLast("a", null)    = "a"
     * DSSUtils.substringBeforeLast("a", "")      = "a"
     * </pre>
     *
     * @param str       the String to get a substring from, may be null
     * @param separator the String to search for, may be null
     * @return the substring before the last occurrence of the separator,
     * {@code null} if null String input
     * @since 2.0
     */
    public static String substringBeforeLast(String str, String separator) {
        if (isEmpty(str) || isEmpty(separator)) {
            return str;
        }
        int pos = str.lastIndexOf(separator);
        if (pos == INDEX_NOT_FOUND) {
            return str;
        }
        return str.substring(0, pos);
    }

    /**
     * <p>Gets the substring after the last occurrence of a separator.
     * The separator is not returned.</p>
     *
     * <p>A {@code null} string input will return {@code null}.
     * An empty ("") string input will return the empty string.
     * An empty or {@code null} separator will return the empty string if
     * the input string is not {@code null}.</p>
     *
     * <p>If nothing is found, the empty string is returned.</p>
     *
     * <pre>
     * DSSUtils.substringAfterLast(null, *)      = null
     * DSSUtils.substringAfterLast("", *)        = ""
     * DSSUtils.substringAfterLast(*, "")        = ""
     * DSSUtils.substringAfterLast(*, null)      = ""
     * DSSUtils.substringAfterLast("abc", "a")   = "bc"
     * DSSUtils.substringAfterLast("abcba", "b") = "a"
     * DSSUtils.substringAfterLast("abc", "c")   = ""
     * DSSUtils.substringAfterLast("a", "a")     = ""
     * DSSUtils.substringAfterLast("a", "z")     = ""
     * </pre>
     *
     * @param str       the String to get a substring from, may be null
     * @param separator the String to search for, may be null
     * @return the substring after the last occurrence of the separator,
     * {@code null} if null String input
     * @since 2.0
     */
    public static String substringAfterLast(String str, String separator) {
        if (isEmpty(str)) {
            return str;
        }
        if (isEmpty(separator)) {
            return EMPTY;
        }
        int pos = str.lastIndexOf(separator);
        if (pos == INDEX_NOT_FOUND || pos == (str.length() - separator.length())) {
            return EMPTY;
        }
        return str.substring(pos + separator.length());
    }

    /**
     * <p>Repeat a String {@code repeat} times to form a
     * new String.</p>
     *
     * <pre>
     * DSSUtils.repeat(null, 2) = null
     * DSSUtils.repeat("", 0)   = ""
     * DSSUtils.repeat("", 2)   = ""
     * DSSUtils.repeat("a", 3)  = "aaa"
     * DSSUtils.repeat("ab", 2) = "abab"
     * DSSUtils.repeat("a", -2) = ""
     * </pre>
     *
     * @param str    the String to repeat, may be null
     * @param repeat number of times to repeat str, negative treated as zero
     * @return a new String consisting of the original String repeated,
     * {@code null} if null String input
     */
    public static String repeat(String str, int repeat) {
        // Performance tuned for 2.0 (JDK1.4)

        if (str == null) {
            return null;
        }
        if (repeat <= 0) {
            return EMPTY;
        }
        int inputLength = str.length();
        if (repeat == 1 || inputLength == 0) {
            return str;
        }
        if (inputLength == 1 && repeat <= PAD_LIMIT) {
            return padding(repeat, str.charAt(0));
        }

        int outputLength = inputLength * repeat;
        switch (inputLength) {
            case 1:
                char ch = str.charAt(0);
                char[] output1 = new char[outputLength];
                for (int i = repeat - 1; i >= 0; i--) {
                    output1[i] = ch;
                }
                return new String(output1);
            case 2:
                char ch0 = str.charAt(0);
                char ch1 = str.charAt(1);
                char[] output2 = new char[outputLength];
                for (int i = repeat * 2 - 2; i >= 0; i--, i--) {
                    output2[i] = ch0;
                    output2[i + 1] = ch1;
                }
                return new String(output2);
            default:
                StringBuilder buf = new StringBuilder(outputLength);
                for (int i = 0; i < repeat; i++) {
                    buf.append(str);
                }
                return buf.toString();
        }
    }

    /**
     * <p>Returns padding using the specified delimiter repeated
     * to a given length.</p>
     *
     * <pre>
     * DSSUtils.padding(0, 'e')  = ""
     * DSSUtils.padding(3, 'e')  = "eee"
     * DSSUtils.padding(-2, 'e') = IndexOutOfBoundsException
     * </pre>
     *
     * <p>Note: this method doesn't not support padding with
     * <a href="http://www.unicode.org/glossary/#supplementary_character">Unicode Supplementary Characters</a>
     * as they require a pair of {@code char}s to be represented.
     * If you are needing to support full I18N of your applications
     * consider using {@link #repeat(String, int)} instead.
     * </p>
     *
     * @param repeat  number of times to repeat delim
     * @param padChar character to repeat
     * @return String with repeated character
     * @throws DSSException if {@code repeat &lt; 0}
     * @see #repeat(String, int)
     */
    private static String padding(int repeat, char padChar) throws DSSException {
        if (repeat < 0) {
            throw new DSSException("Cannot pad a negative amount: " + repeat);
        }
        final char[] buf = new char[repeat];
        for (int i = 0; i < buf.length; i++) {
            buf[i] = padChar;
        }
        return new String(buf);
    }

    /**
     * <p>Gets the {@code toString} of an {@code Object} returning
     * an empty string ("") if {@code null} input.</p>
     *
     * <pre>
     * ObjectUtils.toString(null)         = ""
     * ObjectUtils.toString("")           = ""
     * ObjectUtils.toString("bat")        = "bat"
     * ObjectUtils.toString(Boolean.TRUE) = "true"
     * </pre>
     *
     * @param obj the Object to {@code toString}, may be null
     * @return the passed in Object's toString, or nullStr if {@code null} input
     * @see String#valueOf(Object)
     * @since 2.0
     */
    public static String toString(Object obj) {

        return obj == null ? "" : obj.toString();
    }

    /**
     * This method compares two {@code X500Principal}s. {@code X500Principal.CANONICAL} and {@code X500Principal.RFC2253} forms are compared.
     * TODO: (Bob: 2014 Feb 20) To be investigated why the standard equals does not work!?
     *
     * @param firstX500Principal
     * @param secondX500Principal
     * @return
     */
    public static boolean equals(X500Principal firstX500Principal, X500Principal secondX500Principal) {

        if (firstX500Principal == null || secondX500Principal == null) {
            return false;
        }
        if (firstX500Principal.equals(secondX500Principal)) {
            return true;
        }
        final String firstString = firstX500Principal.toString();
        final String secondString = secondX500Principal.toString();
        if (firstString.equals(secondString)) {
            return true;
        }
        final String firstRfc2253Name = firstX500Principal.getName(X500Principal.RFC2253);
        final String secondRfc2253Name = secondX500Principal.getName(X500Principal.RFC2253);
        if (firstRfc2253Name.equals(secondRfc2253Name)) {
            return true;
        }
        final String firstCanonicalName = firstX500Principal.getName(X500Principal.CANONICAL);
        final String secondCanonicalName = secondX500Principal.getName(X500Principal.CANONICAL);
        final boolean equals = firstCanonicalName.equals(secondCanonicalName);
        return equals;
    }

    public static InputStream getResource(final String resourcePath) {

        final InputStream resourceAsStream = DSSUtils.class.getClassLoader().getResourceAsStream(resourcePath);
        return resourceAsStream;
    }

    /**
     * This method returns an UTC date base on the year, the month and the day. The year must be encoded as 1978... and not 78
     *
     * @param year  the year
     * @param month the month
     * @param day   the day
     * @return the UTC date base on parameters
     */
    public static Date getUtcDate(final int year, final int month, final int day) {

        final Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        calendar.set(year, month, day);
        final Date date = calendar.getTime();
        return date;
    }

    /**
     * This method adds or subtract the given number of days from the date
     *
     * @param date {@code Date} to change
     * @param days number of days (can be negative)
     * @return new {@code Date}
     */
    public static Date getDate(final Date date, int days) {

        final Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.add(Calendar.DATE, days);
        final Date newDate = calendar.getTime();
        return newDate;
    }
}
