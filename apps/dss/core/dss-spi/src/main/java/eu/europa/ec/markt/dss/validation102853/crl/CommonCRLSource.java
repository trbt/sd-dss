package eu.europa.ec.markt.dss.validation102853.crl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

/**
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public abstract class CommonCRLSource implements CRLSource {

    /**
     * This method verifies the signature of the CRL and the key usage of the signing certificate. If one of the tests fails {@code null} is
     * returned. If CRL or signing certificate are {@code null} than {@code null} is returned.
     *
     * @param x509CRL    CRL to be verified (can be null)
     * @param issuerCert CRL signing certificate (can be null)
     * @return CRL list or null
     */
    protected X509CRL verify(final X509CRL x509CRL, final X509Certificate issuerCert) {

        if (x509CRL == null || issuerCert == null) {

            return null;
        }
        try {

            x509CRL.verify(issuerCert.getPublicKey());
        } catch (final Exception e) {

            //LOG.warn("The CRL signature is not valid!" + e.getMessage());
            return null;
        }
        // assert CRLSign KeyUsage bit
        final boolean[] keyUsage = issuerCert.getKeyUsage();
        if (keyUsage == null || !keyUsage[6]) {

            //LOG.warn("No KeyUsage extension for CRL issuing certificate!");
            return null;
        }
        return x509CRL;
    }

    protected CRLValidity isValidCRL(final X509CRL x509CRL, final CertificateToken issuerToken) {

        final CRLValidity crlValidity = new CRLValidity();
        crlValidity.x509CRL = x509CRL;

        final X500Principal x509CRLIssuerX500Principal = x509CRL.getIssuerX500Principal();
        final X500Principal issuerTokenSubjectX500Principal = issuerToken.getSubjectX500Principal();
        if (x509CRLIssuerX500Principal.equals(issuerTokenSubjectX500Principal)) {

            crlValidity.issuerX509PrincipalMatches = true;
        }
        try {

            x509CRL.verify(issuerToken.getPublicKey());
            crlValidity.signatureIntact = true;
            crlValidity.issuerToken = issuerToken;
        } catch (InvalidKeyException e) {
            setSignatureInvalidityReason(crlValidity, e);
        } catch (CRLException e) {
            setSignatureInvalidityReason(crlValidity, e);
        } catch (NoSuchAlgorithmException e) {
            setSignatureInvalidityReason(crlValidity, e);
        } catch (SignatureException e) {
            setSignatureInvalidityReason(crlValidity, e);
        } catch (NoSuchProviderException e) {
            throw new DSSException(e);
        }
        if (crlValidity.signatureIntact) {

            crlValidity.hasCRLSignKeyUsage = issuerToken.hasCRLSignKeyUsage();
        }
        return crlValidity;
    }

    private void setSignatureInvalidityReason(final CRLValidity crlValidity, final Exception e) {

        crlValidity.signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
    }
}
