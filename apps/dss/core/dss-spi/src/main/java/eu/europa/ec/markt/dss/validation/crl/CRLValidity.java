package eu.europa.ec.markt.dss.validation.crl;

import java.security.cert.X509CRL;

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
public class CRLValidity {

    X509CRL x509CRL = null;

    boolean issuerX509PrincipalMatches = false;
    boolean signatureIntact = false;
    boolean hasCRLSignKeyUsage = false;

    CertificateToken issuerToken = null;

    String signatureInvalidityReason = "";

    boolean isValid() {

        return issuerX509PrincipalMatches && signatureIntact && hasCRLSignKeyUsage;
    }
}
