package eu.europa.esig.dss.exception;

import eu.europa.esig.dss.DSSException;

public class SigningCertificateUnknownException extends DSSException {
    public SigningCertificateUnknownException() {
        super("Signing certificate is UNKNOWN according to OCSP responder.");
    }
}
