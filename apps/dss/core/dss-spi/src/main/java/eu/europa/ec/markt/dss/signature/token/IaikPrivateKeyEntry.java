package eu.europa.ec.markt.dss.signature.token;
import iaik.pkcs.pkcs11.Token;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;


public class IaikPrivateKeyEntry implements DSSPrivateKeyEntry
{
	private X509Certificate m_cert;
	private PrivateKey m_key;
	private Token m_tok;
	
	public  IaikPrivateKeyEntry(PrivateKey key, X509Certificate cert, Token tok)
	{
		m_key = key;
		m_cert = cert;
		m_tok = tok;
	}
	
	/**
     * @return the certificate
     */
    public X509Certificate getCertificate() { return m_cert; }

    /**
     * @return the certificateChain
     */
    public X509Certificate[] getCertificateChain()
    {
    	X509Certificate[] chain = new X509Certificate[1];
    	chain[0] = m_cert;
    	return chain;
    }

    /**
     * Get the SignatureAlgorithm corresponding to the PrivateKey
     *
     * @return
     */
    public EncryptionAlgorithm getEncryptionAlgorithm() throws DSSException
    {
    	return null; //???
    }

    /**
     * Returns the encapsulated private key.
     *
     * @return
     */
    public PrivateKey getPrivateKey() { return m_key; }
    
    public Token getToken() { return m_tok; }
}
