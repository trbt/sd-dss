package eu.europa.ec.markt.dss.signature.timestamp;

import eu.europa.ec.markt.dss.parameter.ContentTimestampReference;
import eu.europa.ec.markt.dss.parameter.TimestampParameters;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.ByteArrayOutputStream;
import javax.xml.crypto.dsig.CanonicalizationMethod;

/**
 * From RFC 3216, section 3.12.4:
 * The content time-stamp attribute is an attribute which is the time-
 * stamp of the signed data content before it is signed.
 *
 * The content time-stamp attribute must be a signed attribute.
 *
 * The following object identifier identifies the signer-attribute
 * attribute:
 *
 * id-aa-ets-contentTimestamp OBJECT IDENTIFIER ::= { iso(1)
 * member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
 * smime(16) id-aa(2) 20}
 *
 * Content time-stamp attribute values have ASN.1 type ContentTimestamp:
 * ContentTimestamp::= TimeStampToken
 *
 * The value of messageImprint field within TimeStampToken must be a
 * hash of the value of eContent field within encapContentInfo within
 * the signedData.
 *
 * From ETSI 101 733 v2.2:
 * ----------------------
 * The content-time-stamp attribute is an attribute that is the time-stamp token of the signed data content before it
 * is signed.
 * The content-time-stamp attribute shall be a signed attribute.
 * The following object identifier identifies the content-time-stamp attribute:
 * id-aa-ets-contentTimestamp OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 20}
 *
 * content-time-stamp attribute values have ASN.1 type ContentTimestamp:
 * ContentTimestamp::= TimeStampToken
 *
 * The value of messageImprint of TimeStampToken (as described in RFC 3161 [7]) shall be a hash of the
 * message digest as defined in clause 5.6.1 of the present document.
 * For further information and definition of TimeStampToken, see clause 7.4.
 * ETSI
 * 36 ETSI TS 101 733 V2.2.1 (2013-04)
 * NOTE: content-time-stamp indicates that the signed information was formed before the date included in
 * the content-time-stamp.
 */

public class ContentTimestampGenerator {

    private final String DEFAULT_TIMESTAMP_CREATION_CANONICALIZATION_METHOD = CanonicalizationMethod.EXCLUSIVE;

    //The timestamping authority
    private TSPSource tspSource;

    private CertificatePool certificatePool;

    private TimestampParameters timestampParameters;

    public ContentTimestampGenerator() {}

    /**
     *
     * @param tspSource the timestamping authority
     * @param certificatePool
     */
    public ContentTimestampGenerator(final TSPSource tspSource, final CertificatePool certificatePool) {
        this.tspSource = tspSource;
        this.certificatePool = certificatePool;
    }

    public CertificatePool getCertificatePool() {
        return certificatePool;
    }

    public void setCertificatePool(CertificatePool certificatePool) {
        this.certificatePool = certificatePool;
    }

    public TSPSource getTspSource() {
        return tspSource;
    }

    public void setTspSource(TSPSource tspSource) {
        this.tspSource = tspSource;
    }

    public void setTimestampParameters(TimestampParameters parameters) {
        timestampParameters = parameters;
    }

    public TimestampParameters getTimestampParameters() {
        return timestampParameters;
    }

    /**
     *
     * @param timestampType
     * @return
     */
    public TimestampToken generateTimestampToken(final TimestampType timestampType, final DigestAlgorithm digestAlgorithm, final byte[] digest ) {

		final TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, digest);
		return new TimestampToken(timeStampResponse, timestampType, certificatePool);
    }

    //1. getInfo().getReferences()
    //2. for each node in getReferences() -> if node is nodeset, canonicalize it according to either ds:Canonicalization, or
    //   canonicalization method specified in xmldsig
    //3. concatenate resulting octets in byte stream
    //4. pass resulting octet stream to timestamptoken creation method, specifying timestamptype.ALLDATA.. or timestamptype.INDIV as type
    public TimestampToken generateAllDataObjectsTimestamp(final TimestampParameters parameters) {

        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		String canonicalizationMethod = parameters.getCanonicalizationMethod();
        if (canonicalizationMethod == null) {
            canonicalizationMethod = DEFAULT_TIMESTAMP_CREATION_CANONICALIZATION_METHOD;
        }

		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		byte[] digest = parameters.getDigest();
		if(digest== null){

			for (final ContentTimestampReference reference : parameters.getReferences()) {

				DSSUtils.write(reference.getData(),buffer);
			}
			digest = DSSUtils.digest(digestAlgorithm, buffer.toByteArray());
		}
        final TimestampToken token = generateTimestampToken(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP,digestAlgorithm,digest);
		return token;
    }

    public TimestampToken generateIndividualDataObjectsTimestamp(final TimestampParameters parameters) {

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		String canonicalizationMethod = parameters.getCanonicalizationMethod();
        if (canonicalizationMethod == null) {
            canonicalizationMethod = DEFAULT_TIMESTAMP_CREATION_CANONICALIZATION_METHOD;
        }
		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		byte[] digest = parameters.getDigest();
		if(digest== null){

			for (final ContentTimestampReference reference : parameters.getReferences()) {

				DSSUtils.write(reference.getData(),buffer);
			}
			digest = DSSUtils.digest(digestAlgorithm, buffer.toByteArray());
		}
		final TimestampToken token = generateTimestampToken(TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP,digestAlgorithm,digest);
        return token;
    }
}
