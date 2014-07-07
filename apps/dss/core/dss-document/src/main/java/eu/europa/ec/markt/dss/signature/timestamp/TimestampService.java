package eu.europa.ec.markt.dss.signature.timestamp;

import eu.europa.ec.markt.dss.parameter.TimestampParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

/**
 * // TODO-Vin (07/07/2014): To be completed
 */
public class TimestampService {

	private TSPSource tspSource;
	private CertificatePool certificatePool;

	//Define method calling ContentTimestampGenerator
	//@return a DSSDocument containing the contentTimestamp

	public TimestampService(TSPSource tspSource, CertificatePool certificatePool) {
		this.tspSource = tspSource;
		this.certificatePool = certificatePool;
	}

	/**
	 * Method that generates a contentTimestamp as a DSSDocument
	 *
	 * @param parameters
	 * @return contentTimestamp as an InMemoryDocument
	 */
	public DSSDocument generateContentTimestamp(final TimestampParameters parameters) {

		ContentTimestampGenerator contentTimestampGenerator = new ContentTimestampGenerator(tspSource, certificatePool);
		TimestampToken token = contentTimestampGenerator.generateIndividualDataObjectsTimestamp(parameters);

		InMemoryDocument document = new InMemoryDocument(token.getEncoded());

		return document;
	}

	/**
	 * @param parameters
	 * @return
	 */
	public DSSDocument generateAllDataObjectsTimestamp(final TimestampParameters parameters) {

		final ContentTimestampGenerator generator = new ContentTimestampGenerator(tspSource, certificatePool);
		final TimestampToken token = generator.generateAllDataObjectsTimestamp(parameters);

		final InMemoryDocument inMemoryDocument = new InMemoryDocument(token.getEncoded());

		return inMemoryDocument;
	}

	public TimestampToken generateAllDataObjectsTimestampAsTimestampToken(final TimestampParameters parameters) {
		final ContentTimestampGenerator generator = new ContentTimestampGenerator(tspSource, certificatePool);
		final TimestampToken token = generator.generateAllDataObjectsTimestamp(parameters);
		return token;
	}

	/**
	 * @param parameters
	 * @return
	 */
	public DSSDocument generateIndividualDataObjectsTimestamp(final TimestampParameters parameters) {

		final ContentTimestampGenerator generator = new ContentTimestampGenerator(tspSource, certificatePool);
		final TimestampToken token = generator.generateIndividualDataObjectsTimestamp(parameters);

		final InMemoryDocument inMemoryDocument = new InMemoryDocument(token.getEncoded());

		return inMemoryDocument;
	}
}
