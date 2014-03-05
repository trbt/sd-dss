package eu.europa.ec.markt.dss.validation102853;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.util.List;

import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.validation102853.report.DetailedReport;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;

/**
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public interface DocumentValidator {

    DSSDocument getDocument();

    DSSDocument getExternalContent();

    /**
     * Retrieves the signatures found in the document
     *
     * @return a list of AdvancedSignatures for validation purposes
     */
    List<AdvancedSignature> getSignatures();

    void setCertificateVerifier(final CertificateVerifier certVerifier);

    void setExternalContent(final DSSDocument externalContent);

    void setPolicyFile(final File policyDocument);

    void setPolicyFile(final String signatureId, final File policyDocument);

    DetailedReport validateDocument();

    DetailedReport validateDocument(final URL validationPolicyURL);

    DetailedReport validateDocument(final String policyResourcePath);

    DetailedReport validateDocument(final File policyFile);

    DetailedReport validateDocument(final InputStream policyDataStream);

    DiagnosticData getDiagnosticData();

    SimpleReport getSimpleReport();

    DetailedReport getDetailedReport();

    void printReports();
}
