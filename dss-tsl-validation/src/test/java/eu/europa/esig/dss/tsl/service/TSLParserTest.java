package eu.europa.esig.dss.tsl.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.tsl.Condition;
import eu.europa.esig.dss.tsl.TSLConditionsForQualifiers;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLPointer;
import eu.europa.esig.dss.tsl.TSLService;
import eu.europa.esig.dss.tsl.TSLServiceExtension;
import eu.europa.esig.dss.tsl.TSLServiceProvider;
import eu.europa.esig.dss.x509.CertificateToken;

public class TSLParserTest {

	@Test
	public void parseLOTL() throws Exception {
		TSLParser parser = new TSLParser(new FileInputStream(new File("src/test/resources/LOTL.xml")));
		TSLParserResult model = parser.call();
		assertNotNull(model);
		assertNotNull(model.getNextUpdateDate());
		assertNotNull(model.getIssueDate());
		assertEquals("EU", model.getTerritory());
		assertEquals(115, model.getSequenceNumber());
		List<TSLPointer> pointers = model.getPointers();
		assertTrue(CollectionUtils.isNotEmpty(pointers));
		for (TSLPointer tslPointer : pointers) {
			assertTrue(StringUtils.isNotEmpty(tslPointer.getMimeType()));
			assertTrue(StringUtils.isNotEmpty(tslPointer.getTerritory()));
			assertTrue(StringUtils.isNotEmpty(tslPointer.getUrl()));
			assertTrue(CollectionUtils.isNotEmpty(tslPointer.getPotentialSigners()));
		}
		assertTrue(CollectionUtils.isNotEmpty(model.getDistributionPoints()));
	}

	@Test
	public void countCertificatesLT() throws Exception {
		int oldResult = 35;
		TSLParser parser = new TSLParser(new FileInputStream(new File("src/test/resources/tsls/621C7723265CA33AAD0607B3C612B313872E7514.xml")));
		TSLParserResult model = parser.call();

		Set<CertificateToken> certs = new HashSet<CertificateToken>();
		List<TSLServiceProvider> serviceProviders = model.getServiceProviders();
		for (TSLServiceProvider tslServiceProvider : serviceProviders) {
			List<TSLService> services = tslServiceProvider.getServices();
			for (TSLService tslService : services) {
				certs.addAll(tslService.getCertificates());
			}
		}
		assertEquals(oldResult, certs.size());
	}

	@Test
	public void countCertificatesDE() throws Exception {
		int oldResult = 413;
		TSLParser parser = new TSLParser(new FileInputStream(new File("src/test/resources/tsls/59F95095730A1809A027655246D6524959B191A8.xml")));
		TSLParserResult model = parser.call();

		Set<CertificateToken> certs = new HashSet<CertificateToken>();
		List<TSLServiceProvider> serviceProviders = model.getServiceProviders();
		for (TSLServiceProvider tslServiceProvider : serviceProviders) {
			List<TSLService> services = tslServiceProvider.getServices();
			for (TSLService tslService : services) {
				certs.addAll(tslService.getCertificates());
			}
		}
		assertEquals(oldResult, certs.size());
	}

	@Test
	public void serviceQualificationEE() throws Exception {
		// ***************************** OLD VERSION OF TL
		TSLParser parser = new TSLParser(new FileInputStream(new File("src/test/resources/tsls/0A191C3E18CAB7B783E690D3E4431C354A068FF0.xml")));
		TSLParserResult model = parser.call();

		List<TSLServiceProvider> serviceProviders = model.getServiceProviders();
		assertEquals(2, serviceProviders.size());

		TSLService service = getESTEIDSK2007(serviceProviders);
		assertNotNull(service);

		List<TSLServiceExtension> extensions = service.getExtensions();
		assertEquals(1, extensions.size());
		TSLServiceExtension extension = extensions.get(0);

		List<TSLConditionsForQualifiers> conditionsForQualifiers = extension.getConditionsForQualifiers();
		assertEquals(1, conditionsForQualifiers.size());

		TSLConditionsForQualifiers qcStatement = getQualificationQCStatement(conditionsForQualifiers);
		assertNull(qcStatement);

		// ***************************** NEW VERSION OF TL

		CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID3DCCAsSgAwIBAgIER/idhzANBgkqhkiG9w0BAQUFADBbMQswCQYDVQQGEwJFRTEiMCAGA1UEChMZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEPMA0GA1UECxMGRVNURUlEMRcwFQYDVQQDEw5FU1RFSUQtU0sgMjAwNzAeFw0wODA0MDYwOTUzMDlaFw0xMjAzMDUyMjAwMDBaMIGWMQswCQYDVQQGEwJFRTEPMA0GA1UEChMGRVNURUlEMRowGAYDVQQLExFkaWdpdGFsIHNpZ25hdHVyZTEiMCAGA1UEAxMZU0lOSVZFRSxWRUlLTywzNjcwNjAyMDIxMDEQMA4GA1UEBBMHU0lOSVZFRTEOMAwGA1UEKhMFVkVJS08xFDASBgNVBAUTCzM2NzA2MDIwMjEwMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCGRN42R9e6VEHMCyvacuubjtm1+5Kk92WgIgtWA8hY8DW2iNvQJ3jOF5XlVIyIDTwl2JVKxWKhXX+8+yNFPpqAK43IINcmMfznw/KcR7jACGNuTrivA9HrvRiqDzTg5E1rktjho6OkDkdV3dgOLB2wyhVm2anNpICfrUq8c09HPwIDMMP5o4HvMIHsMA4GA1UdDwEB/wQEAwIGQDA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vd3d3LnNrLmVlL2NybHMvZXN0ZWlkL2VzdGVpZDIwMDcuY3JsMFEGA1UdIARKMEgwRgYLKwYBBAHOHwEBAQEwNzASBggrBgEFBQcCAjAGGgRub25lMCEGCCsGAQUFBwIBFhVodHRwOi8vd3d3LnNrLmVlL2Nwcy8wHwYDVR0jBBgwFoAUSAbevoyHV5WAeGP6nCMrK6A6GHUwHQYDVR0OBBYEFJAJUyDrH3rdxTStU+LDa6aHdE8dMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEFBQADggEBAA5qjfeuTdOoEtatiA9hpjDHzyqN1PROcaPrABXGqpLxcHbLVr7xmovILAjxS9fJAw28u9ZE3asRNa9xgQNTeX23mMlojJAYVbYCeIeJ6jtsRiCo34wgvO3CtVfO3+C1T8Du5XLCHa6SoT8SpCApW+Crwe+6eCZDmv2NKTjhn1wCCNO2e8HuSt+pTUNBTUB+rkvF4KO9VnuzRzT7zN7AUdW4OFF3bI+9+VmW3t9vq1zDOxNTdBkCM3zm5TRa8ZtyAPL48bW19JAcYzQLjPGORwoIRNSXdVTqX+cDiw2wbmb2IhPdxRqN9uPwU1x/ltZZ3W5GzJ1t8JeQN7PuGM0OHqE=");

		parser = new TSLParser(new FileInputStream(new File("src/test/resources/tsls/0A191C3E18CAB7B783E690D3E4431C354A068FF0-2.xml")));
		model = parser.call();

		serviceProviders = model.getServiceProviders();
		assertEquals(2, serviceProviders.size());

		service = getESTEIDSK2007(serviceProviders);
		assertNotNull(service);

		extensions = service.getExtensions();
		assertEquals(1, extensions.size());
		extension = extensions.get(0);

		conditionsForQualifiers = extension.getConditionsForQualifiers();
		assertEquals(2, conditionsForQualifiers.size());

		qcStatement = getQualificationQCStatement(conditionsForQualifiers);
		assertNotNull(qcStatement);

		Condition condition = qcStatement.getCondition();
		assertTrue(condition.check(certificate));
	}

	private TSLConditionsForQualifiers getQualificationQCStatement(List<TSLConditionsForQualifiers> conditionsForQualifiers) {
		for (TSLConditionsForQualifiers tslConditionsForQualifiers : conditionsForQualifiers) {
			List<String> qualifiers = tslConditionsForQualifiers.getQualifiers();
			for (String qualifier : qualifiers) {
				if ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement".equals(qualifier)) {
					return tslConditionsForQualifiers;
				}
			}
		}
		return null;
	}

	private TSLService getESTEIDSK2007(List<TSLServiceProvider> serviceProviders) {
		String serviceNameToFind = "ESTEID-SK 2007: Qualified certificates for Estonian ID-card, the residence permit card, the digital identity card, the digital identity card in form of the Mobile-ID";
		TSLService service = null;

		for (TSLServiceProvider tslServiceProvider : serviceProviders) {
			List<TSLService> services = tslServiceProvider.getServices();
			for (TSLService tslService : services) {
				if (serviceNameToFind.equals(tslService.getName())) {
					service = tslService;
					break;
				}
			}
		}
		return service;
	}

	@Test
	public void countCertificatesEE_TSLv5() throws Exception {
		int oldResult = 41;
		TSLParser parser = new TSLParser(new FileInputStream(new File("src/test/resources/tsls/tl-estonia_v5.xml")));
		TSLParserResult model = parser.call();

		Set<CertificateToken> certs = new HashSet<CertificateToken>();
		List<TSLServiceProvider> serviceProviders = model.getServiceProviders();
		for (TSLServiceProvider tslServiceProvider : serviceProviders) {
			List<TSLService> services = tslServiceProvider.getServices();
			for (TSLService tslService : services) {
				certs.addAll( tslService.getCertificates());
			}
		}
		assertEquals(oldResult, certs.size());
	}

}
