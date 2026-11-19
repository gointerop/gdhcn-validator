package co.entomo.gdhcn;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.math.BigInteger;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/**
 * End-to-end issue -> validate flow through the REST API. Only the WHO TNG trust-list call is
 * mocked (it returns a certificate generated here); everything else is the real code path:
 * JSON binding, ModelMapper, JPA, file storage, CBOR/COSE/deflate/Base45 and signature checks.
 */
@org.junit.jupiter.api.extension.ExtendWith(org.springframework.boot.test.system.OutputCaptureExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({ "test", "fileSystem" })
class IssuanceValidationFlowTests {

	static final String KID = "qb4L0atiX/4=";
	static final String COUNTRY = "XM";
	static final Path DIR;
	static final String CERTIFICATE_BASE64;

	static {
		try {
			DIR = Files.createTempDirectory("gdhcn-it");
			Files.createDirectories(DIR.resolve("json"));
			KeyPair kp = newKeyPair();
			CERTIFICATE_BASE64 = Base64.getEncoder().encodeToString(selfSigned(kp, "GDHCN Test DSC").getEncoded());
			String pem = "-----BEGIN PRIVATE KEY-----\n"
					+ Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
							.encodeToString(kp.getPrivate().getEncoded())
					+ "\n-----END PRIVATE KEY-----\n";
			Files.writeString(DIR.resolve("dsc.key"), pem);
		} catch (Exception e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	static KeyPair newKeyPair() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec("secp256r1"));
		return kpg.generateKeyPair();
	}

	static X509Certificate selfSigned(KeyPair kp, String cn) throws Exception {
		X500Name name = new X500Name("CN=" + cn + ",C=" + COUNTRY);
		Date from = new Date(System.currentTimeMillis() - 86_400_000L);
		Date to = new Date(System.currentTimeMillis() + 86_400_000L * 365);
		return new JcaX509CertificateConverter().getCertificate(
				new JcaX509v3CertificateBuilder(name, BigInteger.ONE, from, to, name, kp.getPublic())
						.build(new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate())));
	}

	@DynamicPropertySource
	static void props(DynamicPropertyRegistry r) {
		r.add("filesystem.baseLocation", DIR::toString);
		r.add("tng.dsc.privateKey", () -> DIR.resolve("dsc.key").toString());
		r.add("tng.dsc.privateKey.kid", () -> KID);
		r.add("tng.country", () -> COUNTRY);
		r.add("vhl.cors.allowed-origins", () -> "https://viewer.example.gov.br");
	}

	@Autowired
	MockMvc mvc;

	@Autowired
	co.entomo.gdhcn.service.GdhcnService gdhcnService;

	@MockitoBean
	HttpClient httpClient;

	@BeforeEach
	void publishTrustedCertificate() throws Exception {
		stubTrustList(CERTIFICATE_BASE64);
	}

	@SuppressWarnings("unchecked")
	private void stubTrustList(String certificate) throws Exception {
		HttpResponse<String> resp = mock(HttpResponse.class);
		when(resp.statusCode()).thenReturn(200);
		when(resp.body()).thenReturn("[{\"uuid\":\"u1\",\"timestamp\":\"2024-01-01T00:00:00Z\",\"country\":\""
				+ COUNTRY + "\",\"kid\":\"" + KID + "\",\"certificateType\":\"DSC\",\"version\":1,"
				+ "\"domain\":\"DCC\",\"certificate\":\"" + certificate + "\",\"group\":\"DSC\","
				+ "\"unknownFutureField\":true}]");
		when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(resp);
	}

	private String issue(String expiresOn) throws Exception {
		return issue(expiresOn, null);
	}

	private String issue(String expiresOn, String passCode) throws Exception {
		String body = "{\"jsonContent\":\"{\\\"resourceType\\\":\\\"Bundle\\\"}\""
				+ (expiresOn != null ? ",\"expiresOn\":\"" + expiresOn + "\"" : "")
				+ (passCode != null ? ",\"passCode\":\"" + passCode + "\"" : "") + "}";
		String hc1 = mvc.perform(post("/v2/vshcIssuance").contentType(MediaType.APPLICATION_JSON).content(body))
				.andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
		assertTrue(hc1.startsWith("HC1:"), "unexpected issuance output: " + hc1);
		return hc1;
	}

	private ResultActions validate(String hc1) throws Exception {
		return mvc.perform(post("/v2/vshcValidation").contentType(MediaType.APPLICATION_JSON)
				.content("{\"qrCodeContent\":\"" + hc1 + "\"}"));
	}

	@Test
	void issuedCertificateValidatesThroughAllNineSteps() throws Exception {
		ResultActions r = validate(issue("2099-01-01T00:00:00.000Z")).andExpect(status().isOk());
		for (int i = 1; i <= 9; i++) {
				r.andExpect(jsonPath("$.validationStatus['" + i + "'].status").value("SUCCESS"));
		}
		r.andExpect(jsonPath("$.shLinkContent.label").value(org.hamcrest.Matchers.nullValue()))
				.andExpect(jsonPath("$.shLinkContent.exp").isNumber());
	}

	@Test
	void legacyListFormatStillIssuesAndValidates() throws Exception {
		Object service = org.springframework.test.util.AopTestUtils.getTargetObject(gdhcnService);
		org.springframework.test.util.ReflectionTestUtils.setField(service, "vhlPayloadFormat", "list");
		try {
			ResultActions r = validate(issue("2099-01-01T00:00:00.000Z")).andExpect(status().isOk());
			for (int i = 1; i <= 9; i++) {
				r.andExpect(jsonPath("$.validationStatus['" + i + "'].status").value("SUCCESS"));
			}
			r.andExpect(jsonPath("$.shLinkContent.label").value("GDHCN Validator"));
		} finally {
			org.springframework.test.util.ReflectionTestUtils.setField(service, "vhlPayloadFormat", "map");
		}
	}

	@Test
	void certificateWithoutExpiryValidates() throws Exception {
		validate(issue(null)).andExpect(status().isOk())
				.andExpect(jsonPath("$.validationStatus['9'].status").value("SUCCESS"));
	}

	@Test
	void expiredShLinkFailsAtExpiryStep() throws Exception {
		validate(issue("2001-01-01T00:00:00.000Z")).andExpect(status().isOk())
				.andExpect(jsonPath("$.validationStatus['8'].status").value("SUCCESS"))
				.andExpect(jsonPath("$.validationStatus['9'].status").value("FAILED"));
	}

	@Test
	void signatureVerifiedAgainstADifferentKeyIsRejected() throws Exception {
		String hc1 = issue(null);
		// the trust list now publishes a different certificate under the same kid
		stubTrustList(Base64.getEncoder().encodeToString(selfSigned(newKeyPair(), "Other").getEncoded()));
		validate(hc1).andExpect(status().isOk())
				.andExpect(jsonPath("$.validationStatus['7'].status").value("FAILED"));
	}

	@Test
	void passcodeProtectedLinkYieldsTheIpsExactlyOnce() throws Exception {
		String hc1 = issue(null, "1234");
		String url = com.jayway.jsonpath.JsonPath.read(
				validate(hc1).andReturn().getResponse().getContentAsString(), "$.shLinkContent.url");
		String manifestId = url.substring(url.lastIndexOf('/') + 1);

		String manifest = mvc.perform(post("/v2/manifests/" + manifestId).contentType(MediaType.APPLICATION_JSON)
				.content("{\"recipient\":\"r\",\"passcode\":\"1234\"}")).andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();
		String location = com.jayway.jsonpath.JsonPath.read(manifest, "$.files[0].location");
		String ipsId = location.substring(location.lastIndexOf('/') + 1);

		mvc.perform(get("/v2/ips-json/" + ipsId)).andExpect(status().isOk())
				.andExpect(jsonPath("$.resourceType").value("Bundle"));
		// single use: the second download is refused
		mvc.perform(get("/v2/ips-json/" + ipsId)).andExpect(status().is4xxClientError());
	}

	// ------------------------------------------------------------------ passcode: hash, attempt limit, status codes

	@Autowired
	co.entomo.gdhcn.repository.QrCodeRepository qrCodes;

	private String manifestIdOf(String hc1) throws Exception {
		String url = com.jayway.jsonpath.JsonPath.read(
				validate(hc1).andReturn().getResponse().getContentAsString(), "$.shLinkContent.url");
		return url.substring(url.lastIndexOf('/') + 1);
	}

	private ResultActions openManifest(String manifestId, String passcode) throws Exception {
		String body = passcode == null ? "{\"recipient\":\"r\"}"
				: "{\"recipient\":\"r\",\"passcode\":\"" + passcode + "\"}";
		return mvc.perform(post("/v2/manifests/" + manifestId).contentType(MediaType.APPLICATION_JSON).content(body));
	}

	@Test
	void thePasscodeIsStoredOnlyAsAnArgon2Hash() throws Exception {
		String manifestId = manifestIdOf(issue(null, "4321"));
		co.entomo.gdhcn.entity.QrCode row = qrCodes.findByManifestId(manifestId).orElseThrow();
		assertNull(row.getPassCode());
		assertTrue(row.getPassCodeHash().startsWith("$argon2"), row.getPassCodeHash());
		assertFalse(row.getPassCodeHash().contains("4321"));
		openManifest(manifestId, "4321").andExpect(status().isOk());
	}

	@Test
	void aWrongPasscodeIs401WithTheRemainingAttempts() throws Exception {
		String manifestId = manifestIdOf(issue(null, "1234"));
		openManifest(manifestId, "0000").andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.remainingAttempts").value(4));
		openManifest(manifestId, "1111").andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.remainingAttempts").value(3));
		// the right one still works while attempts remain; the wrong ones are not forgiven
		openManifest(manifestId, "1234").andExpect(status().isOk());
		assertEquals(2, qrCodes.findByManifestId(manifestId).orElseThrow().getFailedAttempts());
	}

	@Test
	void afterTheLastAttemptTheLinkIsInactiveEvenWithTheRightPasscode() throws Exception {
		String manifestId = manifestIdOf(issue(null, "1234"));
		for (int remaining = 4; remaining >= 0; remaining--) {
			openManifest(manifestId, "9999").andExpect(status().isUnauthorized())
					.andExpect(jsonPath("$.remainingAttempts").value(remaining));
		}
		openManifest(manifestId, "9999").andExpect(status().isNotFound());
		openManifest(manifestId, "1234").andExpect(status().isNotFound());
	}

	@Test
	void aMissingPasscodeDoesNotUseUpAnAttempt() throws Exception {
		String manifestId = manifestIdOf(issue(null, "1234"));
		openManifest(manifestId, null).andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.remainingAttempts").value(5));
		openManifest(manifestId, " ").andExpect(status().isUnauthorized());
		assertEquals(0, qrCodes.findByManifestId(manifestId).orElseThrow().getFailedAttempts());
	}

	@Test
	void anUnknownLinkIs404() throws Exception {
		openManifest("does-not-exist", "1234").andExpect(status().isNotFound());
	}

	@Test
	void anExpiredLinkIs404() throws Exception {
		// a QR that is already expired does not even validate, so age a valid link instead
		String manifestId = manifestIdOf(issue("2099-01-01T00:00:00.000Z", "1234"));
		co.entomo.gdhcn.entity.QrCode row = qrCodes.findByManifestId(manifestId).orElseThrow();
		row.setExpiresOn(java.time.Instant.now().minusSeconds(60));
		qrCodes.save(row);
		openManifest(manifestId, "1234").andExpect(status().isNotFound());
	}

	@Test
	void aLinkWithoutPasscodeHasNoManifest() throws Exception {
		String manifestId = manifestIdOf(issue("2099-01-01T00:00:00.000Z", null));
		openManifest(manifestId, "1234").andExpect(status().isNotFound());
	}

	@Test
	void aLinkIssuedBeforeTheHashIsCheckedInClearAndUpgraded() throws Exception {
		String manifestId = manifestIdOf(issue(null, "1234"));
		co.entomo.gdhcn.entity.QrCode row = qrCodes.findByManifestId(manifestId).orElseThrow();
		row.setPassCodeHash(null);
		row.setPassCode("5678");
		qrCodes.save(row);

		openManifest(manifestId, "1234").andExpect(status().isUnauthorized());
		openManifest(manifestId, "5678").andExpect(status().isOk());
		row = qrCodes.findByManifestId(manifestId).orElseThrow();
		assertNull(row.getPassCode());
		assertTrue(row.getPassCodeHash().startsWith("$argon2"));
		openManifest(manifestId, "5678").andExpect(status().isOk());
	}

	// ------------------------------------------------------------------ logs without patient data, CORS, 404s

	private static final String ORIGIN = "https://viewer.example.gov.br";

	@Test
	void noPatientDataQrContentOrPasscodeReachesTheLogs(
			org.springframework.boot.test.system.CapturedOutput output) throws Exception {
		String body = "{\"jsonContent\":\"{\\\"resourceType\\\":\\\"Bundle\\\",\\\"note\\\":\\\"SENTINEL-PHI-9f3a\\\"}\","
				+ "\"expiresOn\":\"2099-01-01T00:00:00.000Z\",\"passCode\":\"pin-7391-x\"}";
		String hc1 = mvc.perform(post("/v2/vshcIssuance").contentType(MediaType.APPLICATION_JSON).content(body))
				.andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
		String manifestId = manifestIdOf(hc1);
		String manifest = openManifest(manifestId, "pin-7391-x").andExpect(status().isOk()).andReturn()
				.getResponse().getContentAsString();
		openManifest(manifestId, "wrong-pin-5528").andExpect(status().isUnauthorized());
		String location = com.jayway.jsonpath.JsonPath.read(manifest, "$.files[0].location");
		mvc.perform(get("/v2/ips-json/" + location.substring(location.lastIndexOf('/') + 1)))
				.andExpect(status().isOk());

		String logs = output.getAll();
		assertFalse(logs.contains("SENTINEL-PHI-9f3a"), "IPS content in the log");
		assertFalse(logs.contains("pin-7391-x"), "passcode in the log");
		assertFalse(logs.contains("wrong-pin-5528"), "attempted passcode in the log");
		assertFalse(logs.contains(hc1.substring(8, 60)), "QR content in the log");
	}

	@Test
	void anIssuanceFailureIsAnErrorNotANullPointer() throws Exception {
		Object service = org.springframework.test.util.AopTestUtils.getTargetObject(gdhcnService);
		Object good = org.springframework.test.util.ReflectionTestUtils.getField(service, "dscKeyPath");
		org.springframework.test.util.ReflectionTestUtils.setField(service, "dscKeyPath", "/nonexistent/dsc.key");
		try {
			mvc.perform(post("/v2/vshcIssuance").contentType(MediaType.APPLICATION_JSON)
					.content("{\"jsonContent\":\"{}\"}")).andExpect(status().isInternalServerError())
					.andExpect(jsonPath("$.error").value("Unable to issue the certificate"));
		} finally {
			org.springframework.test.util.ReflectionTestUtils.setField(service, "dscKeyPath", good);
		}
	}

	@Test
	void corsIsOnlyGrantedToTheListedOrigin() throws Exception {
		org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder preflight =
				org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options("/v2/manifests/abc")
						.header("Access-Control-Request-Method", "POST");
		mvc.perform(preflight.header("Origin", ORIGIN)).andExpect(status().isOk())
				.andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
						.string("Access-Control-Allow-Origin", ORIGIN));
		mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options("/v2/manifests/abc")
				.header("Access-Control-Request-Method", "POST").header("Origin", "https://evil.example"))
				.andExpect(status().isForbidden());
		// a link answers with the header for the listed origin and never with a wildcard
		mvc.perform(get("/v2/ips-json/abc").header("Origin", ORIGIN)).andExpect(status().isNotFound())
				.andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
						.string("Access-Control-Allow-Origin", ORIGIN));
	}

	@Test
	void ipsDownloadsThatAreNotValidAre404() throws Exception {
		mvc.perform(get("/v2/ips-json/does-not-exist")).andExpect(status().isNotFound());

		// the manifest id of a passcode-protected link is not a direct download
		String protectedId = manifestIdOf(issue(null, "1234"));
		mvc.perform(get("/v2/ips-json/" + protectedId)).andExpect(status().isNotFound());

		// a link without passcode, aged past its expiry
		String openId = manifestIdOf(issue("2099-01-01T00:00:00.000Z", null));
		co.entomo.gdhcn.entity.QrCode row = qrCodes.findByManifestId(openId).orElseThrow();
		mvc.perform(get("/v2/ips-json/" + openId)).andExpect(status().isOk());
		row.setExpiresOn(java.time.Instant.now().minusSeconds(60));
		qrCodes.save(row);
		mvc.perform(get("/v2/ips-json/" + openId)).andExpect(status().isNotFound());
	}

	@Autowired
	org.springframework.jdbc.core.JdbcTemplate jdbc;

	@Test
	void anIpsLinkPastItsLifetimeIs404() throws Exception {
		String manifestId = manifestIdOf(issue(null, "1234"));
		String manifest = openManifest(manifestId, "1234").andExpect(status().isOk()).andReturn().getResponse()
				.getContentAsString();
		String location = com.jayway.jsonpath.JsonPath.read(manifest, "$.files[0].location");
		String ipsId = location.substring(location.lastIndexOf('/') + 1);
		// created_at is set by Hibernate on insert only, so age the row directly
		assertEquals(1, jdbc.update("update ips_file set created_at = ? where id = ?",
				java.sql.Timestamp.from(java.time.Instant.now().minus(java.time.Duration.ofHours(3))), ipsId));
		mvc.perform(get("/v2/ips-json/" + ipsId)).andExpect(status().isNotFound());
	}
}
