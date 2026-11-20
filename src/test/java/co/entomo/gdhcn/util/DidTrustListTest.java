package co.entomo.gdhcn.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import co.entomo.gdhcn.exceptions.GdhcnValidationException;
import co.entomo.gdhcn.vo.GdhcnCertificateVO;

/** Uses an excerpt of the real DEV trust list (public data): 2 BRA DSC, 1 BRA SCA, 1 CHL DSC. */
@SuppressWarnings("unchecked")
class DidTrustListTest {

	private static final String BRA_KID = "nid6LzRxNyI=";
	private static final String BRA_SCA_KID = "E9t9hna1YsE=";

	private HttpClient http;
	private DidTrustList list;
	private String body;

	@BeforeEach
	void setUp() throws Exception {
		body = new String(getClass().getResourceAsStream("/did-excerpt.json").readAllBytes(), StandardCharsets.UTF_8);
		http = mock(HttpClient.class);
		reply(200, body);
		list = new DidTrustList();
		ReflectionTestUtils.setField(list, "httpClient", http);
		ReflectionTestUtils.setField(list, "url", "https://example.invalid/did.json");
		ReflectionTestUtils.setField(list, "ttlMinutes", 60L);
		ReflectionTestUtils.setField(list, "minRefreshSeconds", 60L);
		ReflectionTestUtils.setField(list, "maxStaleHours", 24L);
	}

	private void reply(int status, String text) throws Exception {
		HttpResponse<String> resp = mock(HttpResponse.class);
		when(resp.statusCode()).thenReturn(status);
		when(resp.body()).thenReturn(text);
		when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(resp);
	}

	@Test
	void findsTheDscByCountryAndKid() throws Exception {
		// a QR says BR; the DID ids say BRA
		for (String iss : new String[] { "BR", "BRA", "br" }) {
			GdhcnCertificateVO vo = list.find(iss, BRA_KID);
			assertNotNull(vo, iss);
			assertEquals("BRA", vo.getCountry());
			assertEquals("PH4H", vo.getDomain());
			assertEquals("DSC", vo.getGroup());
			assertEquals(BRA_KID, vo.getKid());
			assertTrue(vo.getCertificate().length() > 200);
			assertEquals(64, vo.getThumbprint().length());
		}
	}

	@Test
	void doesNotReturnSigningCaOrOtherCountries() throws Exception {
		assertNull(list.find("BR", BRA_SCA_KID));
		assertNull(list.find("CL", BRA_KID));
		assertNull(list.find("BR", "unknown-kid="));
		assertNull(list.find("BR", null));
		assertNull(list.find(null, BRA_KID));
	}

	@Test
	void mapsAlpha2ToAlpha3OnlyWhereItExists() {
		assertTrue(DidTrustList.sameCountry("CL", "CHL"));
		assertTrue(DidTrustList.sameCountry("XM", "XM"));
		assertFalse(DidTrustList.sameCountry("XM", "XMX"));
		assertFalse(DidTrustList.sameCountry("BR", "CHL"));
		assertFalse(DidTrustList.sameCountry("BR", null));
	}

	@Test
	void cachesTheListWithinTheTtl() throws Exception {
		list.find("BR", BRA_KID);
		list.find("BR", BRA_KID);
		list.find("BR", BRA_KID);
		verify(http, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
	}

	@Test
	void anUnknownKidRefreshesAtMostOncePerInterval() throws Exception {
		list.find("BR", BRA_KID);
		assertNull(list.find("BR", "nope1="));
		assertNull(list.find("BR", "nope2="));
		verify(http, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));

		ReflectionTestUtils.setField(list, "minRefreshSeconds", 0L);
		assertNull(list.find("BR", "nope3="));
		verify(http, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
	}

	@Test
	void servesTheOldCopyWhenARefreshFails() throws Exception {
		list.find("BR", BRA_KID);
		ReflectionTestUtils.setField(list, "ttlMinutes", 0L);
		reply(503, "down");
		assertNotNull(list.find("BR", BRA_KID));
	}

	@Test
	void failsWhenThereIsNoCopyAndTheListIsUnreachable() throws Exception {
		reply(503, "down");
		assertThrows(GdhcnValidationException.class, () -> list.find("BR", BRA_KID));
		assertFalse(list.isLoaded());
		assertFalse(list.tryLoad());
	}

	@Test
	void rejectsADocumentThatIsNotATrustList() throws Exception {
		reply(200, "{\"hello\":\"world\"}");
		assertThrows(GdhcnValidationException.class, () -> list.find("BR", BRA_KID));
		reply(200, "not json at all");
		assertThrows(GdhcnValidationException.class, () -> list.find("BR", BRA_KID));
	}

	@Test
	void loadedOnlyAfterASuccessfulFetch() throws Exception {
		assertFalse(list.isLoaded());
		assertTrue(list.tryLoad());
		assertTrue(list.isLoaded());
	}

	@Test
	void anIoErrorOnTheFirstFetchIsAValidationError() throws Exception {
		when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenThrow(new IOException("boom"));
		assertThrows(GdhcnValidationException.class, () -> list.find("BR", BRA_KID));
	}
}
