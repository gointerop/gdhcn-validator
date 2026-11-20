package co.entomo.gdhcn.hcert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectDecrypter;

/** Nimbus JOSE is the independent reader: whatever it opens is what a SMART Health Links viewer can open. */
class JweEncryptorTest {

	private static String newKey() {
		byte[] k = new byte[32];
		new SecureRandom().nextBytes(k);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(k);
	}

	@Test
	void nimbusOpensWhatWeEncrypt() throws Exception {
		String key = newKey();
		String json = "{\"resourceType\":\"Bundle\",\"nota\":\"ação\"}";
		String jwe = JweEncryptor.encrypt(json, key, "application/fhir+json");

		assertEquals(5, jwe.split("\\.", -1).length);
		JWEObject parsed = JWEObject.parse(jwe);
		assertEquals("dir", parsed.getHeader().getAlgorithm().getName());
		assertEquals("A256GCM", parsed.getHeader().getEncryptionMethod().getName());
		assertEquals("application/fhir+json", parsed.getHeader().getContentType());
		parsed.decrypt(new DirectDecrypter(Base64.getUrlDecoder().decode(key)));
		assertEquals(json, parsed.getPayload().toString());
	}

	@Test
	void everyCallUsesANewNonce() {
		String key = newKey();
		assertNotEquals(JweEncryptor.encrypt("{}", key, null), JweEncryptor.encrypt("{}", key, null));
	}

	@Test
	void aDifferentKeyDoesNotOpenIt() throws Exception {
		String jwe = JweEncryptor.encrypt("{}", newKey(), null);
		JWEObject parsed = JWEObject.parse(jwe);
		assertThrows(com.nimbusds.jose.JOSEException.class,
				() -> parsed.decrypt(new DirectDecrypter(Base64.getUrlDecoder().decode(newKey()))));
	}

	@Test
	void aTamperedCiphertextIsRejected() throws Exception {
		String key = newKey();
		String[] parts = JweEncryptor.encrypt("{\"a\":1}", key, null).split("\\.", -1);
		byte[] ct = Base64.getUrlDecoder().decode(parts[3]);
		ct[0] ^= 1;
		parts[3] = Base64.getUrlEncoder().withoutPadding().encodeToString(ct);
		JWEObject parsed = JWEObject.parse(String.join(".", parts));
		assertThrows(com.nimbusds.jose.JOSEException.class,
				() -> parsed.decrypt(new DirectDecrypter(Base64.getUrlDecoder().decode(key))));
	}

	@Test
	void theKeyMustBe256Bits() {
		assertThrows(IllegalArgumentException.class, () -> JweEncryptor.encrypt("{}", "c2hvcnQ", null));
	}
}
