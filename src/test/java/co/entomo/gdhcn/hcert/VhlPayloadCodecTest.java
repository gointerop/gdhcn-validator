package co.entomo.gdhcn.hcert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import co.entomo.gdhcn.vo.SHLinkContent;
import nl.minvws.encoding.Base45;

class VhlPayloadCodecTest {

	private static final long IAT = 1_795_000_000L;
	private static final long EXP_SECONDS = IAT + 3600;

	private static SHLinkContent link() {
		byte[] id = new byte[32];
		byte[] key = new byte[32];
		new SecureRandom().nextBytes(id);
		new SecureRandom().nextBytes(key);
		return SHLinkContent.builder()
				.url("https://ips.example.gov.br/v2/manifests/" + Base64.getUrlEncoder().encodeToString(id))
				.key(Base64.getUrlEncoder().encodeToString(key))
				.flag("P")
				.exp(EXP_SECONDS * 1000L)
				.label("GDHCN Validator")
				.build();
	}

	private static CBORObject vhlOf(byte[] cbor) {
		return CBORObject.DecodeFromBytes(cbor).get(CBORObject.FromObject(-260)).get(CBORObject.FromObject(5));
	}

	@Test
	void mapFormRoundTripsWithIntegerKeysAndSeconds() {
		SHLinkContent in = link();
		in.setLabel(null);
		byte[] cbor = VhlPayloadCodec.encode("BR", IAT, EXP_SECONDS, in, VhlPayloadCodec.Format.MAP);

		CBORObject cwt = CBORObject.DecodeFromBytes(cbor);
		assertEquals(IAT, cwt.get(CBORObject.FromObject(6)).AsInt64Value());
		assertEquals(EXP_SECONDS, cwt.get(CBORObject.FromObject(4)).AsInt64Value());
		assertEquals(CBORType.Map, vhlOf(cbor).getType());

		VhlPayloadCodec.Decoded out = VhlPayloadCodec.decode(cbor);
		assertEquals("BR", out.iss());
		assertEquals(IAT, out.iat());
		assertEquals(in.getUrl(), out.link().getUrl());
		assertEquals(in.getKey(), out.link().getKey());
		assertEquals("P", out.link().getFlag());
		assertEquals(EXP_SECONDS * 1000L, out.link().getExp());
		assertNull(out.link().getLabel());
	}

	@Test
	void mapFormHasNoLabelVersionOrType() {
		byte[] cbor = VhlPayloadCodec.encode("BR", IAT, EXP_SECONDS, link(), VhlPayloadCodec.Format.MAP);
		CBORObject vhl = vhlOf(cbor);
		assertEquals(4, vhl.size());
		for (String key : new String[] { "url", "key", "flag", "exp" }) {
			assertTrue(vhl.ContainsKey(CBORObject.FromObject(key)), key);
		}
		for (String absent : new String[] { "label", "v", "type" }) {
			assertFalse(vhl.ContainsKey(CBORObject.FromObject(absent)), absent);
		}
	}

	@Test
	void legacyListFormRoundTrips() {
		SHLinkContent in = link();
		byte[] cbor = VhlPayloadCodec.encode("BR", IAT, EXP_SECONDS, in, VhlPayloadCodec.Format.LIST);
		CBORObject vhl = vhlOf(cbor);
		assertEquals(CBORType.Array, vhl.getType());
		assertTrue(vhl.get(0).get(CBORObject.FromObject("u")).AsString().startsWith("shlink://"));

		VhlPayloadCodec.Decoded out = VhlPayloadCodec.decode(cbor);
		assertEquals(in.getUrl(), out.link().getUrl());
		assertEquals(in.getKey(), out.link().getKey());
		assertEquals("GDHCN Validator", out.link().getLabel());
		assertEquals(EXP_SECONDS * 1000L, out.link().getExp());
	}

	@Test
	void readsTheCensPayloadWithTextKeysAndMillisecondIat() {
		String json = "{\"url\":\"https://x.example/v2/manifests/abc\",\"flag\":\"P\",\"exp\":" + EXP_SECONDS * 1000L
				+ ",\"key\":\"k\",\"label\":\"GDHCN Validator\"}";
		String u = "shlink://" + Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
		CBORObject cwt = CBORObject.NewMap()
				.Add("1", "CL")
				.Add("6", IAT * 1000L)
				.Add("4", EXP_SECONDS)
				.Add("-260", CBORObject.NewMap().Add("5",
						CBORObject.NewArray().Add(CBORObject.NewMap().Add("u", u))));
		VhlPayloadCodec.Decoded out = VhlPayloadCodec.decode(cwt.EncodeToBytes());
		assertEquals("CL", out.iss());
		assertEquals("https://x.example/v2/manifests/abc", out.link().getUrl());
		assertEquals(EXP_SECONDS * 1000L, out.link().getExp());
	}

	@Test
	void readsBase64UrlAndVhlinkPrefixes() {
		String json = "{\"url\":\"https://x.example/m/1\",\"key\":\"k\",\"exp\":" + EXP_SECONDS + "}";
		String b64url = Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
		for (String text : new String[] { "shlink:/" + b64url, "vhlink://" + b64url }) {
			CBORObject cwt = CBORObject.NewMap().Add(1, "BR").Add(-260, CBORObject.NewMap().Add(5, text));
			VhlPayloadCodec.Decoded out = VhlPayloadCodec.decode(cwt.EncodeToBytes());
			assertEquals("https://x.example/m/1", out.link().getUrl());
			assertEquals(EXP_SECONDS * 1000L, out.link().getExp());
		}
	}

	@Test
	void rejectsPayloadsWithoutALink() {
		assertThrows(IllegalArgumentException.class,
				() -> VhlPayloadCodec.decode(CBORObject.NewMap().Add(1, "BR").EncodeToBytes()));
		assertThrows(IllegalArgumentException.class,
				() -> VhlPayloadCodec.decode(CBORObject.NewArray().EncodeToBytes()));
		assertThrows(IllegalArgumentException.class, () -> VhlPayloadCodec.decode(CBORObject
				.NewMap().Add(-260, CBORObject.NewMap().Add(5, CBORObject.NewArray())).EncodeToBytes()));
		assertThrows(IllegalArgumentException.class, () -> VhlPayloadCodec.decode(CBORObject
				.NewMap().Add(-260, CBORObject.NewMap().Add(5, CBORObject.NewMap().Add("foo", "bar"))).EncodeToBytes()));
	}

	@Test
	void parseFormatDefaultsToMap() {
		assertEquals(VhlPayloadCodec.Format.MAP, VhlPayloadCodec.parseFormat(null));
		assertEquals(VhlPayloadCodec.Format.MAP, VhlPayloadCodec.parseFormat("map"));
		assertEquals(VhlPayloadCodec.Format.LIST, VhlPayloadCodec.parseFormat("LIST"));
	}

	@Test
	void signedQrWithEightByteKidIsShortAndVerifies() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair kp = kpg.generateKeyPair();
		byte[] kid = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(kp.getPublic().getEncoded()), 8);
		String kidB64 = Base64.getEncoder().encodeToString(kid);

		SHLinkContent in = link();
		in.setLabel(null);
		byte[] cwt = VhlPayloadCodec.encode("BR", IAT, EXP_SECONDS, in, VhlPayloadCodec.Format.MAP);
		String hc1 = new GreenCertificateEncoder(kp.getPrivate(), kidB64).encodeCbor(cwt);
		assertTrue(hc1.startsWith("HC1:"));

		byte[] cose = GreenCertificateDecoder.getCoseBytes(Base45.getDecoder().decode(hc1.substring(4)));
		CoseSign1 msg = CoseSign1.decode(cose);
		assertEquals(kidB64, msg.kid());
		assertTrue(new GreenCertificateDecoder(kp.getPublic()).validate(msg));
		assertEquals(in.getUrl(), VhlPayloadCodec.decode(msg.payload()).link().getUrl());

		// the point of the exercise: well under the CENS form (about 613 characters, QR version 20)
		assertTrue(hc1.length() < 440, "HC1 length " + hc1.length());
		String list = new GreenCertificateEncoder(kp.getPrivate(), kidB64)
				.encodeCbor(VhlPayloadCodec.encode("BR", IAT, EXP_SECONDS, link(), VhlPayloadCodec.Format.LIST));
		assertTrue(list.length() > hc1.length() + 100);
	}

	@Test
	void kidThatIsNotEightBytesStaysText() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair kp = kpg.generateKeyPair();
		byte[] cwt = VhlPayloadCodec.encode("BR", IAT, EXP_SECONDS, link(), VhlPayloadCodec.Format.MAP);
		String hc1 = new GreenCertificateEncoder(kp.getPrivate(), "not-base64-eight-bytes").encodeCbor(cwt);
		byte[] cose = GreenCertificateDecoder.getCoseBytes(Base45.getDecoder().decode(hc1.substring(4)));
		assertEquals("not-base64-eight-bytes", CoseSign1.decode(cose).kid());
	}
}
