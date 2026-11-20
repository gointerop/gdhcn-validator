package co.entomo.gdhcn.hcert;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Compact JWE with direct key agreement ({@code alg: dir}) and {@code enc: A256GCM}, the form HL7 SMART Health Links
 * asks for the files behind a link. The key is the 43-character Base64url {@code key} of the link payload, which only
 * the holder of the QR knows, so the server never serves the IPS in clear when this is on.
 *
 * <p>Compact serialization: {@code BASE64URL(header) . (empty encrypted key) . BASE64URL(iv) . BASE64URL(ciphertext)
 * . BASE64URL(tag)}; the ASCII of the encoded header is the additional authenticated data. A new random 96-bit IV is
 * drawn for every call.
 */
public final class JweEncryptor {

	private static final SecureRandom RANDOM = new SecureRandom();
	private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

	private JweEncryptor() { }

	public static String encrypt(String plaintext, String keyBase64Url, String contentType) {
		byte[] key = Base64.getUrlDecoder().decode(keyBase64Url);
		if (key.length != 32) {
			throw new IllegalArgumentException("A256GCM needs a 256-bit key");
		}
		String header = "{\"alg\":\"dir\",\"enc\":\"A256GCM\"" + (contentType == null ? "" : ",\"cty\":\"" + contentType + "\"") + "}";
		String encodedHeader = B64.encodeToString(header.getBytes(StandardCharsets.UTF_8));
		byte[] iv = new byte[12];
		RANDOM.nextBytes(iv);
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
			cipher.updateAAD(encodedHeader.getBytes(StandardCharsets.US_ASCII));
			byte[] sealed = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
			int tagStart = sealed.length - 16;
			byte[] ciphertext = java.util.Arrays.copyOfRange(sealed, 0, tagStart);
			byte[] tag = java.util.Arrays.copyOfRange(sealed, tagStart, sealed.length);
			return encodedHeader + ".." + B64.encodeToString(iv) + "." + B64.encodeToString(ciphertext) + "." + B64.encodeToString(tag);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Unable to encrypt", e);
		}
	}
}
