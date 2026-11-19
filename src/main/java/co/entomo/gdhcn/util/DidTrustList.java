package co.entomo.gdhcn.util;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import co.entomo.gdhcn.exceptions.GdhcnValidationException;
import co.entomo.gdhcn.vo.GdhcnCertificateVO;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Reads the DSCs from the public GDHCN trust list published as a DID document (for DEV:
 * {@code https://tng-cdn-dev.who.int/v2/trustlist/did.json}). The document is public: no client certificate
 * (mTLS) is needed to <em>validate</em> a QR; the TLS certificate is only needed to <em>register</em> a DSC.
 *
 * <p>Each verification method has an id like {@code did:web:<host>:v2:trustlist:<DOMAIN>:<COUNTRY>:<GROUP>#<kid>}
 * and a {@code publicKeyJwk} whose {@code x5c[0]} is the Base64 DER of the certificate.
 *
 * <p>The list is cached for {@code gdhcn.trustlist.ttl-minutes}. An unknown {@code kid} triggers a refresh, at most
 * once per {@code gdhcn.trustlist.min-refresh-seconds}. If a refresh fails the previous copy keeps being served for
 * up to {@code gdhcn.trustlist.max-stale-hours}.
 *
 * <p>Not done here: the {@code proof} (JsonWebSignature2020) of the document is not verified. Trust rests on HTTPS to
 * the CDN, as it did on mTLS to the TNG API before.
 */
@Slf4j
@Component
public class DidTrustList {

	private static final Pattern ID = Pattern.compile(":([^:#]+):([^:#]+):([^:#]+)#(.+)$");

	private record Snapshot(Instant loadedAt, List<GdhcnCertificateVO> certificates) { }

	@Autowired
	HttpClient httpClient;
	@Value("${gdhcn.trustlist.did.url:https://tng-cdn-dev.who.int/v2/trustlist/did.json}")
	private String url;
	@Value("${gdhcn.trustlist.ttl-minutes:60}")
	private long ttlMinutes;
	@Value("${gdhcn.trustlist.min-refresh-seconds:60}")
	private long minRefreshSeconds;
	@Value("${gdhcn.trustlist.max-stale-hours:24}")
	private long maxStaleHours;

	private final JsonMapper mapper = JsonMapper.builder().build();
	private final AtomicReference<Snapshot> snapshot = new AtomicReference<>();
	private volatile Instant lastAttempt = Instant.EPOCH;

	/** The DSC for {@code country} and {@code kid}, or {@code null} when the list does not have it. */
	public GdhcnCertificateVO find(String country, String kid) throws GdhcnValidationException {
		Snapshot current = ensureFresh();
		GdhcnCertificateVO found = lookup(current, country, kid);
		if (found == null && refreshAllowed()) {
			found = lookup(refresh(), country, kid);
		}
		return found;
	}

	/** True once a copy of the list that is not older than the stale limit is available. */
	public boolean isLoaded() {
		Snapshot s = snapshot.get();
		return s != null && !tooOld(s);
	}

	/** Tries to load the list; used at startup so that readiness reflects it. Never throws. */
	public boolean tryLoad() {
		try {
			refresh();
			return true;
		} catch (GdhcnValidationException e) {
			log.warn("Trust list not loaded: {}", e.getMessage());
			return false;
		}
	}

	private Snapshot ensureFresh() throws GdhcnValidationException {
		Snapshot s = snapshot.get();
		if (s == null || Duration.between(s.loadedAt(), Instant.now()).toMinutes() >= ttlMinutes) {
			return refresh();
		}
		return s;
	}

	private boolean refreshAllowed() {
		return Duration.between(lastAttempt, Instant.now()).getSeconds() >= minRefreshSeconds;
	}

	private boolean tooOld(Snapshot s) {
		return Duration.between(s.loadedAt(), Instant.now()).toHours() >= maxStaleHours;
	}

	private static GdhcnCertificateVO lookup(Snapshot s, String country, String kid) {
		if (kid == null || country == null) {
			return null;
		}
		for (GdhcnCertificateVO c : s.certificates()) {
			if (sameCountry(country, c.getCountry()) && kid.contentEquals(c.getKid())) {
				return c;
			}
		}
		return null;
	}

	/**
	 * A QR carries the ISO 3166 alpha-2 code in {@code iss} (BR) while the DID document ids use alpha-3 (BRA).
	 * Both forms match; codes that have no alpha-3 (such as user-assigned ones) only match as they are.
	 */
	static boolean sameCountry(String fromQr, String fromList) {
		if (fromList == null) {
			return false;
		}
		if (fromQr.equalsIgnoreCase(fromList)) {
			return true;
		}
		try {
			return fromQr.length() == 2 && new java.util.Locale.Builder().setRegion(fromQr).build().getISO3Country()
					.equalsIgnoreCase(fromList);
		} catch (RuntimeException e) {
			return false;
		}
	}

	private synchronized Snapshot refresh() throws GdhcnValidationException {
		lastAttempt = Instant.now();
		Snapshot previous = snapshot.get();
		try {
			HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(20))
					.header("Accept", "application/json").GET().build();
			HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() != java.net.HttpURLConnection.HTTP_OK) {
				throw new IOException("Trust list answered HTTP " + response.statusCode());
			}
			Snapshot loaded = new Snapshot(Instant.now(), parse(response.body()));
			snapshot.set(loaded);
			log.info("Trust list loaded: {} DSC entries", loaded.certificates().size());
			return loaded;
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return stale(previous, e);
		} catch (IOException | RuntimeException e) {
			return stale(previous, e);
		}
	}

	private Snapshot stale(Snapshot previous, Exception cause) throws GdhcnValidationException {
		if (previous != null && !tooOld(previous)) {
			log.warn("Trust list refresh failed, serving the copy from {}: {}", previous.loadedAt(), cause.getMessage());
			return previous;
		}
		throw new GdhcnValidationException("Unable to load the trust list: " + cause.getMessage());
	}

	List<GdhcnCertificateVO> parse(String body) throws IOException {
		JsonNode root = mapper.readTree(body);
		JsonNode methods = root.path("verificationMethod");
		if (!methods.isArray()) {
			throw new IOException("Trust list has no verificationMethod array");
		}
		List<GdhcnCertificateVO> out = new ArrayList<>();
		for (JsonNode m : methods) {
			Matcher id = ID.matcher(m.path("id").asString(""));
			if (!id.find() || !"DSC".equals(id.group(3))) {
				continue;
			}
			JsonNode x5c = m.path("publicKeyJwk").path("x5c");
			if (!x5c.isArray() || x5c.size() == 0) {
				continue;
			}
			String certificate = x5c.get(0).asString("");
			GdhcnCertificateVO vo = new GdhcnCertificateVO();
			vo.setDomain(id.group(1));
			vo.setCountry(id.group(2));
			vo.setGroup("DSC");
			vo.setCertificateType("DSC");
			vo.setKid(id.group(4));
			vo.setCertificate(certificate);
			vo.setThumbprint(thumbprint(certificate));
			out.add(vo);
		}
		return out;
	}

	private static String thumbprint(String base64Der) {
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Base64.getDecoder().decode(base64Der)));
		} catch (Exception e) {
			return null;
		}
	}
}
