package co.entomo.gdhcn.hcert;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import co.entomo.gdhcn.vo.SHLinkContent;

/**
 * Builds and reads the CWT payload that carries a Verifiable Health Link (VHL) in the HCERT claim
 * {@code -260 -> 5}.
 *
 * <p>Writing uses integer CWT keys (1 iss, 6 iat, 4 exp, -260 hcert) with times in seconds. The VHL is, by
 * default, a CBOR map with text keys {@code url}, {@code key}, {@code flag} and {@code exp} (seconds), with no
 * {@code label}, {@code v} or {@code type}: that is what makes the QR short. {@link Format#LIST} writes the
 * older {@code [{u: "shlink://<Base64 JSON>"}]} form (which the WHO Android verifier reads) as a fallback.
 *
 * <p>Reading accepts every form seen so far: integer or text CWT keys, the map, the list, a bare text link,
 * the {@code shlink:/} and {@code vhlink:/} prefixes with Base64 or Base64url, and expiry in seconds or
 * milliseconds.
 */
public final class VhlPayloadCodec {

    public enum Format { MAP, LIST }

    /** What was read from a payload. {@code link.exp} is in milliseconds, as the API has always returned it. */
    public record Decoded(String iss, Long iat, Long exp, SHLinkContent link) { }

    private static final int CWT_ISS = 1;
    private static final int CWT_EXP = 4;
    private static final int CWT_IAT = 6;
    private static final int CLAIM_HCERT = -260;
    private static final int HCERT_VHL = 5;
    /** Epoch values at or above this are milliseconds (this is year 5138 when read as seconds). */
    private static final long MILLIS_THRESHOLD = 100_000_000_000L;

    private VhlPayloadCodec() { }

    public static Format parseFormat(String value) {
        return "list".equalsIgnoreCase(value) ? Format.LIST : Format.MAP;
    }

    public static byte[] encode(String iss, long iatSeconds, long expSeconds, SHLinkContent link, Format format) {
        CBORObject vhl = format == Format.LIST ? legacyList(link) : map(link);
        CBORObject hcert = CBORObject.NewMap().Add(CBORObject.FromObject(HCERT_VHL), vhl);
        CBORObject cwt = CBORObject.NewMap()
                .Add(CBORObject.FromObject(CWT_ISS), CBORObject.FromObject(iss))
                .Add(CBORObject.FromObject(CWT_IAT), CBORObject.FromObject(iatSeconds))
                .Add(CBORObject.FromObject(CWT_EXP), CBORObject.FromObject(expSeconds))
                .Add(CBORObject.FromObject(CLAIM_HCERT), hcert);
        return cwt.EncodeToBytes();
    }

    public static Decoded decode(byte[] cbor) {
        CBORObject cwt = CBORObject.DecodeFromBytes(cbor);
        if (cwt.getType() != CBORType.Map) {
            throw new IllegalArgumentException("CWT payload is not a CBOR map");
        }
        CBORObject iss = claim(cwt, CWT_ISS);
        CBORObject iat = claim(cwt, CWT_IAT);
        CBORObject exp = claim(cwt, CWT_EXP);
        CBORObject hcert = claim(cwt, CLAIM_HCERT);
        CBORObject vhl = hcert == null ? null : claim(hcert, HCERT_VHL);
        if (vhl == null) {
            throw new IllegalArgumentException("No health link in claim -260/5");
        }
        return new Decoded(
                iss == null || iss.getType() != CBORType.TextString ? null : iss.AsString(),
                number(iat), number(exp), link(vhl));
    }

    // ------------------------------------------------------------------ writing

    private static CBORObject map(SHLinkContent link) {
        CBORObject m = CBORObject.NewMap()
                .Add("url", CBORObject.FromObject(link.getUrl()))
                .Add("key", CBORObject.FromObject(link.getKey()));
        if (link.getFlag() != null) {
            m.Add("flag", CBORObject.FromObject(link.getFlag()));
        }
        if (link.getExp() != null) {
            m.Add("exp", CBORObject.FromObject(toSeconds(link.getExp())));
        }
        return m;
    }

    private static CBORObject legacyList(SHLinkContent link) {
        CBORObject json = CBORObject.NewMap().Add("url", link.getUrl());
        if (link.getFlag() != null) {
            json.Add("flag", link.getFlag());
        }
        if (link.getExp() != null) {
            json.Add("exp", link.getExp());
        }
        json.Add("key", link.getKey());
        if (link.getLabel() != null) {
            json.Add("label", link.getLabel());
        }
        String u = "shlink://" + Base64.getEncoder().encodeToString(json.ToJSONString().getBytes(StandardCharsets.UTF_8));
        return CBORObject.NewArray().Add(CBORObject.NewMap().Add("u", u));
    }

    // ------------------------------------------------------------------ reading

    private static SHLinkContent link(CBORObject vhl) {
        switch (vhl.getType()) {
            case Map:
                return fromMap(vhl);
            case Array:
                if (vhl.size() == 0) {
                    throw new IllegalArgumentException("Empty health link list");
                }
                return link(vhl.get(0));
            case TextString:
                return fromText(vhl.AsString());
            default:
                throw new IllegalArgumentException("Unsupported health link type " + vhl.getType());
        }
    }

    private static SHLinkContent fromMap(CBORObject m) {
        CBORObject u = text(m, "u");
        if (u != null) {
            return fromText(u.AsString());
        }
        CBORObject url = text(m, "url");
        if (url == null) {
            throw new IllegalArgumentException("Health link has neither url nor u");
        }
        return SHLinkContent.builder()
                .url(url.AsString())
                .key(string(text(m, "key")))
                .flag(string(text(m, "flag")))
                .label(string(text(m, "label")))
                .exp(toMillis(number(text(m, "exp"))))
                .build();
    }

    private static SHLinkContent fromText(String link) {
        String body = link.replaceFirst("^(shlink|vhlink):/{1,2}", "");
        byte[] bytes = Base64.getUrlDecoder().decode(body.replace('+', '-').replace('/', '_'));
        return fromMap(CBORObject.FromJSONString(new String(bytes, StandardCharsets.UTF_8)));
    }

    // ------------------------------------------------------------------ helpers

    private static CBORObject claim(CBORObject m, int key) {
        CBORObject v = m.get(CBORObject.FromObject(key));
        return v != null ? v : m.get(CBORObject.FromObject(Integer.toString(key)));
    }

    private static CBORObject text(CBORObject m, String key) {
        return m.get(CBORObject.FromObject(key));
    }

    private static String string(CBORObject o) {
        return o == null || o.getType() != CBORType.TextString ? null : o.AsString();
    }

    private static Long number(CBORObject o) {
        return o == null || !o.isNumber() ? null : o.AsInt64Value();
    }

    private static long toSeconds(long epoch) {
        return epoch >= MILLIS_THRESHOLD ? epoch / 1000L : epoch;
    }

    private static Long toMillis(Long epoch) {
        return epoch == null ? null : (epoch >= MILLIS_THRESHOLD ? epoch : epoch * 1000L);
    }
}
