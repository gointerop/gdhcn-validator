package co.entomo.gdhcn.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Key and certificate settings accept either a file path or the PEM text itself. The second form is how an
 * ECS task receives a Secrets Manager value ({@code secrets: valueFrom}): as an environment variable, with no file
 * written to disk.
 */
public final class PemSource {

    private PemSource() { }

    /** The PEM text: the value itself when it starts with {@code -----BEGIN}, otherwise the content of that file. */
    public static String read(String valueOrPath) throws IOException {
        if (valueOrPath == null || valueOrPath.isBlank()) {
            throw new IOException("No key or certificate configured");
        }
        String trimmed = valueOrPath.trim();
        if (trimmed.startsWith("-----BEGIN")) {
            return trimmed + System.lineSeparator();
        }
        return Files.readString(Path.of(trimmed), StandardCharsets.UTF_8);
    }
}
