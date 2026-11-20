package co.entomo.gdhcn.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PemSourceTest {

	private static final String PEM = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";

	@Test
	void inlinePemIsReturnedAsIs() throws Exception {
		assertEquals(PEM + System.lineSeparator(), PemSource.read("  " + PEM + "\n\n"));
	}

	@Test
	void aPathIsReadFromDisk(@TempDir Path dir) throws Exception {
		Path file = Files.writeString(dir.resolve("k.pem"), PEM);
		assertEquals(PEM, PemSource.read(file.toString()));
	}

	@Test
	void missingFileFails(@TempDir Path dir) {
		assertThrows(IOException.class, () -> PemSource.read(dir.resolve("nope.pem").toString()));
	}

	@Test
	void emptySettingFailsWithAClearMessage() {
		assertTrue(assertThrows(IOException.class, () -> PemSource.read("")).getMessage().contains("No key"));
		assertThrows(IOException.class, () -> PemSource.read(null));
	}
}
