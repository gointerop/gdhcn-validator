package co.entomo.gdhcn.service.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

class LocalFileSystemTest {

	private LocalFileSystem fs(Path base) {
		LocalFileSystem fs = new LocalFileSystem();
		ReflectionTestUtils.setField(fs, "baseLocation", base.toString());
		ReflectionTestUtils.setField(fs, "jsonFolder", "json");
		return fs;
	}

	@Test
	void createsTheJsonFolderWhenWritingText(@TempDir Path base) throws Exception {
		LocalFileSystem fs = fs(base);
		fs.uploadJson("a.json", "{\"a\":1}");
		assertEquals("{\"a\":1}", Files.readString(base.resolve("json").resolve("a.json")));
		assertEquals("{\"a\":1}", new String(fs.downloadJson("a.json").readAllBytes()));
	}

	@Test
	void createsTheJsonFolderWhenCopyingAFile(@TempDir Path base) throws Exception {
		File source = Files.writeString(base.resolve("source.tmp"), "{\"b\":2}").toFile();
		LocalFileSystem fs = fs(base);
		fs.uploadJson("b.json", source);
		assertEquals("{\"b\":2}", Files.readString(base.resolve("json").resolve("b.json")));
	}

	@Test
	void refusesToOverwriteAnExistingText(@TempDir Path base) throws Exception {
		LocalFileSystem fs = fs(base);
		fs.uploadJson("c.json", "1");
		assertThrows(java.nio.file.FileAlreadyExistsException.class, () -> fs.uploadJson("c.json", "2"));
	}
}
