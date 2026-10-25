package org.shem.search;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import org.apache.lucene.codecs.CodecUtil;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.Term;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.TermQuery;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.store.NIOFSDirectory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.OpaqueId;
import org.shem.crypto.SymmetricKey;
import org.shem.store.PlaintextScan;

class EncryptedDirectoryTest {
  private static final SecureRandom RANDOM = new SecureRandom();
  @TempDir Path dir;
  private SymmetricKey key;
  private final OpaqueId mailbox = OpaqueId.random(RANDOM);
  private Directory directory;

  @BeforeEach
  void setUp() throws Exception {
    key = SymmetricKey.generate(RANDOM);
    directory = new EncryptedDirectory(new NIOFSDirectory(dir), key, mailbox);
  }

  @AfterEach
  void tearDown() throws Exception {
    directory.close();
    key.close();
  }

  private byte[] write(String name, int size) throws IOException {
    byte[] data = new byte[size];
    RANDOM.nextBytes(data);
    try (IndexOutput out = directory.createOutput(name, IOContext.DEFAULT)) {
      out.writeBytes(data, 0, data.length / 2);
      for (int i = data.length / 2; i < data.length; i++) {
        out.writeByte(data[i]);
      }
      assertThat(out.getFilePointer()).isEqualTo(size);
    }
    return data;
  }

  @Test
  void randomAccessClonesAndSlicesReturnPlaintext() throws Exception {
    byte[] data = write("_0.dat", 200_000);
    assertThat(directory.fileLength("_0.dat")).isEqualTo(200_000);
    try (IndexInput in = directory.openInput("_0.dat", IOContext.DEFAULT)) {
      for (int i = 0; i < 200; i++) {
        int pos = RANDOM.nextInt(data.length - 100);
        in.seek(pos);
        byte[] chunk = new byte[100];
        in.readBytes(chunk, 0, chunk.length);
        assertThat(chunk).isEqualTo(Arrays.copyOfRange(data, pos, pos + 100));
      }
      IndexInput clone = in.clone();
      clone.seek(12345);
      assertThat(clone.readByte()).isEqualTo(data[12345]);
      IndexInput slice = in.slice("part", 50_000, 1000);
      assertThat(slice.length()).isEqualTo(1000);
      slice.seek(999);
      assertThat(slice.readByte()).isEqualTo(data[50_999]);
      assertThatThrownBy(() -> slice.seek(1001)).isInstanceOf(IOException.class);
      assertThatThrownBy(() -> in.slice("bad", 199_999, 10))
          .isInstanceOf(IllegalArgumentException.class);
    }
  }

  @Test
  void luceneChecksumsCoverPlaintext() throws Exception {
    try (IndexOutput out = directory.createOutput("_1.cs", IOContext.DEFAULT)) {
      CodecUtil.writeHeader(out, "shem-test", 1);
      out.writeString("payload");
      CodecUtil.writeFooter(out);
    }
    try (IndexInput in = directory.openInput("_1.cs", IOContext.DEFAULT)) {
      CodecUtil.checksumEntireFile(in);
    }
  }

  @Test
  void tamperingTruncationAndSwappingAreDetected() throws Exception {
    write("_2.dat", 70_000);
    write("_3.dat", 70_000);
    Path file = dir.resolve("_2.dat");
    byte[] raw = Files.readAllBytes(file);

    byte[] flipped = raw.clone();
    flipped[raw.length / 2] ^= 1;
    Files.write(file, flipped);
    assertThatThrownBy(() -> readAll("_2.dat")).isInstanceOf(IOException.class);

    Files.write(file, Arrays.copyOf(raw, raw.length - 20_000));
    assertThatThrownBy(() -> readAll("_2.dat")).isInstanceOf(IOException.class);

    Files.copy(dir.resolve("_3.dat"), file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    assertThatThrownBy(() -> readAll("_2.dat")).isInstanceOf(IOException.class);
  }

  @Test
  void wrongKeyCannotRead() throws Exception {
    write("_4.dat", 1000);
    try (SymmetricKey other = SymmetricKey.generate(RANDOM);
        Directory wrong = new EncryptedDirectory(new NIOFSDirectory(dir), other, mailbox)) {
      assertThatThrownBy(() -> wrong.openInput("_4.dat", IOContext.DEFAULT).close())
          .isInstanceOf(IOException.class);
    }
  }

  @Test
  void renameReencryptsUnderTheNewName() throws Exception {
    byte[] data = write("pending_segments_1", 3000);
    directory.rename("pending_segments_1", "segments_1");
    assertThat(directory.listAll()).contains("segments_1").doesNotContain("pending_segments_1");
    assertThat(readAll("segments_1")).isEqualTo(data);
    assertThat(
            Arrays.stream(directory.listAll())
                .filter(n -> n.startsWith(EncryptedDirectory.RENAME_PREFIX)))
        .isEmpty();
  }

  @Test
  void fullIndexLifecycleAndNoPlaintextTerms() throws Exception {
    try (IndexWriter writer = new IndexWriter(directory, new IndexWriterConfig())) {
      for (int i = 0; i < 500; i++) {
        Document doc = new Document();
        doc.add(new StringField("id", "doc" + i, Field.Store.YES));
        doc.add(new TextField("body", "secretterm" + (i % 10) + " ordinary words", Field.Store.NO));
        writer.addDocument(doc);
        if (i % 100 == 99) {
          writer.commit();
        }
      }
      writer.forceMerge(1);
      writer.commit();
    }
    try (DirectoryReader reader = DirectoryReader.open(directory)) {
      IndexSearcher searcher = new IndexSearcher(reader);
      assertThat(searcher.count(new TermQuery(new Term("body", "secretterm3")))).isEqualTo(50);
      assertThat(searcher.count(new TermQuery(new Term("id", "doc42")))).isEqualTo(1);
    }
    PlaintextScan.assertNoMarkers(dir, "secretterm", "ordinary", "doc42", "body");
  }

  private byte[] readAll(String name) throws IOException {
    try (IndexInput in = directory.openInput(name, IOContext.DEFAULT)) {
      byte[] data = new byte[(int) in.length()];
      in.readBytes(data, 0, data.length);
      return data;
    }
  }
}
