package org.shem.extract;

import java.io.DataInputStream;
import java.io.DataOutputStream;

/** A test worker that completes the handshake and then never answers a request. */
public final class HangingWorker {
  private HangingWorker() {}

  public static void main(String[] args) throws Exception {
    DataInputStream in = new DataInputStream(System.in);
    DataOutputStream out = new DataOutputStream(System.out);
    Protocol.expectMagic(in);
    in.readInt();
    Protocol.readString(in);
    String scratch = Protocol.readString(in);
    out.writeInt(Protocol.MAGIC);
    out.writeBoolean(false);
    out.writeBoolean(false);
    Protocol.writeString(out, scratch);
    out.writeBoolean(true);
    out.flush();
    in.readByte();
    Thread.sleep(Long.MAX_VALUE);
  }
}
