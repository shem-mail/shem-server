package org.shem.policy;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Baseline dangerous-attachment detection by file name and declared type: executable and script
 * extensions, macro-enabled Office formats, and double extensions that hide one. It inspects
 * neither archives nor file contents and is not antivirus (ADR 0010).
 */
final class AttachmentCheck {
  static final Set<String> DANGEROUS =
      Set.of(
          "exe",
          "com",
          "scr",
          "pif",
          "bat",
          "cmd",
          "cpl",
          "msi",
          "msp",
          "msc",
          "dll",
          "jar",
          "js",
          "jse",
          "vbs",
          "vbe",
          "wsf",
          "wsh",
          "hta",
          "ps1",
          "psm1",
          "lnk",
          "reg",
          "scf",
          "inf",
          "application",
          "gadget",
          "appx",
          "msix",
          "iso",
          "img",
          "vhd",
          "vhdx",
          "docm",
          "dotm",
          "xlsm",
          "xltm",
          "xlam",
          "pptm",
          "potm",
          "ppam",
          "sldm");
  static final Set<String> DANGEROUS_TYPES =
      Set.of(
          "application/x-msdownload",
          "application/x-dosexec",
          "application/x-msdos-program",
          "application/x-ms-installer",
          "application/vnd.ms-word.document.macroenabled.12",
          "application/vnd.ms-excel.sheet.macroenabled.12",
          "application/vnd.ms-powerpoint.presentation.macroenabled.12");

  private AttachmentCheck() {}

  /** Reason codes for the dangerous attachments found (safe to log and to record). */
  static List<String> findings(List<MessageScan.Attachment> attachments) {
    List<String> findings = new ArrayList<>();
    for (MessageScan.Attachment attachment : attachments) {
      String name = attachment.fileName().toLowerCase(Locale.ROOT).strip();
      // Trailing dots and spaces are ignored by Windows and used to disguise extensions.
      while (name.endsWith(".") || name.endsWith(" ")) {
        name = name.substring(0, name.length() - 1);
      }
      int dot = name.lastIndexOf('.');
      String extension = dot < 0 ? "" : name.substring(dot + 1);
      if (DANGEROUS.contains(extension)) {
        boolean hidden = name.lastIndexOf('.', dot - 1) > 0;
        findings.add(hidden ? "double-extension" : "dangerous-extension");
      } else if (DANGEROUS_TYPES.contains(attachment.mimeType())) {
        findings.add("dangerous-type");
      }
    }
    return findings;
  }
}
