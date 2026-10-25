/**
 * Encrypted mailbox storage. Every byte written below a mailbox directory is ciphertext or a public
 * format/structure identifier; no folder names, flags, addresses, or content appear in file names
 * or plaintext headers.
 */
@NullMarked
package org.shem.store;

import org.jspecify.annotations.NullMarked;
