/**
 * Encrypted per-mailbox search index (PLAN step 9): an authenticated encrypted Lucene {@code
 * Directory} and a trigram index used only as a conservative candidate filter in front of exact
 * SEARCH evaluation. See docs/adr/0008-search-index.md.
 */
@NullMarked
package org.shem.search;

import org.jspecify.annotations.NullMarked;
