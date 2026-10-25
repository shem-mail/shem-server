package org.shem.search;

import java.util.Iterator;
import java.util.Set;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;

/** Emits a precomputed set of terms as tokens (no analysis). */
final class GramTokenStream extends TokenStream {
  private final Set<String> grams;
  private final CharTermAttribute term = addAttribute(CharTermAttribute.class);
  private Iterator<String> iterator;

  GramTokenStream(Set<String> grams) {
    this.grams = grams;
    this.iterator = grams.iterator();
  }

  @Override
  public boolean incrementToken() {
    clearAttributes();
    if (!iterator.hasNext()) {
      return false;
    }
    term.setEmpty().append(iterator.next());
    return true;
  }

  @Override
  public void reset() {
    iterator = grams.iterator();
  }
}
