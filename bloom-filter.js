/**
 * Bloom Filter — the real, industry-standard technique for "have I seen
 * this before?" checks across large pattern sets with tiny memory use.
 * This is what Cloudflare, Google Safe Browsing, and malware-hash lookups
 * actually use for this exact problem — not a neural network (which would
 * be enormous overkill and dishonest to call this).
 *
 * How it's compact: instead of storing full strings and scanning through
 * them one by one, we store a fixed-size bit array (e.g. 8,000 bits =
 * 1KB) no matter how many patterns we learn. Each pattern sets a handful
 * of bits via hash functions. Checking "have I seen this?" is just
 * checking if those same bits are set — O(1), no matter how much has
 * been learned.
 *
 * Trade-off (must be honest about this): Bloom filters can have RARE
 * false positives (says "maybe seen" for something new) but NEVER false
 * negatives (if it says "definitely not seen," that's always correct).
 * For a security block-list, that trade-off is the right one — worst
 * case we double-check something that turns out to be fine.
 */

class BloomFilter {
  constructor(sizeBits = 8192, hashCount = 4) {
    this.sizeBits = sizeBits;
    this.hashCount = hashCount;
    this.bits = new Uint8Array(Math.ceil(sizeBits / 8)); // 1 byte per 8 bits — this is the entire storage
  }

  _hash(str, seed) {
    // FNV-1a variant, cheap and good enough for this use case
    let h = 0x811c9dc5 ^ seed;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return (h >>> 0) % this.sizeBits;
  }

  _setBit(pos) {
    this.bits[pos >> 3] |= (1 << (pos & 7));
  }

  _getBit(pos) {
    return (this.bits[pos >> 3] & (1 << (pos & 7))) !== 0;
  }

  add(str) {
    for (let i = 0; i < this.hashCount; i++) {
      this._setBit(this._hash(str, i * 2654435761));
    }
  }

  mightContain(str) {
    for (let i = 0; i < this.hashCount; i++) {
      if (!this._getBit(this._hash(str, i * 2654435761))) return false; // definitely not seen
    }
    return true; // maybe seen — needs exact confirmation
  }

  // for persistence — the ENTIRE learned-pattern memory compresses to this one string
  toBase64() {
    return Buffer.from(this.bits).toString('base64');
  }

  static fromBase64(b64, sizeBits, hashCount) {
    const filter = new BloomFilter(sizeBits, hashCount);
    if (b64) filter.bits = new Uint8Array(Buffer.from(b64, 'base64'));
    return filter;
  }

  sizeBytes() {
    return this.bits.length;
  }
}

module.exports = { BloomFilter };
