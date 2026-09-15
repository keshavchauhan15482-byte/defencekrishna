/**
 * Bharat Cyber Shield — Layer 2: Semantic Intent Vectorizer & Distance Engine
 * Token & 3-Gram TF-IDF Vectorizer with Cosine Distance against Malicious Intent Centroids
 * 
 * Latency Target: < 0.15ms
 */

class SemanticFeatureExtractor {
  constructor() {
    this.intentCorpus = {
      sql_exfiltration: [
        'union select null password admin credentials schema tables column',
        'or boolean true 1=1 2>1 sleep waitfor delay benchmark information_schema',
        'drop table truncate insert into load_file into outfile concat version'
      ],
      command_execution: [
        'cat etc passwd bin sh bash curl wget nc powershell cmd exec system spawn',
        'sudo rm rf chmod 777 netcat reverse shell eval eval base64 decode',
        'jndi ldap rmi dns classloader runtime getruntime exec env export'
      ],
      cloud_metadata_ssrf: [
        '169.254.169.254 latest meta-data security-credentials iam instance-identity',
        'metadata.google.internal computeMetadata v1 instance service-accounts token',
        '127.0.0.1 0.0.0.0 localhost internal admin status debug actuate'
      ],
      path_traversal: [
        'dot dot slash etc passwd etc shadow boot.ini win.ini proc self environ',
        'windows system32 drivers etc hosts appsettings json web config'
      ],
      prototype_pollution: [
        'constructor prototype __proto__ isAdmin isAuthorized role admin root',
        'pollute object Object.prototype __defineGetter__ hasOwnProperty',
        'class module classloader resources context parent pipeline getclassloader'
      ]
    };

    this.centroids = {};
    this.buildCentroids();
  }

  /**
   * Tokenizes text into word-tokens and character 3-grams
   */
  tokenize(text) {
    const clean = String(text || '').toLowerCase().replace(/[^a-z0-9_$/.-]/g, ' ');
    const words = clean.split(/\s+/).filter(w => w.length >= 2);

    // Generate 3-grams
    const grams = [];
    const compact = clean.replace(/\s+/g, '');
    for (let i = 0; i <= compact.length - 3; i++) {
      grams.push(compact.substring(i, i + 3));
    }

    return { words, grams };
  }

  /**
   * Builds term frequency vector from tokens and n-grams
   */
  buildVector(tokens) {
    const vec = new Map();
    // Words count with 5x weight for semantic clarity
    for (const w of tokens.words) {
      vec.set(w, (vec.get(w) || 0) + 5.0);
    }
    // 3-grams count with 1x weight for fuzzy sub-token matching
    for (const g of tokens.grams) {
      vec.set(g, (vec.get(g) || 0) + 1.0);
    }
    return vec;
  }

  /**
   * Computes normalized cosine similarity between two sparse vector maps
   */
  cosineSimilarity(vecA, vecB) {
    let dot = 0;
    let normA = 0;
    let normB = 0;

    for (const [k, v] of vecA.entries()) {
      normA += v * v;
      if (vecB.has(k)) {
        dot += v * vecB.get(k);
      }
    }

    for (const [, v] of vecB.entries()) {
      normB += v * v;
    }

    if (normA === 0 || normB === 0) return 0;
    
    // Coverage of query terms matched against intent centroid
    const coverage = dot / normA;
    const cosine = dot / (Math.sqrt(normA) * Math.sqrt(normB));

    // Hybrid relevance metric: 70% query term coverage + 30% cosine alignment
    return Math.min(1.0, 0.70 * coverage + 0.30 * (cosine * 2.5));
  }

  buildCentroids() {
    for (const [intentName, sentences] of Object.entries(this.intentCorpus)) {
      const combinedText = sentences.join(' ');
      const tokens = this.tokenize(combinedText);
      this.centroids[intentName] = this.buildVector(tokens);
    }
  }

  /**
   * Computes semantic similarity score (0.00 to 1.00) against all malicious intent domains
   */
  computeSemanticScore(input) {
    if (!input || String(input).trim() === '') {
      return { score: 0.0, dominantIntent: 'none', intentScores: {} };
    }

    const inputTokens = this.tokenize(input);
    const inputVec = this.buildVector(inputTokens);

    let maxSim = 0;
    let dominant = 'none';
    const scores = {};

    for (const [intentName, centroidVec] of Object.entries(this.centroids)) {
      const sim = this.cosineSimilarity(inputVec, centroidVec);
      scores[intentName] = Number(sim.toFixed(4));
      if (sim > maxSim) {
        maxSim = sim;
        dominant = intentName;
      }
    }

    return {
      score: Number(maxSim.toFixed(4)),
      dominantIntent: dominant,
      intentScores: scores
    };
  }
}

const semanticExtractor = new SemanticFeatureExtractor();

module.exports = {
  SemanticFeatureExtractor,
  semanticExtractor
};
