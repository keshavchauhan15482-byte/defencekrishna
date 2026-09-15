/**
 * Bharat Cyber Shield — Layer 1: Statistical Anomaly Detection Engine
 * High-Performance Pure JavaScript Isolation Forest & Statistical Deviation Engine
 * 
 * Extracts multi-dimensional structural & statistical features from raw input payloads
 * and computes isolation depth across an ensemble of randomized decision trees.
 * Latency Target: < 0.10ms (100 microseconds)
 */

class IsolationTreeNode {
  constructor(feature = null, splitValue = null, left = null, right = null, size = 0) {
    this.feature = feature;
    this.splitValue = splitValue;
    this.left = left;
    this.right = right;
    this.size = size;
  }
}

class IsolationTree {
  constructor(maxHeight) {
    this.maxHeight = maxHeight;
    this.root = null;
  }

  fit(data, currentHeight = 0) {
    const numRows = data.length;
    if (currentHeight >= this.maxHeight || numRows <= 1) {
      return new IsolationTreeNode(null, null, null, null, numRows);
    }

    const numFeatures = data[0].length;
    const randomFeature = Math.floor(Math.random() * numFeatures);

    let min = Infinity;
    let max = -Infinity;
    for (let i = 0; i < numRows; i++) {
      const val = data[i][randomFeature];
      if (val < min) min = val;
      if (val > max) max = val;
    }

    if (min === max) {
      return new IsolationTreeNode(null, null, null, null, numRows);
    }

    const splitValue = min + Math.random() * (max - min);
    const leftData = [];
    const rightData = [];

    for (let i = 0; i < numRows; i++) {
      if (data[i][randomFeature] < splitValue) {
        leftData.push(data[i]);
      } else {
        rightData.push(data[i]);
      }
    }

    const leftNode = this.fit(leftData, currentHeight + 1);
    const rightNode = this.fit(rightData, currentHeight + 1);

    return new IsolationTreeNode(randomFeature, splitValue, leftNode, rightNode, numRows);
  }

  pathLength(vector, node = this.root, currentHeight = 0) {
    if (!node || (!node.left && !node.right)) {
      const size = node ? node.size : 1;
      return currentHeight + IsolationTree.c(size);
    }

    if (vector[node.feature] < node.splitValue) {
      return this.pathLength(vector, node.left, currentHeight + 1);
    } else {
      return this.pathLength(vector, node.right, currentHeight + 1);
    }
  }

  static c(n) {
    if (n <= 1) return 0;
    if (n === 2) return 1;
    // Harmonic approximation for average depth: 2*(ln(n-1) + 0.5772156649) - (2*(n-1)/n)
    return 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n);
  }
}

class StatisticalAnomalyDetector {
  constructor(numTrees = 25, subSampleSize = 64) {
    this.numTrees = numTrees;
    this.subSampleSize = subSampleSize;
    this.maxHeight = Math.ceil(Math.log2(Math.max(subSampleSize, 2)));
    this.trees = [];
    this.baselineFitted = false;
    this.trainBaselineModel();
  }

  /**
   * Extract 8 high-dimensional statistical & structural metrics from input string
   */
  extractFeatures(input) {
    let raw = String(input || '');
    if (raw.length === 0) return [0, 0, 0, 0, 0, 0, 0, 0];

    // Normalize JSON envelopes so field names & punctuation don't artificially inflate symbol ratio
    const text = raw.replace(/[\[\]\{\}\"\:\,]/g, ' ').replace(/\s+/g, ' ').trim();
    const len = Math.max(text.length, 1);

    // 1. Shannon Entropy
    const freqs = {};
    for (let i = 0; i < len; i++) {
      const c = text[i];
      freqs[c] = (freqs[c] || 0) + 1;
    }
    let entropy = 0;
    for (const char in freqs) {
      const p = freqs[char] / len;
      entropy -= p * Math.log2(p);
    }

    // 2. Exploit / Scripting Syntax Symbols Ratio (; | ` $ < > { } ^ ~ * % [ ] = + \)
    const symbols = (text.match(/[;|\`\$<>{}^~*%\[\]=+\\]/g) || []).length;
    const symbolRatio = symbols / len;

    // 3. Hex & Unicode Encoding Density
    const hexUnicode = (raw.match(/%[0-9a-fA-F]{2}|0x[0-9a-fA-F]+|\\u[0-9a-fA-F]{4}/g) || []).length;
    const hexDensity = hexUnicode / len;

    // 4. Nesting / Delimiter Depth (Parentheses, Angle brackets)
    let openDelims = 0;
    let maxNesting = 0;
    for (let i = 0; i < raw.length; i++) {
      const c = raw[i];
      if (c === '(' || c === '<') {
        openDelims++;
        if (openDelims > maxNesting) maxNesting = openDelims;
      } else if (c === ')' || c === '>') {
        if (openDelims > 0) openDelims--;
      }
    }
    // Semicolon-chaining ko separately count karo (matching-close-nahi-hota, isliye
    // yeh proper "nesting" nahi hai — sirf command-chaining ka signal hai, alag-track-karo)
    const semicolonChainCount = (raw.match(/;/g) || []).length;
    if (semicolonChainCount >= 3) {
      maxNesting = Math.max(maxNesting, 2); // 3+ semicolons = genuinely-suspicious command-chaining
    }

    // 5. Contiguous Operator / Punctuation Clustering (>= 3 contiguous code injection operators like ;--, /**/, &&, ||, )(|()
    const codePunctuation = text.replace(/https?:\/\//gi, ' ').replace(/\*\/\*/g, ' ').replace(/application\/[a-z0-9+-]+/gi, ' ');
    const clusters = codePunctuation.match(/[;|\`\$<>{}^~*%\[\]=+\\]{3,}/g) || [];
    const maxClusterLen = clusters.reduce((max, cl) => Math.max(max, cl.length), 0);

    // 6. Digit to Alphanumeric Ratio
    const digits = (text.match(/[\p{N}]/gu) || []).length;
    const digitRatio = digits / len;

    // 7. Whitespace and Control Character Density
    const whitespaces = (raw.match(/[\s\t\r\n\0\b]/g) || []).length;
    const whitespaceRatio = whitespaces / len;

    // 8. Normalized Length Indicator (log-scaled)
    const normalizedLength = Math.min(10, Math.log1p(len));

    return [
      entropy,            // [0] Shannon entropy
      symbolRatio,        // [1] Exploit Syntax Symbol ratio
      hexDensity,         // [2] Hex / URL encode density
      maxNesting,         // [3] Max parenthesis/operator depth
      maxClusterLen,      // [4] Punctuation cluster run length
      digitRatio,         // [5] Digit density
      whitespaceRatio,    // [6] Whitespace / control char density
      normalizedLength    // [7] Log-normalized string length
    ];
  }

  /**
   * Initializes and trains Isolation Forest with robust benign seed traffic baseline
   */
  trainBaselineModel() {
    const benignCorpus = [
      '/products {} {} /products Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0',
      '/products {"category":"books"} {} /products curl/8.5.0 */*',
      '/ {} {} / Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      '/checkout {"items":[{"id":"prod_1","qty":2}],"total":1499} /checkout Mozilla/5.0',
      '/login {"username":"john_doe","password":"SecurePassword123!"} /login Mozilla/5.0',
      'Laptop M3 Pro 16-inch 512GB SSD Space Gray',
      'Wireless Noise Cancelling Headphones Black Over Ear',
      'Gaming Monitor 27-inch 144Hz IPS Panel HDR 400',
      'Smart Watch Series 9 GPS Aluminum Case Sport Band',
      'Mechanical Keyboard RGB Backlit Brown Switch USB-C',
      'Ultra-thin Cotton T-Shirt Navy Blue Size L 100% Organic',
      'Organic Green Tea 100 Tea Bags Pack with Jasmine Flavor',
      'Stainless Steel Water Bottle 1000ml Double Wall Vacuum Insulated',
      'Ergonomic Office Chair with Lumbar Support High Back Mesh',
      'USB-C Fast Charger 65W Power Delivery 3-Port Wall Adapter',
      'customer.support@enterprise.co.in',
      'john.doe.personal@gmail.com',
      'P@ssw0rd2026#Secure!Alpha',
      'Tr0ub4dor&3!Xk#99',
      'kX9#mP2$vL8&qR@2026',
      'New Delhi, Connaught Place, Inner Circle Block B, Pin 110001',
      'Mumbai, Bandra West, Hill Road Near Police Station, 400050',
      'Bangalore, Indiranagar, 100ft Road Opposite Metro Pillar 42',
      'Discount coupon SAVE20-SUMMER-SPECIAL',
      'Product review: 5/5 stars -- would definitely buy again! It is great & works perfectly.',
      'Great product!! 5/5 stars -- would buy again & recommend to friends...',
      'Customer question: Does this item ship with warranty card and power cable?',
      '{"item_id": 1042, "quantity": 2, "shipping": "standard", "gift_wrap": true}',
      '{"search_query": "budget smartphone under 15000 with 5G", "page": 1, "sort": "rating"}'
    ];

    const featureMatrix = benignCorpus.map(text => this.extractFeatures(text));

    // Train Forest Trees
    this.trees = [];
    for (let i = 0; i < this.numTrees; i++) {
      const tree = new IsolationTree(this.maxHeight);
      // Sample subset
      const sample = [];
      for (let s = 0; s < Math.min(this.subSampleSize, featureMatrix.length); s++) {
        const idx = Math.floor(Math.random() * featureMatrix.length);
        sample.push(featureMatrix[idx]);
      }
      tree.root = tree.fit(sample);
      this.trees.push(tree);
    }
    this.baselineFitted = true;
  }

  /**
   * Evaluates input payload and computes statistical anomaly score (0.00 to 1.00)
   */
  computeAnomalyScore(input) {
    if (!input || String(input).trim() === '') return { score: 0.0, isAnomaly: false, features: [] };

    const vector = this.extractFeatures(input);
    const n = this.subSampleSize;
    const cN = IsolationTree.c(n);

    let totalPathLength = 0;
    for (let i = 0; i < this.trees.length; i++) {
      totalPathLength += this.trees[i].pathLength(vector);
    }
    const avgPathLength = totalPathLength / this.trees.length;

    // Isolation score formula: s(x, n) = 2 ^ ( - E(h(x)) / c(n) )
    const rawScore = Math.pow(2, - (avgPathLength / Math.max(cN, 1)));

    // Normalize so that average benign traffic (rawScore ~0.50) maps to < 0.20,
    // and isolated anomalies (rawScore > 0.65) map to > 0.70
    let adjustedScore = Math.max(0.0, (rawScore - 0.45) * 1.6);
    const [entropy, symbolRatio, hexDensity, maxNesting, maxClusterLen] = vector;

    if ((symbolRatio > 0.15 && entropy > 4.4) || hexDensity > 0.05 || maxClusterLen >= 2 || maxNesting >= 2 || (symbolRatio > 0.25 && maxClusterLen >= 1)) {
      adjustedScore = Math.min(1.0, adjustedScore + 0.40);
    } else if (symbolRatio < 0.10 && hexDensity === 0 && maxClusterLen === 0 && maxNesting <= 1) {
      adjustedScore = Math.max(0.0, adjustedScore - 0.30);
    }

    const normalizedScore = Number(Math.max(0.0, Math.min(1.0, adjustedScore)).toFixed(4));
    const isAnomaly = normalizedScore >= 0.65;

    return {
      score: normalizedScore,
      isAnomaly,
      features: {
        entropy: Number(entropy.toFixed(2)),
        symbolRatio: Number(symbolRatio.toFixed(3)),
        hexDensity: Number(hexDensity.toFixed(3)),
        maxNesting,
        maxClusterLen
      }
    };
  }
}

const anomalyDetector = new StatisticalAnomalyDetector();

module.exports = {
  StatisticalAnomalyDetector,
  anomalyDetector
};
