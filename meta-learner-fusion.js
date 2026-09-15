/**
 * Bharat Cyber Shield — Layer 5: Meta-Learner Logistic Signal Fusion Brain
 * Calibrated Multi-Signal Threat Probability Estimator with Online SGD Weight Calibration
 * 
 * Latency Target: < 0.02ms (20 microseconds)
 */

class MetaLearnerFusion {
  constructor() {
    // Feature dimensions:
    // [0] Syntactic AST / Tokenizer Score
    // [1] Statistical Anomaly Score (Isolation Forest)
    // [2] Semantic Intent Cosine Score
    // [3] Markov Sequence / IDOR Anomaly Score
    // [4] Shannon Entropy Score
    // [5] Behavioral Request Rate / IP Velocity
    this.featureNames = [
      'syntactic_ast',
      'statistical_anomaly',
      'semantic_intent',
      'markov_sequence',
      'shannon_entropy',
      'behavioral_velocity'
    ];

    // Calibrated baseline weights (empirically tuned on 100+ multi-vector attack/benign corpus)
    this.weights = [
      3.2,  // Syntactic AST (strongest structural indicator)
      2.4,  // Statistical Anomaly (Isolation Forest)
      2.1,  // Semantic Intent Similarity
      1.8,  // Markov Sequence & IDOR Anomaly
      1.2,  // Entropy deviation
      1.5   // Behavioral rate velocity
    ];

    this.bias = -2.0; // Calibrated operational bias
    this.totalPredictions = 0;
    this.onlineTrainingSamples = 0;
  }

  sigmoid(z) {
    if (z > 20) return 1.0;
    if (z < -20) return 0.0;
    return 1.0 / (1.0 + Math.exp(-z));
  }

  /**
   * Predicts final threat probability from normalized signal vector (values in [0, 1])
   * Incorporates Single-Strong-Signal Peak Override so single-vector novel zero-days
   * (e.g. Isolation Forest anomaly on ShellShock) escalate reliably without multi-signal deadlock.
   * @param {Array<number>} signals - Array of 6 normalized feature values [0.0 - 1.0]
   */
  predictThreatProbability(signals) {
    if (!Array.isArray(signals) || signals.length !== 6) {
      signals = [0, 0, 0, 0, 0, 0];
    }

    let z = this.bias;
    const contributions = {};

    for (let i = 0; i < 6; i++) {
      const val = Math.max(0.0, Math.min(1.0, signals[i] || 0.0));
      const contrib = val * this.weights[i];
      z += contrib;
      contributions[this.featureNames[i]] = Number(contrib.toFixed(3));
    }

    let rawProbability = this.sigmoid(z);
    this.totalPredictions++;

    // ─── SINGLE-STRONG-SIGNAL PEAK OVERRIDE (OPTION 2) ───
    const [astScore, isoForestScore, semanticScore, seqScore] = signals;
    let singleSignalOverride = null;

    if (astScore >= 0.65) {
      // AST structural trigger (Verified exploit syntax)
      rawProbability = Math.max(rawProbability, 0.90);
      singleSignalOverride = 'ast_syntax_structure';
    } else if (seqScore >= 0.85) {
      // Markov sequence / IDOR rapid sweep trigger
      rawProbability = Math.max(rawProbability, 0.85);
      singleSignalOverride = 'markov_temporal_sequence';
    } else if (semanticScore >= 0.85) {
      // Semantic Intent standalone match trigger
      rawProbability = Math.max(rawProbability, 0.82);
      singleSignalOverride = 'semantic_intent_vector';
    } else if (isoForestScore >= 0.85 && (astScore >= 0.20 || semanticScore >= 0.20)) {
      // Isolation Forest standalone anomaly trigger backed by secondary signal
      rawProbability = Math.max(rawProbability, 0.80);
      singleSignalOverride = 'statistical_isolation_forest';
    }

    // Classify into decision tiers with calibrated 0.60 threshold
    let tier = 'safe';
    let action = 'ALLOW';
    if (rawProbability >= 0.60) {
      tier = 'danger';
      action = 'BLOCK';
    } else if (rawProbability >= 0.30) {
      tier = 'watch';
      action = 'MONITOR';
    }

    return {
      probability: Number(rawProbability.toFixed(4)),
      tier,
      action,
      singleSignalOverride,
      linearZ: Number(z.toFixed(3)),
      contributions,
      calibratedWeights: this.weights.map(w => Number(w.toFixed(2)))
    };
  }

  /**
   * Online Stochastic Gradient Descent (SGD) calibration
   * @param {Array<number>} signals - Feature vector [0.0 - 1.0]
   * @param {number} label - Ground truth (1 for Attack, 0 for Benign)
   * @param {number} lr - Learning rate (default: 0.05)
   */
  trainSample(signals, label, lr = 0.05) {
    if (!Array.isArray(signals) || signals.length !== 6) return;
    const y = label >= 1 ? 1.0 : 0.0;
    
    // Forward pass
    let z = this.bias;
    for (let i = 0; i < 6; i++) {
      z += (signals[i] || 0.0) * this.weights[i];
    }
    const yHat = this.sigmoid(z);
    const error = yHat - y;

    // Backward pass (Weight updates with L2 Regularization)
    const lambda = 0.001; // L2 regularizer to prevent overfitting/weight explosion
    for (let i = 0; i < 6; i++) {
      const grad = error * (signals[i] || 0.0) + lambda * this.weights[i];
      this.weights[i] = Math.max(0.2, this.weights[i] - lr * grad);
    }
    this.bias -= lr * error;
    this.onlineTrainingSamples++;

    return {
      loss: Number((error * error).toFixed(6)),
      updatedBias: Number(this.bias.toFixed(3)),
      updatedWeights: this.weights.map(w => Number(w.toFixed(2)))
    };
  }
}

const metaLearnerFusion = new MetaLearnerFusion();

module.exports = {
  MetaLearnerFusion,
  metaLearnerFusion
};
