/**
 * NTRO SIH26153: AI Garuda AI for Network Attack Forecasting Engine
 * Pure neural network inference of the trained Gated LSTM Sequence Garuda AI.
 * Ingests trained 4-Gate LSTM weights from trained_world_model_weights.json.
 */

const fs = require('fs');
const path = require('path');

class NetworkWorldModel {
  constructor() {
    this.K_STEPS = 8;
    this.FEATURE_NAMES = [
      'TCP SYN/ACK Ratio Imbalance', 'FIN/RST Flag Anomalies', 'Mean Inter-Arrival Time (IAT)',
      'Inter-Arrival Time (IAT) Jitter', 'Payload Bytes Per Flow', 'Packet Count Per Flow',
      'Mean IP Time-To-Live (TTL)', 'TTL Variance (Lateral Subnet Hops)', 'TCP Window Size',
      'Port Scan Sequence Entropy', 'IP Fragmentation Flag', 'TCP Retransmission Ratio'
    ];

    let weightsPath = path.join(__dirname, 'trained_world_model_weights.json');
    if (!fs.existsSync(weightsPath)) {
      weightsPath = path.join(__dirname, 'ntro-world-model', 'trained_world_model_weights.json');
    }

    try {
      this.weights = JSON.parse(fs.readFileSync(weightsPath, 'utf8'));
      this.inputDim = this.weights.input_dim;
      this.hiddenDim = this.weights.hidden_dim;
    } catch (e) {
      console.warn('[WORLD MODEL] Weight loading error:', e.message);
      this.weights = null;
    }

    this.baselineRef = [0.05, 0.02, 0.06, 0.02, 0.10, 0.15, 0.64, 0.02, 0.98, 0.05, 0.0, 0.01];

    this.benchmarkMetrics = {
      validationStatus: 'unverified_legacy_metrics_withdrawn',
      worldModel: { f1: null, precision: null, recall: null, fpr: null, leadTimeSec: null },
      logisticRegression: { f1: null, precision: null, recall: null, fpr: null, leadTimeSec: null }
    };
  }

  _sigmoid(x) {
    const clamped = Math.max(-15.0, Math.min(15.0, x));
    return 1.0 / (1.0 + Math.exp(-clamped));
  }

  _tanh(x) {
    return Math.tanh(x);
  }

  step(xt, hPrev, cPrev) {
    if (!this.weights) {
      return { hNext: new Array(16).fill(0), cNext: new Array(16).fill(0), sPred: xt, prob: 0.05 };
    }

    const hNext = [];
    const cNext = [];

    for (let j = 0; j < this.hiddenDim; j++) {
      let actI = this.weights.b_i[j];
      let actF = this.weights.b_f[j];
      let actG = this.weights.b_g[j];
      let actO = this.weights.b_o[j];

      for (let k = 0; k < this.inputDim; k++) {
        actI += this.weights.W_xi[j][k] * (xt[k] || 0);
        actF += this.weights.W_xf[j][k] * (xt[k] || 0);
        actG += this.weights.W_xg[j][k] * (xt[k] || 0);
        actO += this.weights.W_xo[j][k] * (xt[k] || 0);
      }

      for (let k = 0; k < this.hiddenDim; k++) {
        actI += this.weights.W_hi[j][k] * (hPrev[k] || 0);
        actF += this.weights.W_hf[j][k] * (hPrev[k] || 0);
        actG += this.weights.W_hg[j][k] * (hPrev[k] || 0);
        actO += this.weights.W_ho[j][k] * (hPrev[k] || 0);
      }

      const iVal = this._sigmoid(actI);
      const fVal = this._sigmoid(actF);
      const gVal = this._tanh(actG);
      const oVal = this._sigmoid(actO);

      const cVal = fVal * (cPrev[j] || 0) + iVal * gVal;
      cNext.push(cVal);
      hNext.push(oVal * this._tanh(cVal));
    }

    const sPred = [];
    for (let i = 0; i < this.inputDim; i++) {
      let val = this.weights.b_dec[i];
      for (let j = 0; j < this.hiddenDim; j++) {
        val += this.weights.W_dec[i][j] * hNext[j];
      }
      sPred.push(Math.max(0, Math.min(1.0, val)));
    }

    let pAct = this.weights.b_risk;
    for (let j = 0; j < this.hiddenDim; j++) {
      pAct += this.weights.W_risk[j] * hNext[j];
    }
    const prob = this._sigmoid(pAct);

    return { hNext, cNext, sPred, prob };
  }

  forwardRollout(currentStateVector) {
    const trajectory = [];
    let currentX = [...currentStateVector];
    let h = new Array(this.hiddenDim || 16).fill(0);
    let c = new Array(this.hiddenDim || 16).fill(0);

    const step0 = this.step(currentX, h, c);
    h = step0.hNext;
    c = step0.cNext;
    const prob0 = step0.prob;

    trajectory.push({
      step: 0,
      relativeTime: '+0s (Current S_t)',
      infiltrationProb: Math.round(prob0 * 100),
      stage: this._mapToMitreStage(prob0),
      stateSnapshot: currentX.map(v => Number(v.toFixed(3))),
      threatLevel: prob0 > 0.7 ? 'CRITICAL' : (prob0 > 0.35 ? 'ELEVATED' : 'NOMINAL')
    });

    let sPred = step0.sPred;
    for (let k = 1; k <= this.K_STEPS; k++) {
      currentX = currentX.map((val, idx) => 0.55 * val + 0.45 * (sPred[idx] || val));
      const res = this.step(currentX, h, c);
      h = res.hNext;
      c = res.cNext;
      sPred = res.sPred;
      const probK = res.prob;

      trajectory.push({
        step: k,
        relativeTime: `+${k * 10}s`,
        infiltrationProb: Math.round(probK * 100),
        stage: this._mapToMitreStage(probK),
        stateSnapshot: sPred.map(v => Number(v.toFixed(3))),
        threatLevel: probK > 0.7 ? 'CRITICAL' : (probK > 0.35 ? 'ELEVATED' : 'NOMINAL')
      });
    }

    const peakRisk = Math.max(...trajectory.map(t => t.infiltrationProb));
    const isProactiveAlertTriggered = peakRisk >= 60;
    const finalStage = trajectory[trajectory.length - 1].stage;
    const shapWeights = this.computeShapAttribution(currentStateVector);

    return {
      timestamp: Date.now(),
      trajectory,
      peakInfiltrationProb: peakRisk,
      isProactiveAlertTriggered,
      predictedFinalStage: finalStage,
      recommendedInterventionTime: isProactiveAlertTriggered ? '+30s (Pre-Lateral Movement)' : 'N/A',
      shapAttribution: shapWeights,
      benchmark: this.benchmarkMetrics
    };
  }

  _mapToMitreStage(prob) {
    if (prob < 0.25) return 'Reconnaissance (T1595)';
    if (prob < 0.50) return 'Initial Access (T1190)';
    if (prob < 0.75) return 'Lateral Movement (T1021)';
    if (prob < 0.90) return 'Command & Control (T1071)';
    return 'Exfiltration / Impact (T1041)';
  }

  computeShapAttribution(stateVector) {
    const baseStep = this.step(stateVector, new Array(this.hiddenDim || 16).fill(0), new Array(this.hiddenDim || 16).fill(0));
    const baseProb = baseStep.prob;

    const rawWeights = [];
    for (let i = 0; i < stateVector.length; i++) {
      const perturbed = [...stateVector];
      perturbed[i] = this.baselineRef[i] || 0.05;
      const step = this.step(perturbed, new Array(this.hiddenDim || 16).fill(0), new Array(this.hiddenDim || 16).fill(0));
      const marginal = Math.max(0.0, baseProb - step.prob);
      rawWeights.push(marginal);
    }

    const total = rawWeights.reduce((acc, v) => acc + v, 0);
    const normalized = total > 1e-6 
      ? rawWeights.map(w => w / total) 
      : new Array(rawWeights.length).fill(1 / rawWeights.length);

    const attributions = this.FEATURE_NAMES.map((name, idx) => ({
      feature: name,
      weight: Number(normalized[idx].toFixed(4)),
      value: (stateVector[idx] * 100).toFixed(1) + '%'
    }));

    return attributions.sort((a, b) => b.weight - a.weight);
  }
}

const worldModel = new NetworkWorldModel();

module.exports = { NetworkWorldModel, worldModel };
