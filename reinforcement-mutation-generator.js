/**
 * Bharat Cyber Shield — Layer 4: Reinforcement-Weighted Mutation Generator
 * Adaptive Adversarial Variant Generator with Dynamic Technique Reward & Penalty Calibration
 * 
 * Latency Target: < 0.10ms
 */

class ReinforcementMutationGenerator {
  constructor() {
    this.techniqueWeights = {
      case_alternation: 1.0,
      sql_comment_split: 1.2,
      whitespace_substitute: 1.1,
      null_byte_wrap: 0.9,
      hex_encoding_wrap: 1.0,
      unicode_homoglyph: 1.15,
      semantic_tautology_morph: 1.25,
      ifs_shell_delimiter: 1.05,
      double_url_encode: 1.0,
      proto_unicode_escape: 1.1
    };

    this.techniqueStats = {};
    for (const k of Object.keys(this.techniqueWeights)) {
      this.techniqueStats[k] = { used: 0, confirmedDefenses: 0 };
    }

    this.operators = {
      case_alternation: (token) => {
        return token.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join('');
      },
      sql_comment_split: (token) => {
        if (token.length < 4) return token;
        const mid = Math.floor(token.length / 2);
        return token.substring(0, mid) + '/**/' + token.substring(mid);
      },
      whitespace_substitute: (token) => {
        return token.replace(/\s+/g, '%09').replace(/=/g, '%20=%20');
      },
      null_byte_wrap: (token) => {
        return token + '%00';
      },
      hex_encoding_wrap: (token) => {
        const hex = Buffer.from(token.substring(0, Math.min(10, token.length))).toString('hex');
        return '0x' + hex;
      },
      unicode_homoglyph: (token) => {
        const homoglyphs = { 'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р', 'c': 'с', 'x': 'х', 's': 'ѕ' };
        return token.split('').map(c => homoglyphs[c] || c).join('');
      },
      semantic_tautology_morph: (token) => {
        if (/or\s+1=1/i.test(token)) {
          return token.replace(/or\s+1=1/gi, 'OR 2>1');
        }
        if (/or\s+'1'='1'/i.test(token)) {
          return token.replace(/or\s+'1'='1'/gi, "OR 'a'='a'");
        }
        return token + " OR 'xyz'='xyz'";
      },
      ifs_shell_delimiter: (token) => {
        return token.replace(/\s+/g, '${IFS}');
      },
      double_url_encode: (token) => {
        return token.replace(/%/g, '%25').replace(/'/g, '%2527');
      },
      proto_unicode_escape: (token) => {
        return token.replace(/__proto__/gi, '__\\u0070roto__').replace(/prototype/gi, 'proto\\u0074ype');
      }
    };
  }

  /**
   * Weighted random selection of mutation techniques
   */
  selectTechniques(count = 5) {
    const techniques = Object.keys(this.operators);
    const weights = techniques.map(t => Math.max(0.1, this.techniqueWeights[t]));
    const totalWeight = weights.reduce((a, b) => a + b, 0);

    const chosen = new Set();
    let attempts = 0;
    while (chosen.size < Math.min(count, techniques.length) && attempts < 50) {
      attempts++;
      let rand = Math.random() * totalWeight;
      for (let i = 0; i < techniques.length; i++) {
        rand -= weights[i];
        if (rand <= 0) {
          chosen.add(techniques[i]);
          break;
        }
      }
    }
    return Array.from(chosen);
  }

  /**
   * Generates prioritized synthetic mutations from root seed token
   */
  generateMutations(seedToken, count = 5) {
    if (!seedToken || typeof seedToken !== 'string') return [];
    const selected = this.selectTechniques(count);
    const mutations = [];

    for (const tech of selected) {
      try {
        const mutated = this.operators[tech](seedToken);
        if (mutated && mutated !== seedToken) {
          mutations.push({
            token: mutated,
            technique: tech,
            weight: Number(this.techniqueWeights[tech].toFixed(3))
          });
          this.techniqueStats[tech].used++;
        }
      } catch (e) {}
    }

    return mutations;
  }

  /**
   * Reinforcement Feedback Loop: Updates weights based on confirmed threat interception
   */
  recordFeedback(technique, wasConfirmedAttack = true) {
    if (!this.techniqueWeights[technique]) return;

    if (wasConfirmedAttack) {
      // Reward effective technique (+15% weight)
      this.techniqueWeights[technique] = Math.min(5.0, this.techniqueWeights[technique] * 1.15);
      this.techniqueStats[technique].confirmedDefenses++;
    } else {
      // Penalize false-positive or ineffective technique (-5% weight)
      this.techniqueWeights[technique] = Math.max(0.2, this.techniqueWeights[technique] * 0.95);
    }
  }

  getTechniqueRankings() {
    return Object.entries(this.techniqueWeights)
      .map(([tech, weight]) => ({
        technique: tech,
        weight: Number(weight.toFixed(3)),
        stats: this.techniqueStats[tech]
      }))
      .sort((a, b) => b.weight - a.weight);
  }
}

const reinforcementMutationGenerator = new ReinforcementMutationGenerator();

module.exports = {
  ReinforcementMutationGenerator,
  reinforcementMutationGenerator
};
