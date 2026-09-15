import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import numpy as np
from garuda_v3.model import GraphWorldModel
from garuda_v3.v10_experiment import state_objective,fit_one,CONFIG
from garuda_v3.inference import ForecastService
from garuda_v3.state_evaluation import state_evidence


class V10Tests(unittest.TestCase):
    def test_tiny_holdout_cannot_produce_zero_width_confidence(self):
        target=np.ones((8,4,21));prediction=target*.9;base=target*.5
        r=state_evidence(prediction,target,base)
        self.assertEqual(r['paired_block_bootstrap_95pct'],[None,None])
        self.assertEqual(r['bootstrap_status'],'insufficient_examples_for_two_blocks')

    def arrays(self):
        x=np.full((2,8,2,21),.3,dtype=np.float32)
        adj=np.zeros((2,8,2,2),dtype=np.float32);mask=np.ones((2,8,2),dtype=np.float32)
        target=np.full((2,4,21),.5,dtype=np.float32)
        return (x,adj,mask,target,np.full((2,4),-1),np.ones(2))

    def test_state_learning_independent_of_risk_labels(self):
        arrays=self.arrays();model=GraphWorldModel(decoder='residual')
        a=state_objective(model,arrays);a.backward()
        self.assertIsNone(model.params['risk'].grad)
        self.assertGreater(np.abs(model.params['mean'].grad).sum(),0)
        altered=list(arrays);altered[4]=np.ones((2,4))
        self.assertEqual(float(a.data),float(state_objective(model,altered).data))

    def test_persistence_checkpoint_can_win(self):
        arrays=list(self.arrays());arrays[3][:]=.3
        with patch.dict(CONFIG,epochs=2,patience=2):
            model,result=fit_one(arrays,arrays,'gnn_lstm',42,'state_only')
        self.assertEqual(result['best_epoch'],0)
        self.assertEqual(result['selection_value'],0)

    def test_state_checkpoint_cannot_emit_attack_scores(self):
        with tempfile.TemporaryDirectory() as tmp:
            GraphWorldModel().save(Path(tmp)/'gnn_lstm.npz',dict(risk_output_permitted=False))
            with self.assertRaisesRegex(ValueError,'State-only checkpoint'):
                ForecastService(tmp)


if __name__=='__main__':unittest.main()
