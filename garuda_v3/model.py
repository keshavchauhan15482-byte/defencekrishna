"""Trainable directed GraphSAGE -> graph pooling -> LSTM -> AR Gaussian/risk decoder.
NumPy reverse-mode differentiation keeps the reference implementation CPU/offline friendly.
No future graph, label, node identity or target is an input to forward().
"""
import json
from pathlib import Path
import numpy as np
from .autograd import Tensor, concat
from .data import FEATURES, SCHEMA

PS_COMPLETE_SCHEMA = 'garuda-observed-graph-v46-ps-complete'
RELATIVE_PS_COMPLETE_SCHEMA = 'garuda-observed-graph-v46-ps-complete-relative-v1'
SUPPORTED_SCHEMAS = {SCHEMA, PS_COMPLETE_SCHEMA, RELATIVE_PS_COMPLETE_SCHEMA}

class GraphWorldModel:
    def __init__(self, architecture='gnn_lstm', feature_dim=len(FEATURES), graph_dim=12, hidden=16, seed=42,
                 decoder='absolute', stage_count=0, schema=SCHEMA):
        if architecture not in ('gnn_lstm','lstm'): raise ValueError('Unknown architecture')
        if decoder not in ('absolute', 'residual'): raise ValueError('Unknown decoder')
        if stage_count not in (0, 5): raise ValueError('stage_count must be 0 or 5')
        if schema not in SUPPORTED_SCHEMAS: raise ValueError(f'Unsupported graph schema: {schema}')
        self.schema=schema
        self.config=dict(architecture=architecture,feature_dim=feature_dim,graph_dim=graph_dim,hidden=hidden,
                         seed=seed,decoder=decoder,stage_count=stage_count,schema=schema)
        self.decoder=decoder; self.stage_count=stage_count
        self.architecture=architecture; self.f=feature_dim; self.g=graph_dim; self.h=hidden
        self.params={}; rng=np.random.default_rng(seed)
        def weight(name,a,b): self.params[name]=Tensor(rng.normal(0,np.sqrt(2/(a+b)),(a,b)),requires_grad=True)
        def bias(name,n): self.params[name]=Tensor(np.zeros(n),requires_grad=True)
        if architecture=='gnn_lstm':
            for layer,a,b in ((1,feature_dim,graph_dim),(2,graph_dim,graph_dim)):
                for kind in ('self','in','out'): weight(f'g{layer}_{kind}',a,b)
                bias(f'g{layer}_b',b)
        input_dim=feature_dim+(graph_dim if architecture=='gnn_lstm' else 0)
        for name,dim in (('enc',input_dim),('dec',feature_dim)):
            weight(name+'_x',dim,4*hidden);weight(name+'_h',hidden,4*hidden);bias(name+'_b',4*hidden)
            self.params[name+'_b'].data[hidden:2*hidden]=1.
        weight('mean',hidden,feature_dim);bias('mean_b',feature_dim)
        weight('sigma',hidden,feature_dim);bias('sigma_b',feature_dim)
        weight('risk',hidden,1);bias('risk_b',1)
        if decoder=='residual': self.params['mean'].data[:]=0
        if stage_count: weight('stage',hidden,stage_count);bias('stage_b',stage_count)
    def parameters(self): return list(self.params.values())
    def cell(self,x,h,c,name):
        p=self.params; gate=x@p[name+'_x']+h@p[name+'_h']+p[name+'_b']
        i=gate[:,:self.h].sigmoid(); f=gate[:,self.h:2*self.h].sigmoid()
        g=gate[:,2*self.h:3*self.h].tanh(); o=gate[:,3*self.h:].sigmoid()
        c=f*c+i*g; return o*c.tanh(),c
    def forward(self,x,adj,mask,horizon=6,return_stages=False):
        x=Tensor.wrap(x); adj=np.asarray(adj,dtype=np.float32);mask=np.asarray(mask,dtype=np.float32)
        if x.data.shape[-1] != self.f: raise ValueError(f'Feature dimension mismatch: {x.data.shape[-1]} != {self.f}')
        b,t,n,_=x.data.shape
        denom=np.maximum(mask.sum(axis=2,keepdims=True),1)
        pooled=(x*mask[:,:,:,None]).sum(axis=2)/denom
        e=pooled
        if self.architecture=='gnn_lstm':
            incoming=adj/np.maximum(adj.sum(axis=-1,keepdims=True),1)
            outgoing=np.swapaxes(adj,-1,-2)
            outgoing=outgoing/np.maximum(outgoing.sum(axis=-1,keepdims=True),1)
            z=x
            for layer in (1,2):
                p=self.params
                z=(z@p[f'g{layer}_self']+(Tensor(incoming)@z)@p[f'g{layer}_in']+(Tensor(outgoing)@z)@p[f'g{layer}_out']+p[f'g{layer}_b']).relu()*mask[:,:,:,None]
            e=concat([pooled,z.sum(axis=2)/denom])
        h=Tensor(np.zeros((b,self.h)));c=Tensor(np.zeros((b,self.h)))
        for i in range(t): h,c=self.cell(e[:,i],h,c,'enc')
        current=pooled[:,-1]
        means=[];sigmas=[];risks=[];stages=[]
        for k in range(horizon):
            h,c=self.cell(current,h,c,'dec')
            innovation=h@self.params['mean']+self.params['mean_b']
            if self.decoder=='residual':
                proposed=current+.1*innovation.tanh()
                current=proposed.relu()-(proposed-1).relu()
            else: current=innovation.sigmoid()
            if self.stage_count:
                stages.append((h@self.params['stage']+self.params['stage_b']).sigmoid().reshape(b,1,self.stage_count))
            sigma=.02+.48*(h@self.params['sigma']+self.params['sigma_b']).sigmoid()
            risk=(h@self.params['risk']+self.params['risk_b']).sigmoid()
            means.append(current.reshape(b,1,self.f));sigmas.append(sigma.reshape(b,1,self.f));risks.append(risk.reshape(b,1))
        outputs=(concat(means,1),concat(sigmas,1),concat(risks,1))
        if return_stages:
            if not self.stage_count: raise ValueError('stage head disabled')
            return outputs+(concat(stages,1),)
        return outputs
    def save(self,path,metadata=None):
        path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
        arrays={k:v.data for k,v in self.params.items()}; arrays['__config__']=np.array(json.dumps(self.config))
        arrays['__metadata__']=np.array(json.dumps(metadata or {}));np.savez(path,**arrays)
    @classmethod
    def load(cls,path):
        z=np.load(path,allow_pickle=False);config=json.loads(str(z['__config__']))
        metadata=json.loads(str(z['__metadata__'])) if '__metadata__' in z.files else {}
        obj=cls(**config)
        for k in obj.params:
            if k not in z.files: raise ValueError(f'Missing weight: {k}')
            obj.params[k].data=np.asarray(z[k])
        return obj,metadata
