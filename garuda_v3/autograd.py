"""Small NumPy reverse-mode tensor engine used by the offline reference model.
Supports exact chain-rule BPTT; tests compare analytical and numerical gradients.
"""
import numpy as np

def unbroadcast(g, shape):
    while g.ndim > len(shape): g = g.sum(axis=0)
    for i, size in enumerate(shape):
        if size == 1 and g.shape[i] != 1: g = g.sum(axis=i, keepdims=True)
    return g

class Tensor:
    __array_priority__ = 1000
    def __init__(self, data, parents=(), backward=None, requires_grad=False):
        self.data = np.asarray(data, dtype=np.float32)
        self.grad = None
        self.parents = parents
        self._backward = backward
        self.requires_grad = requires_grad or any(p.requires_grad for p in parents)
    @staticmethod
    def wrap(x): return x if isinstance(x, Tensor) else Tensor(x)
    def add_grad(self, g):
        if self.requires_grad:
            g = unbroadcast(g, self.data.shape)
            self.grad = g if self.grad is None else self.grad + g
    def __add__(self, other):
        b = Tensor.wrap(other)
        return Tensor(self.data+b.data, (self,b), lambda g:(self.add_grad(g), b.add_grad(g)))
    __radd__ = __add__
    def __neg__(self): return self * -1
    def __sub__(self,b): return self + -Tensor.wrap(b)
    def __rsub__(self,b): return Tensor.wrap(b) + -self
    def __mul__(self, other):
        b=Tensor.wrap(other)
        return Tensor(self.data*b.data,(self,b),lambda g:(self.add_grad(g*b.data), b.add_grad(g*self.data)))
    __rmul__=__mul__
    def __truediv__(self,b): return self * Tensor.wrap(b).power(-1)
    def __matmul__(self, other):
        b=Tensor.wrap(other)
        return Tensor(self.data@b.data,(self,b),lambda g:(self.add_grad(g@np.swapaxes(b.data,-1,-2)),b.add_grad(np.swapaxes(self.data,-1,-2)@g)))
    def power(self,n):
        return Tensor(self.data**n,(self,),lambda g:self.add_grad(g*n*self.data**(n-1)))
    def exp(self):
        y=np.exp(self.data)
        return Tensor(y,(self,),lambda g:self.add_grad(g*y))
    def log(self): return Tensor(np.log(self.data),(self,),lambda g:self.add_grad(g/self.data))
    def tanh(self):
        y=np.tanh(self.data)
        return Tensor(y,(self,),lambda g:self.add_grad(g*(1-y*y)))
    def sigmoid(self):
        y=np.exp(-np.logaddexp(0,-self.data))
        return Tensor(y,(self,),lambda g:self.add_grad(g*y*(1-y)))
    def relu(self): return Tensor(np.maximum(self.data,0),(self,),lambda g:self.add_grad(g*(self.data>0)))
    def sum(self, axis=None, keepdims=False):
        y=self.data.sum(axis=axis,keepdims=keepdims)
        def back(g):
            if axis is not None and not keepdims:
                g=np.expand_dims(g,axis=axis)
            self.add_grad(np.ones_like(self.data)*g)
        return Tensor(y,(self,),back)
    def mean(self,axis=None,keepdims=False):
        n=self.data.size if axis is None else self.data.shape[axis]
        return self.sum(axis,keepdims)/n
    def reshape(self,*shape): return Tensor(self.data.reshape(*shape),(self,),lambda g:self.add_grad(g.reshape(self.data.shape)))
    def __getitem__(self,key):
        def back(g):
            grad=np.zeros_like(self.data); grad[key]+=g; self.add_grad(grad)
        return Tensor(self.data[key],(self,),back)
    def backward(self):
        order=[]; seen=set()
        def visit(t):
            if id(t) in seen: return
            seen.add(id(t))
            for p in t.parents: visit(p)
            order.append(t)
        visit(self)
        for t in order: t.grad=None
        self.grad=np.ones_like(self.data)
        for t in reversed(order):
            if t._backward is not None and t.grad is not None: t._backward(t.grad)


def concat(tensors,axis=-1):
    tensors=[Tensor.wrap(t) for t in tensors]
    lengths=np.cumsum([t.data.shape[axis] for t in tensors])[:-1]
    def back(g):
        for t,piece in zip(tensors,np.split(g,lengths,axis=axis)): t.add_grad(piece)
    return Tensor(np.concatenate([t.data for t in tensors],axis=axis),tuple(tensors),back)

class Adam:
    def __init__(self,params,lr=.003):
        self.params=params; self.lr=lr; self.t=0
        self.m=[np.zeros_like(p.data) for p in params]; self.v=[np.zeros_like(p.data) for p in params]
    def step(self,max_norm=1.):
        self.t+=1
        norm=np.sqrt(sum(float((p.grad**2).sum()) for p in self.params if p.grad is not None))
        scale=min(1.,max_norm/max(float(norm),1e-12))
        for i,p in enumerate(self.params):
            if p.grad is None: continue
            g=p.grad*scale
            if not np.isfinite(g).all(): raise FloatingPointError('Nonfinite gradients')
            self.m[i]=.9*self.m[i]+.1*g; self.v[i]=.999*self.v[i]+.001*g*g
            p.data-=self.lr*(self.m[i]/(1-.9**self.t))/(np.sqrt(self.v[i]/(1-.999**self.t))+1e-8)
