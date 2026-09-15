const express = require('express');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Idempotency-Key & Race-Condition Protection (Prevents double-spending / coupon replay)
const activeOperations = new Map();

function checkIdempotency(req, res, next) {
  const idempotencyKey = req.headers['idempotency-key'] || (req.body && req.body.idempotency_key);
  if (!idempotencyKey) return next();

  if (activeOperations.has(idempotencyKey)) {
    return res.status(409).json({
      status: 'error',
      code: 'DUPLICATE_CONCURRENT_REQUEST',
      message: 'Duplicate/concurrent request blocked (idempotency-protection active)'
    });
  }
  activeOperations.set(idempotencyKey, Date.now());
  setTimeout(() => activeOperations.delete(idempotencyKey), 5000);
  next();
}

// Standard E-Commerce Routes
app.get('/', (req, res) => res.send('<h1>Demo Website</h1><p>This is the real site — running unprotected on port 4000, only reachable through Sentinel on 8080.</p>'));
app.get('/products', (req, res) => res.json({ status: 'success', products: ['Laptop M3 Pro', 'Smartphone 5G', 'Wireless Headphones', 'Gaming Monitor'] }));
app.post('/products', (req, res) => res.json({ status: 'success', created: req.body }));
app.post('/login', (req, res) => res.json({ status: 'success', message: 'login endpoint hit', user: req.body.username || 'guest' }));
app.post('/checkout', checkIdempotency, (req, res) => res.json({ status: 'success', orderId: 'ORD-' + Math.floor(Math.random() * 900000 + 100000), total: 1499, items: req.body }));
app.post('/redeem', checkIdempotency, (req, res) => res.json({ status: 'success', coupon: req.body.coupon || 'WELCOME50', discount: 50, message: 'Coupon redeemed successfully' }));
app.all(/.*/, (req, res) => res.json({ status: 'success', path: req.path, method: req.method }));

app.listen(4000, () => console.log('Demo website running on port 4000 (this is what Sentinel is protecting)'));


