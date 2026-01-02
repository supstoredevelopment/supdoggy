import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import validator from 'validator';
import csrf from 'csurf';
import cookieParser from 'cookie-parser';
import Stripe from 'stripe';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,http://localhost:5500,http://127.0.0.1:5500')
  .split(',')
  .map(origin => origin.trim());

const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const corsOptions = {
  origin: function (origin, callback) {
    console.log('📨 CORS request from origin:', origin);
    console.log('✅ ALLOWED_ORIGINS:', ALLOWED_ORIGINS);

    if (!origin) return callback(null, true);

    if (ALLOWED_ORIGINS.includes(origin)) {
      console.log('✅ Origin ALLOWED');
      return callback(null, true);
    } else {
      console.log('❌ Origin BLOCKED');
      return callback(new Error('Not allowed by CORS'), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
};

app.use((req, res, next) => {
  console.log(`📨 ${req.method} ${req.path} from ${req.get('origin') || 'no-origin'}`);
  next();
});

app.options('/api/stripe-webhook', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'stripe-signature, content-type');
  res.sendStatus(200);
});

app.get('/api/stripe-webhook', (req, res) => {
  res.json({
    status: 'Webhook endpoint is active',
    message: 'This endpoint only accepts POST requests from Stripe',
    timestamp: new Date().toISOString()
  });
});

app.post('/api/stripe-webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    console.log('🎯 Webhook POST received!');
    console.log('Headers:', req.headers);

    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!sig) {
      console.log('❌ No stripe-signature header');
      return res.status(400).json({ error: 'No signature header' });
    }

    if (!webhookSecret) {
      console.log('❌ No STRIPE_WEBHOOK_SECRET in environment');
      return res.status(500).json({ error: 'Webhook secret not configured' });
    }

    let event;

    try {
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
      console.log('✅ Webhook verified:', event.type);
    } catch (err) {
      console.error('❌ Webhook signature verification failed:', err.message);
      return res.status(400).json({ error: 'Webhook signature verification failed' });
    }

    try {
      if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        const { data: order, error: fetchError } = await supabaseAdmin
          .from('orders')
          .select('id, user_id')
          .eq('session_id', session.id)
          .single();

        if (fetchError || !order) {
          console.error('Order not found for session:', session.id);
          return res.status(404).json({ error: 'Order not found' });
        }

        const { error: updateError } = await supabaseAdmin
          .from('orders')
          .update({
            status: 'completed',
            payment_date: new Date().toISOString()
          })
          .eq('session_id', session.id);

        if (updateError) {
          console.error('Failed to update order:', updateError);
          return res.status(500).json({ error: 'Failed to update order' });
        }

        const sessionWithLineItems = await stripe.checkout.sessions.retrieve(session.id, { expand: ['line_items'] });

        console.log('Processing payment for user:', session.metadata.userId);
        console.log('Line items:', sessionWithLineItems.line_items.data.length);

        for (const lineItem of sessionWithLineItems.line_items.data) {
          const priceId = lineItem.price.id;
          console.log('Processing price ID:', priceId);

          const { data: asset, error: assetError } = await supabaseAdmin
            .from('assets')
            .select('id')
            .eq('stripe_price_id', priceId)
            .single();

          if (assetError) {
            console.error('Asset error for price', priceId, ':', assetError);
            continue;
          }

          if (!asset) {
            console.warn('No asset found for price', priceId);
            continue;
          }

          console.log('Found asset:', asset.id);

          const { error: insertError } = await supabaseAdmin
            .from('user_assets')
            .insert({
              user_id: session.metadata.userId,
              asset_id: asset.id,
              purchased_at: new Date().toISOString(),
            });

          if (insertError) {
            if (insertError.code === '23505') {
              console.log('Asset already owned by user, skipping');
            } else {
              console.error('Insert error:', insertError);
            }
          } else {
            console.log('Successfully added asset', asset.id, 'to user', session.metadata.userId);
          }
        }

        try {
          await supabaseAdmin.from('audit_logs').insert({
            user_id: order.user_id,
            action: 'payment',
            resource: 'order',
            resource_id: session.id,
            status: 'completed',
            details: { amount: session.amount_total / 100 },
          });
        } catch (logErr) {
          console.error('Audit log error:', logErr);
        }
      }

      if (event.type === 'checkout.session.expired') {
        const session = event.data.object;

        const { error: updateError } = await supabaseAdmin
          .from('orders')
          .update({ status: 'cancelled' })
          .eq('session_id', session.id);

        if (updateError) {
          console.error('Failed to cancel order:', updateError);
          return res.status(500).json({ error: 'Failed to update order' });
        }
      }

      if (event.type === 'charge.refunded') {
        const charge = event.data.object;
        const { metadata } = charge;

        if (metadata?.orderId) {
          const { error: updateError } = await supabaseAdmin
            .from('orders')
            .update({ status: 'refunded' })
            .eq('id', metadata.orderId);

          if (!updateError) {
            try {
              await supabaseAdmin.from('audit_logs').insert({
                action: 'refund',
                resource: 'order',
                resource_id: metadata.orderId,
                status: 'completed',
                details: { amount: charge.amount / 100 },
              });
            } catch (logErr) {
              console.error('Audit log error:', logErr);
            }
          }
        }
      }

      console.log('✅ Webhook processed successfully');
      res.json({ received: true });
    } catch (err) {
      console.error('❌ Webhook processing error:', err);
      res.status(500).json({ error: 'Webhook processing failed' });
    }
  });

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://cdnjs.cloudflare.com",
          "https://js.stripe.com",
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
          "https://cdnjs.cloudflare.com",
        ],
        fontSrc: [
          "'self'",
          "https://fonts.gstatic.com",
          "https://cdnjs.cloudflare.com",
        ],
        imgSrc: [
          "'self'",
          "data:",
          "https:",
          "blob:",
        ],
        connectSrc: [
          "'self'",
          "https://api.stripe.com",
          process.env.SUPABASE_URL,
          process.env.FRONTEND_URL || "'self'",
          "http://localhost:3000",
          "http://localhost:3001",
        ].filter(Boolean),
        frameSrc: [
          "'self'",
          "https://js.stripe.com",
          "https://hooks.stripe.com",
        ],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
      },
    },
  })
);
app.use(cookieParser(SESSION_SECRET));
app.use(cors(corsOptions));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === 'GET' || req.path === '/api/stripe-webhook',
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
});

const checkoutLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
});

app.use(limiter);

const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
});

const validateEmail = (email) => {
  if (!validator.isEmail(email)) throw new Error('Invalid email');
  return validator.trim(email).toLowerCase();
};

const validateUserId = (userId) => {
  if (typeof userId !== 'string' || !validator.isUUID(userId)) {
    throw new Error('Invalid user ID');
  }
  return userId;
};

const validateCartItem = (item) => {
  if (!Number.isInteger(item.id) || item.id < 1) {
    throw new Error('Invalid item ID');
  }
  if (!Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > 100) {
    throw new Error('Invalid quantity');
  }
  return { id: item.id, quantity: item.quantity };
};

const authenticateToken = async (req, res, next) => {
  try {
    let token = req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      token = req.cookies.auth_token;
    }

    if (!token) {
      return res.status(401).json({ error: 'No authentication token' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const { data: { user }, error } = await supabaseAdmin.auth.admin.getUserById(decoded.userId);

    if (error || !user || !user.email_confirmed_at) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    req.user = user;
    req.userId = validateUserId(user.id);
    next();
  } catch (err) {
    console.error('Auth error:', err);
    return res.status(401).json({ error: 'Invalid token' });
  }
};

app.post('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.get('/api/assets/top-selling', async (req, res) => {
  try {
    const limit = Math.min(20, parseInt(req.query.limit) || 10);

    const { data: assets, error } = await supabase
      .from('assets')
      .select('id, title, description, price, image_url, tag')
      .eq('is_top_selling', true)
      .limit(limit)
      .order('created_at', { ascending: false });

    if (error) return res.status(500).json({ error: 'Failed to fetch assets' });

    res.json(assets);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/signup', authLimiter, async (req, res) => {
  try {
    const { email, password, fullName } = req.body;

    if (!email || !password || !fullName) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const validEmail = validateEmail(email);

    if (password.length < 8) {
      return res.status(400).json({ warning: 'Password must be at least 12 characters' });
    }

    if (!/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
      return res.status(400).json({ warning: 'Password must contain uppercase letters and numbers' });
    }

    if (!validator.isLength(fullName, { min: 2, max: 100 })) {
      return res.status(400).json({ warning: 'Invalid name length' });
    }

    if (!/^[a-zA-Z\s'-]+$/.test(fullName)) {
      return res.status(400).json({ warning: 'Invalid name format' });
    }

    const { data, error } = await supabase.auth.signUp({
      email: validEmail,
      password,
      options: {
        data: { full_name: validator.trim(fullName) },
        emailRedirectTo: `${process.env.FRONTEND_URL}/p/verified`,
      },
    });

    if (error) return res.status(400).json({ error: error.message });

    supabaseAdmin.from('audit_logs').insert({
      action: 'signup',
      resource: 'auth',
      resource_id: data.user?.id,
      status: 'success',
    });

    res.status(201).json({ message: 'Check your email to confirm' });
  } catch (err) {
    res.status(400).json({ error: 'Signup failed' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    console.log('📨 Login request received');

    const { email, password } = req.body;

    if (!email || !password) {
      console.log('❌ Missing email or password');
      return res.status(400).json({ error: 'Email and password required' });
    }

    const validEmail = validateEmail(email);

    const { data, error } = await supabase.auth.signInWithPassword({
      email: validEmail,
      password,
    });

    if (error || !data?.user?.email_confirmed_at) {
      console.log('❌ Login failed - invalid credentials or unconfirmed email');
      try {
        await supabaseAdmin.from('audit_logs').insert({
          action: 'login',
          resource: 'auth',
          status: 'failed',
        });
      } catch (logErr) { }
      return res.status(401).json({ error: 'Invalid credentials or unconfirmed email' });
    }

    const token = jwt.sign(
      { userId: data.user.id, email: data.user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.cookie('auth_token', data.session.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.cookie('jwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    });

    console.log('✅ Login successful for user:', data.user.id);

    supabaseAdmin.from('audit_logs').insert({
      user_id: data.user.id,
      action: 'login',
      resource: 'auth',
      status: 'success',
    });

    res.json({
      message: 'Logged in successfully',
      token: token
    });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(400).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    res.clearCookie('auth_token');
    res.clearCookie('jwt');

    try {
      await supabaseAdmin.from('audit_logs').insert({
        user_id: req.userId,
        action: 'logout',
        resource: 'auth',
        status: 'success',
      });
    } catch (logErr) { }

    res.json({ message: 'Logged out' });
  } catch (err) {
    res.status(400).json({ error: 'Logout failed' });
  }
});

app.post('/api/create-checkout-session', checkoutLimiter, authenticateToken, async (req, res) => {
  try {
    const { cart } = req.body;
    const userId = req.userId;
    const userEmail = req.user.email;

    if (!Array.isArray(cart) || cart.length === 0 || cart.length > 100) {
      return res.status(400).json({ error: 'Invalid cart' });
    }

    const validatedCart = cart.map(validateCartItem);

    const { data: products, error: productsError } = await supabase
      .from('assets')
      .select('id, title, price, stripe_product_id, stripe_price_id')
      .in('id', validatedCart.map(item => item.id));

    if (productsError || !products) {
      return res.status(400).json({ error: 'Failed to fetch products' });
    }

    const productMap = new Map(products.map(p => [p.id, p]));
    const lineItems = [];
    let totalAmount = 0;

    for (const item of validatedCart) {
      const product = productMap.get(item.id);
      if (!product) {
        console.error(`Product ${item.id} not found in database`);
        return res.status(400).json({ error: `Product ${item.id} not found` });
      }

      if (!product.stripe_price_id) {
        console.error(`Product ${item.id} has no stripe_price_id:`, product);
        return res.status(400).json({ error: `Product ${item.id} not available for purchase` });
      }

      if (product.price < 0 || !Number.isFinite(product.price)) {
        return res.status(400).json({ error: 'Invalid product price' });
      }

      lineItems.push({
        price: product.stripe_price_id,
        quantity: item.quantity,
      });

      totalAmount += product.price * item.quantity;
    }

    const session = await stripe.checkout.sessions.create({
      customer_email: userEmail,
      line_items: lineItems,
      mode: 'payment',
      success_url: `${process.env.FRONTEND_URL}/p/success/?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/p/cancel`,
      allow_promotion_codes: true,
      metadata: {
        userId,
      },
    });

    const { error: orderError } = await supabaseAdmin
      .from('orders')
      .insert({
        user_id: userId,
        session_id: session.id,
        total_amount: Math.round(totalAmount * 100) / 100,
        status: 'pending',
      });

    if (orderError) {
      return res.status(500).json({ error: 'Failed to create order record' });
    }

    try {
      await supabaseAdmin.from('audit_logs').insert({
        user_id: userId,
        action: 'checkout',
        resource: 'order',
        resource_id: session.id,
        status: 'initiated',
        details: { items_count: cart.length, total_amount: totalAmount },
      });
    } catch (logErr) { }

    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

app.get('/api/user/orders', authenticateToken, async (req, res) => {
  try {
    const { data: orders, error } = await supabaseAdmin
      .from('orders')
      .select('id, created_at, total_amount, status')
      .eq('user_id', req.userId)
      .order('created_at', { ascending: false });

    if (error) return res.status(500).json({ error: 'Failed to fetch orders' });

    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/user/assets', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('user_assets')
      .select('*, assets(*)')
      .eq('user_id', req.userId);

    if (error) {
      console.error('Error fetching user assets:', error);
      return res.status(500).json({ error: 'Failed to fetch assets' });
    }

    const assets = data.map(d => d.assets);
    res.json(assets);
  } catch (err) {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/asset/:assetId/versions', authenticateToken, async (req, res) => {
  try {
    const assetId = parseInt(req.params.assetId);
    if (!Number.isInteger(assetId) || assetId < 1) {
      return res.status(400).json({ error: 'Invalid asset ID' });
    }

    const { count, error: countError } = await supabaseAdmin
      .from('user_assets')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', req.userId)
      .eq('asset_id', assetId);

    if (countError || count === 0) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    const { data, error } = await supabaseAdmin
      .from('asset_versions')
      .select('id, version, created_at, release_notes')
      .eq('asset_id', assetId)
      .order('created_at', { ascending: false });

    if (error) return res.status(500).json({ error: 'Failed to fetch versions' });

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/download/:assetId/:versionId', authenticateToken, async (req, res) => {
  try {
    const assetId = parseInt(req.params.assetId);
    const versionId = parseInt(req.params.versionId);

    if (!Number.isInteger(assetId) || assetId < 1 || !Number.isInteger(versionId) || versionId < 1) {
      return res.status(400).json({ error: 'Invalid asset or version ID' });
    }

    const { count, error: countError } = await supabaseAdmin
      .from('user_assets')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', req.userId)
      .eq('asset_id', assetId);

    if (countError || count === 0) {
      console.error('Authorization check failed:', countError);
      return res.status(403).json({ error: 'Not authorized' });
    }

    const { data: version, error: versionError } = await supabaseAdmin
      .from('asset_versions')
      .select('file_path')
      .eq('asset_id', assetId)
      .eq('id', versionId)
      .single();

    if (versionError || !version) {
      console.error('Version lookup failed:', versionError);
      return res.status(404).json({ error: 'Version not found' });
    }

    let filePath = version.file_path;

    if (filePath.startsWith('/')) {
      filePath = filePath.substring(1);
    }

    if (filePath.startsWith('assets/')) {
      filePath = filePath.substring(7);
    }

    const { data: signedUrlData, error: signedUrlError } = await supabaseAdmin
      .storage
      .from('assets')
      .createSignedUrl(filePath, 3600, {
        download: true
      });

    if (signedUrlError) {
      console.error('Signed URL error:', signedUrlError);
      return res.status(500).json({
        error: 'Failed to generate download URL',
        details: process.env.NODE_ENV === 'development' ? signedUrlError.message : undefined
      });
    }

    if (!signedUrlData || !signedUrlData.signedUrl) {
      return res.status(500).json({ error: 'Failed to generate download URL' });
    }

    try {
      await supabaseAdmin.from('audit_logs').insert({
        user_id: req.userId,
        action: 'download',
        resource: 'asset',
        resource_id: assetId.toString(),
        status: 'success',
        details: { version_id: versionId, file_path: filePath }
      });
    } catch (logErr) { }

    res.json({ url: signedUrlData.signedUrl });
  } catch (err) {
    console.error('Download error:', err);
    res.status(500).json({ error: 'Server error', message: err.message });
  }
});

app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const { fullName } = req.body;

    if (!fullName || !validator.isLength(fullName, { min: 2, max: 100 })) {
      return res.status(400).json({ error: 'Invalid name length' });
    }

    if (!/^[a-zA-Z\s'-]+$/.test(fullName)) {
      return res.status(400).json({ error: 'Invalid name format' });
    }

    const { error } = await supabase.auth.updateUser(
      { data: { full_name: validator.trim(fullName) } },
      { jwt: req.cookies.auth_token }
    );

    if (error) return res.status(400).json({ error: 'Update failed' });

    try {
      await supabaseAdmin.from('audit_logs').insert({
        user_id: req.userId,
        action: 'profile_update',
        resource: 'user',
        status: 'success',
      });
    } catch (logErr) { }

    res.json({ message: 'Profile updated' });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    res.json({
      id: req.user.id,
      email: req.user.email,
      fullName: req.user.user_metadata?.full_name || null,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.get('/api/assets', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, parseInt(req.query.limit) || 12);
    const offset = (page - 1) * limit;

    const { data: assets, error, count } = await supabase
      .from('assets')
      .select('id, title, description, price, image_url, tag, is_top_selling', { count: 'exact' })
      .range(offset, offset + limit - 1)
      .order('created_at', { ascending: false });

    if (error) return res.status(500).json({ error: 'Failed to fetch assets' });

    res.json({
      data: assets,
      pagination: {
        page,
        limit,
        total: count,
        pages: Math.ceil(count / limit)
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/assets/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ error: 'Invalid asset ID' });
    }

    const { data: asset, error } = await supabase
      .from('assets')
      .select('id, title, description, price, image_url, tag, is_top_selling, created_at')
      .eq('id', id)
      .single();

    if (error || !asset) {
      return res.status(404).json({ error: 'Asset not found' });
    }

    res.json(asset);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.use(express.static(path.join(__dirname, '..')));

app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'CSRF validation failed' });
  }

  if (err instanceof SyntaxError) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌐 Frontend served from: src/`);
  console.log(`🎯 Webhook endpoint: http://localhost:${PORT}/api/stripe-webhook`);
  console.log(`📁 Static files directory: ${path.join(__dirname, '..')}`);
});