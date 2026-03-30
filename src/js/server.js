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

app.set('trust proxy', 1);

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://supdoggy.onrender.com')
  .split(',')
  .map(origin => origin.trim());

const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// ── Audit log helper (safe fire-and-forget) ───────────────────────────────────
// Supabase query builders are NOT native Promises — never call .catch() on them
// directly. Always await or use this helper.
const auditLog = async (data) => {
  try {
    const { error } = await supabaseAdmin.from('audit_logs').insert(data);
    if (error) console.error('⚠️ Audit log insert error:', error.message, '| data:', JSON.stringify(data));
  } catch (err) {
    console.error('⚠️ Audit log exception:', err.message);
  }
};

// ── CORS ──────────────────────────────────────────────────────────────────────

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

// ── Stripe webhook ────────────────────────────────────────────────────────────
// Must be registered BEFORE express.json() middleware so body stays as raw Buffer

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
    timestamp: new Date().toISOString(),
  });
});

app.post(
  '/api/stripe-webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🎯 Webhook POST received at', new Date().toISOString());
    console.log('   Headers:', JSON.stringify({
      'stripe-signature': req.headers['stripe-signature'] ? '[present]' : '[MISSING]',
      'content-type': req.headers['content-type'],
      'content-length': req.headers['content-length'],
    }));

    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!sig) {
      console.error('❌ No stripe-signature header');
      return res.status(400).json({ error: 'No signature header' });
    }
    if (!webhookSecret) {
      console.error('❌ STRIPE_WEBHOOK_SECRET env var not set');
      return res.status(500).json({ error: 'Webhook secret not configured' });
    }

    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
      console.log('✅ Webhook signature verified');
      console.log('   Event type :', event.type);
      console.log('   Event id   :', event.id);
    } catch (err) {
      console.error('❌ Webhook signature verification failed:', err.message);
      return res.status(400).json({ error: 'Invalid signature' });
    }

    try {
      // ════════════════════════════════════════════════════════════════
      // CHECKOUT COMPLETED
      // ════════════════════════════════════════════════════════════════
      if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        console.log('\n💳 checkout.session.completed');
        console.log('   Session id      :', session.id);
        console.log('   Payment status  :', session.payment_status);
        console.log('   Amount total    :', session.amount_total);
        console.log('   Currency        :', session.currency);
        console.log('   Customer email  :', session.customer_email);
        console.log('   Raw metadata    :', JSON.stringify(session.metadata));

        // ── Resolve userId & orderId ──────────────────────────────────
        // Primary source: session metadata (set at checkout creation time).
        // Fallback 1:     look up order by session_id (handles race where
        //                 session_id was saved to the DB before webhook fires).
        // Fallback 2:     look up the most recent PENDING order for this user
        //                 (handles old sessions created before orderId was added
        //                 to metadata, or rare race conditions).

        let userId = session.metadata?.userId || null;
        let orderId = session.metadata?.orderId || null;

        console.log('\n🔍 Metadata resolution:');
        console.log('   userId from metadata  :', userId || '[MISSING]');
        console.log('   orderId from metadata :', orderId || '[MISSING]');

        // ── Fallback 1: session_id lookup ─────────────────────────────
        if (!userId || !orderId) {
          console.log('\n⚠️  Metadata incomplete — trying fallback 1: lookup by session_id...');

          const { data: fallbackOrder, error: fallbackErr } = await supabaseAdmin
            .from('orders')
            .select('id, user_id, status')
            .eq('session_id', session.id)
            .maybeSingle(); // maybeSingle() returns null instead of throwing on no rows

          if (fallbackErr) {
            console.error('   ❌ Fallback 1 DB error:', fallbackErr.message);
          } else if (!fallbackOrder) {
            console.warn('   ⚠️  Fallback 1: no order row found with session_id:', session.id);
          } else {
            console.log('   ✅ Fallback 1 resolved — order:', fallbackOrder.id, '| user:', fallbackOrder.user_id);
            userId = userId || fallbackOrder.user_id;
            orderId = orderId || fallbackOrder.id;
          }
        }

        // ── Fallback 2: recent pending order for this user ────────────
        // Only possible if we at least have userId from metadata.
        if (userId && !orderId) {
          console.log('\n⚠️  orderId still missing — trying fallback 2: most recent pending order for user...');

          const { data: recentOrder, error: recentErr } = await supabaseAdmin
            .from('orders')
            .select('id, user_id, status, created_at, session_id')
            .eq('user_id', userId)
            .eq('status', 'pending')
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();

          if (recentErr) {
            console.error('   ❌ Fallback 2 DB error:', recentErr.message);
          } else if (!recentOrder) {
            console.warn('   ⚠️  Fallback 2: no pending order found for user:', userId);
          } else {
            console.log('   ✅ Fallback 2 resolved — order:', recentOrder.id, '| created_at:', recentOrder.created_at);
            orderId = recentOrder.id;

            // If this order has no session_id yet, link it now
            if (!recentOrder.session_id) {
              const { error: linkErr } = await supabaseAdmin
                .from('orders')
                .update({ session_id: session.id })
                .eq('id', orderId);
              if (linkErr) {
                console.error('   ⚠️  Failed to link session_id to order (fallback 2):', linkErr.message);
              } else {
                console.log('   🔗 session_id linked to order via fallback 2');
              }
            }
          }
        }

        // ── Give up if we still can't resolve ────────────────────────
        if (!userId || !orderId) {
          console.error('\n❌ UNRESOLVABLE — could not determine userId or orderId after all fallbacks');
          console.error('   userId :', userId);
          console.error('   orderId:', orderId);
          console.error('   session_id:', session.id);

          await auditLog({
            action: 'webhook_unresolvable',
            resource: 'order',
            status: 'failed',
            details: {
              session_id: session.id,
              metadata: session.metadata,
              reason: 'Missing metadata and no matching order row found via any fallback',
            },
          });

          // Return 200 so Stripe does NOT keep retrying — this needs manual review.
          return res.json({ received: true, warning: 'Order not found — logged for manual review' });
        }

        console.log('\n✅ Resolution complete — userId:', userId, '| orderId:', orderId);

        // ── Idempotency guard ─────────────────────────────────────────
        // Stripe can deliver the same event more than once; safe to skip.
        const { data: existingOrder, error: existingErr } = await supabaseAdmin
          .from('orders')
          .select('id, status, session_id')
          .eq('id', orderId)
          .maybeSingle();

        if (existingErr) {
          console.error('❌ Failed to fetch order for idempotency check:', existingErr.message);
          return res.status(500).json({ error: 'DB error fetching order' });
        }
        if (!existingOrder) {
          console.error('❌ Order row not found for orderId:', orderId);
          return res.status(400).json({ error: 'Order not found' });
        }

        console.log('📋 Existing order status:', existingOrder.status);

        if (existingOrder.status === 'completed') {
          console.log('ℹ️  Order already completed — skipping (idempotent):', orderId);
          return res.json({ received: true, note: 'Already completed' });
        }

        // ── Mark order completed ──────────────────────────────────────
        console.log('\n📝 Marking order as completed...');
        const { error: updateError } = await supabaseAdmin
          .from('orders')
          .update({
            status: 'completed',
            payment_date: new Date().toISOString(),
            session_id: session.id, // ensure session_id is always stored
          })
          .eq('id', orderId);

        if (updateError) {
          console.error('❌ Failed to update order status:', updateError.message);
          return res.status(500).json({ error: 'Order update failed' });
        }
        console.log('✅ Order marked as completed:', orderId);

        // ── Resolve line items ────────────────────────────────────────
        console.log('\n🛒 Resolving line items...');
        let lineItems = session.line_items?.data;

        if (!lineItems) {
          console.log('   line_items not on session object — fetching via retrieve()...');
          try {
            const sessionExpanded = await stripe.checkout.sessions.retrieve(session.id, {
              expand: ['line_items'],
            });
            lineItems = sessionExpanded.line_items?.data || [];
            console.log('   ✅ Expanded line items fetched, count:', lineItems.length);
          } catch (stripeErr) {
            console.error('   ❌ Failed to expand line items:', stripeErr.message);
            lineItems = [];
          }
        } else {
          console.log('   Line items already on session, count:', lineItems.length);
        }

        // ── Fetch all assets for price matching ───────────────────────
        const { data: allAssets, error: assetsErr } = await supabaseAdmin
          .from('assets')
          .select('id, title, stripe_price_id, stripe_prices_multi');

        if (assetsErr) {
          console.error('❌ Failed to fetch assets for matching:', assetsErr.message);
          return res.status(500).json({ error: 'Failed to fetch assets' });
        }

        console.log('   Total assets in DB for matching:', allAssets.length);

        // ── Grant assets per line item ────────────────────────────────
        let grantedCount = 0;
        let skippedCount = 0;

        for (const lineItem of lineItems) {
          const priceId = lineItem.price?.id;
          console.log('\n   📦 Processing line item — price_id:', priceId, '| qty:', lineItem.quantity);

          if (!priceId) {
            console.warn('   ⚠️  Line item has no price id, skipping');
            skippedCount++;
            continue;
          }

          // Match by default stripe_price_id OR any currency in stripe_prices_multi
          let asset = allAssets.find(a => a.stripe_price_id === priceId);
          if (!asset) {
            asset = allAssets.find(
              a =>
                a.stripe_prices_multi &&
                Object.values(a.stripe_prices_multi).includes(priceId)
            );
          }

          if (!asset) {
            console.warn('   ⚠️  No asset matched price_id:', priceId);
            console.warn('   Known price IDs:', allAssets.map(a => ({
              id: a.id,
              stripe_price_id: a.stripe_price_id,
              multi_keys: a.stripe_prices_multi ? Object.keys(a.stripe_prices_multi) : [],
            })));
            skippedCount++;
            continue;
          }

          console.log('   🎯 Matched asset:', asset.id, '|', asset.title);

          const { error: insertError } = await supabaseAdmin
            .from('user_assets')
            .insert({
              user_id: userId,
              asset_id: asset.id,
              purchased_at: new Date().toISOString(),
            });

          // 23505 = unique_violation — asset already owned; safe to ignore
          if (insertError && insertError.code !== '23505') {
            console.error('   ❌ Failed to insert user_asset:', insertError.message, '| code:', insertError.code);
          } else if (insertError?.code === '23505') {
            console.log('   ℹ️  Asset already owned by user (unique_violation) — skipping:', asset.id);
          } else {
            console.log('   ✅ Asset granted:', asset.id, '→ user:', userId);
            grantedCount++;
          }
        }

        console.log('\n📊 Grant summary — granted:', grantedCount, '| skipped:', skippedCount);

        // ── Audit log ─────────────────────────────────────────────────
        await auditLog({
          user_id: userId,
          action: 'payment',
          resource: 'order',
          resource_id: orderId,
          status: 'completed',
          details: {
            amount: session.amount_total / 100,
            currency: session.currency,
            session_id: session.id,
            assets_granted: grantedCount,
            line_items_skipped: skippedCount,
          },
        });

        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
      }

      // ════════════════════════════════════════════════════════════════
      // SESSION EXPIRED
      // ════════════════════════════════════════════════════════════════
      if (event.type === 'checkout.session.expired') {
        const session = event.data.object;
        const orderId = session.metadata?.orderId;

        console.log('\n🚫 checkout.session.expired');
        console.log('   Session id:', session.id);
        console.log('   orderId from metadata:', orderId || '[MISSING]');

        if (orderId) {
          const { error } = await supabaseAdmin
            .from('orders')
            .update({ status: 'cancelled' })
            .eq('id', orderId)
            .eq('status', 'pending');
          if (error) console.error('   ❌ Failed to cancel order by orderId:', error.message);
          else console.log('   ✅ Order cancelled:', orderId);
        } else {
          // Fallback by session_id
          console.log('   ⚠️  No orderId — attempting cancel via session_id fallback...');
          const { error } = await supabaseAdmin
            .from('orders')
            .update({ status: 'cancelled' })
            .eq('session_id', session.id)
            .eq('status', 'pending');
          if (error) console.warn('   ⚠️  Fallback cancel failed:', error.message);
          else console.log('   ✅ Order cancelled via session_id fallback');
        }
      }

      // ════════════════════════════════════════════════════════════════
      // REFUND
      // ════════════════════════════════════════════════════════════════
      if (event.type === 'charge.refunded') {
        const charge = event.data.object;
        const orderId = charge.metadata?.orderId;

        console.log('\n💸 charge.refunded');
        console.log('   Charge id  :', charge.id);
        console.log('   Amount     :', charge.amount_refunded);
        console.log('   orderId from metadata:', orderId || '[MISSING]');
        console.log('   payment_intent:', charge.payment_intent || '[MISSING]');

        if (orderId) {
          const { error } = await supabaseAdmin
            .from('orders')
            .update({ status: 'refunded' })
            .eq('id', orderId);
          if (error) console.error('   ❌ Failed to mark order refunded:', error.message);
          else console.log('   ✅ Order marked as refunded:', orderId);
        } else {
          // Stripe links charges to payment intents; attempt a best-effort lookup
          // by matching payment_intent via checkout session → order
          const paymentIntentId = charge.payment_intent;
          console.warn('   ⚠️  orderId missing from charge metadata — attempting payment_intent lookup...');

          if (paymentIntentId) {
            // Find the checkout session that owns this payment_intent
            const sessions = await stripe.checkout.sessions.list({
              payment_intent: paymentIntentId,
              limit: 1,
            });
            const relatedSession = sessions.data?.[0];

            if (relatedSession) {
              console.log('   🔍 Found related session:', relatedSession.id);

              const { data: matchedOrder, error: matchErr } = await supabaseAdmin
                .from('orders')
                .select('id')
                .eq('session_id', relatedSession.id)
                .maybeSingle();

              if (matchErr) {
                console.error('   ❌ DB error looking up order by session_id:', matchErr.message);
              } else if (matchedOrder) {
                const { error: refundErr } = await supabaseAdmin
                  .from('orders')
                  .update({ status: 'refunded' })
                  .eq('id', matchedOrder.id);
                if (refundErr) console.error('   ❌ Failed to mark matched order refunded:', refundErr.message);
                else console.log('   ✅ Order refunded via payment_intent lookup:', matchedOrder.id);
              } else {
                console.warn('   ⚠️  No order found for session_id:', relatedSession.id, '— logging for manual review');
                await auditLog({
                  action: 'refund_unmatched',
                  resource: 'charge',
                  status: 'needs_review',
                  details: {
                    charge_id: charge.id,
                    payment_intent: paymentIntentId,
                    related_session_id: relatedSession.id,
                  },
                });
              }
            } else {
              console.warn('   ⚠️  No Stripe session found for payment_intent:', paymentIntentId);
              await auditLog({
                action: 'refund_unmatched',
                resource: 'charge',
                status: 'needs_review',
                details: {
                  charge_id: charge.id,
                  payment_intent: paymentIntentId,
                  reason: 'No matching checkout session',
                },
              });
            }
          }
        }
      }

      res.json({ received: true });
    } catch (err) {
      console.error('❌ Webhook processing error:', err.message);
      console.error('   Stack:', err.stack);
      // Return 500 so Stripe retries — idempotency guard prevents double-processing.
      res.status(500).json({ error: 'Webhook processing failed' });
    }
  }
);

// ── Middleware ────────────────────────────────────────────────────────────────

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "'unsafe-hashes'",
          "https://cdnjs.cloudflare.com",
          "https://js.stripe.com",
          "https://cdn.jsdelivr.net",
        ],
        scriptSrcAttr: ["'unsafe-inline'", "'unsafe-hashes'"],
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
        imgSrc: ["'self'", "data:", "https:", "blob:"],
        connectSrc: [
          "'self'",
          "https://api.stripe.com",
          "https://api.emailjs.com",
          "https://api.exchangerate-api.com",
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

// ── Validators ────────────────────────────────────────────────────────────────

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
  const id = parseInt(item.id);
  if (!Number.isInteger(id) || id < 1) throw new Error('Invalid item ID');
  if (!Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > 100) {
    throw new Error('Invalid quantity');
  }
  return { id, quantity: item.quantity };
};

// ── Auth middleware ───────────────────────────────────────────────────────────

const authenticateToken = async (req, res, next) => {
  try {
    let token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) token = req.cookies.jwt;
    if (!token) return res.status(401).json({ error: 'No authentication token' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const { data: { user }, error } = await supabaseAdmin.auth.admin.getUserById(decoded.userId);
    if (error || !user) return res.status(401).json({ error: 'Unauthorized' });

    const isEmailConfirmed = !!user.email_confirmed_at;
    const isOAuthUser = user.app_metadata?.provider && user.app_metadata.provider !== 'email';

    if (!isEmailConfirmed && !isOAuthUser) {
      return res.status(401).json({ error: 'Email not confirmed' });
    }

    req.user = user;
    req.userId = validateUserId(user.id);
    next();
  } catch (err) {
    console.error('Auth error:', err);
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// ── Routes ────────────────────────────────────────────────────────────────────

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
        emailRedirectTo: `${process.env.FRONTEND_URL}/p/dashboard`,
      },
    });

    if (error) return res.status(400).json({ error: error.message });

    await auditLog({
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
      return res.status(400).json({ error: 'Email and password required' });
    }

    const validEmail = validateEmail(email);
    const { data, error } = await supabase.auth.signInWithPassword({ email: validEmail, password });

    if (error || !data?.user?.email_confirmed_at) {
      await auditLog({ action: 'login', resource: 'auth', status: 'failed' });
      return res.status(401).json({ error: 'Invalid credentials or unconfirmed email' });
    }

    const token = jwt.sign(
      { userId: data.user.id, email: data.user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const cookieOpts = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    };

    res.cookie('auth_token', data.session.access_token, cookieOpts);
    res.cookie('jwt', token, cookieOpts);

    await auditLog({
      user_id: data.user.id, action: 'login', resource: 'auth', status: 'success',
    });

    console.log('✅ Login successful for user:', data.user.id);
    res.json({ message: 'Logged in successfully', token });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(400).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    res.clearCookie('auth_token');
    res.clearCookie('jwt');

    await auditLog({
      user_id: req.userId, action: 'logout', resource: 'auth', status: 'success',
    });

    res.json({ message: 'Logged out' });
  } catch (err) {
    res.status(400).json({ error: 'Logout failed' });
  }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: { redirectTo: `${process.env.FRONTEND_URL}/p/login` },
    });
    if (error) return res.status(400).json({ error: error.message });
    res.json({ url: data.url });
  } catch (err) {
    console.error('Google OAuth error:', err);
    res.status(500).json({ error: 'Google sign-in failed' });
  }
});

app.post('/api/auth/oauth-callback', async (req, res) => {
  try {
    console.log('📨 /api/auth/oauth-callback hit');
    const { access_token } = req.body;

    if (!access_token) {
      return res.status(400).json({ error: 'Missing access token' });
    }

    const { data: { user }, error } = await supabaseAdmin.auth.getUser(access_token);
    if (error || !user) return res.status(401).json({ error: 'Invalid OAuth token' });

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const cookieOpts = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    };

    res.cookie('auth_token', access_token, cookieOpts);
    res.cookie('jwt', token, cookieOpts);

    await auditLog({
      user_id: user.id,
      action: 'login',
      resource: 'auth',
      status: 'success',
      details: { provider: user.app_metadata?.provider || 'oauth' },
    });

    console.log('✅ OAuth callback success for user:', user.id);
    res.json({ token, message: 'Logged in successfully' });
  } catch (err) {
    console.error('❌ OAuth callback error:', err);
    res.status(500).json({ error: 'OAuth callback failed' });
  }
});

app.post('/api/create-checkout-session', checkoutLimiter, authenticateToken, async (req, res) => {
  try {
    console.log('\n🛒 Checkout request received');
    console.log('   userId    :', req.userId);
    console.log('   userEmail :', req.user.email);
    console.log('   cart      :', JSON.stringify(req.body.cart));
    console.log('   currency  :', req.body.currency);

    const { cart, currency } = req.body;
    const userId = req.userId;
    const userEmail = req.user.email;

    if (!Array.isArray(cart) || cart.length === 0 || cart.length > 100) {
      return res.status(400).json({ error: 'Invalid cart' });
    }

    const validatedCart = cart.map(validateCartItem);

    const { data: products, error: productsError } = await supabase
      .from('assets')
      .select('id, title, price, stripe_product_id, stripe_price_id, stripe_prices_multi')
      .in('id', validatedCart.map(item => item.id));

    if (productsError || !products) {
      console.error('❌ Failed to fetch products:', productsError?.message);
      return res.status(400).json({ error: 'Failed to fetch products' });
    }

    console.log('   Products fetched:', products.map(p => ({ id: p.id, title: p.title, price: p.price })));

    const productMap = new Map(products.map(p => [p.id, p]));

    // ── Split cart into free / paid ───────────────────────────────
    const freeItems = [];
    const paidItems = [];

    for (const item of validatedCart) {
      const product = productMap.get(item.id);
      if (!product) return res.status(400).json({ error: `Product ${item.id} not found` });

      if (!product.price || product.price === 0) {
        freeItems.push({ item, product });
      } else {
        paidItems.push({ item, product });
      }
    }

    console.log('   Free items:', freeItems.length, '| Paid items:', paidItems.length);

    // ── Grant free items immediately ──────────────────────────────
    for (const { product } of freeItems) {
      const { error: insertError } = await supabaseAdmin
        .from('user_assets')
        .insert({
          user_id: userId,
          asset_id: product.id,
          purchased_at: new Date().toISOString(),
        });

      if (insertError && insertError.code !== '23505') {
        console.error('❌ Failed to grant free asset:', product.id, insertError.message);
        return res.status(500).json({ error: 'Failed to grant free asset' });
      }

      console.log('✅ Free asset granted:', product.id);
    }

    // ── Everything free ───────────────────────────────────────────
    if (paidItems.length === 0) {
      const { error: orderErr } = await supabaseAdmin.from('orders').insert({
        user_id: userId,
        session_id: `free_${crypto.randomUUID()}`,
        total_amount: 0,
        status: 'completed',
        payment_date: new Date().toISOString(),
        currency: (currency || 'USD').toUpperCase(),
      });
      if (orderErr) console.error('⚠️ Failed to log free order:', orderErr.message);
      return res.json({ free: true });
    }

    // ── Build Stripe line items ───────────────────────────────────
    const lineItems = [];
    let totalAmount = 0;
    const checkoutCurrency = (currency || 'usd').toLowerCase();

    for (const { item, product } of paidItems) {
      let stripePriceId;

      if (product.stripe_prices_multi && typeof product.stripe_prices_multi === 'object') {
        stripePriceId = product.stripe_prices_multi[checkoutCurrency];
      }

      if (!stripePriceId) {
        stripePriceId = product.stripe_prices_multi?.['usd'] || product.stripe_price_id;
      }

      console.log(`   Product ${product.id} — currency: ${checkoutCurrency} → price_id: ${stripePriceId || '[NOT FOUND]'}`);

      if (!stripePriceId) {
        return res.status(400).json({ error: `Product ${item.id} has no Stripe price configured` });
      }

      lineItems.push({ price: stripePriceId, quantity: item.quantity });
      totalAmount += product.price * item.quantity;
    }

    // ── Create order FIRST so we have orderId for Stripe metadata ─
    const { data: order, error: orderError } = await supabaseAdmin
      .from('orders')
      .insert({
        user_id: userId,
        total_amount: Math.round(totalAmount * 100) / 100,
        status: 'pending',
        currency: checkoutCurrency.toUpperCase(),
      })
      .select()
      .single();

    if (orderError || !order) {
      console.error('❌ Order insert error:', orderError?.message);
      return res.status(500).json({ error: 'Failed to create order record' });
    }

    console.log('✅ Order created:', order.id);

    // ── Create Stripe session with BOTH userId AND orderId ────────
    const session = await stripe.checkout.sessions.create({
      customer_email: userEmail,
      line_items: lineItems,
      mode: 'payment',
      success_url: `${process.env.FRONTEND_URL}/p/success/?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/p/cancel`,
      allow_promotion_codes: true,
      metadata: {
        userId,    // ← always set
        orderId: order.id, // ← always set
      },
    });

    console.log('✅ Stripe session created:', session.id);
    console.log('   Metadata sent to Stripe:', { userId, orderId: order.id });

    // ── Link session_id back to the order row ─────────────────────
    const { error: updateError } = await supabaseAdmin
      .from('orders')
      .update({ session_id: session.id })
      .eq('id', order.id);

    if (updateError) {
      console.error('⚠️ Failed to link session_id to order:', updateError.message);
      // Non-fatal — the webhook has fallbacks, but log it.
    } else {
      console.log('🔗 session_id linked to order row');
    }

    res.json({ url: session.url });

  } catch (err) {
    console.error('❌ Checkout error:', err.message, err.stack);
    res.status(500).json({ error: 'Checkout failed', message: err.message });
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

app.get('/api/user-location', async (req, res) => {
  try {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim()
      || req.headers['x-real-ip']
      || req.connection.remoteAddress;

    console.log('Client IP:', clientIp);

    const response = await fetch(`https://ipwhois.app/json/${clientIp}`);
    const data = await response.json();

    let rate = 1;
    if (data.currency_code && data.currency_code !== 'USD') {
      try {
        const currencyCode = data.currency_code.toLowerCase();
        const quoteResponse = await fetch('https://api.stripe.com/v1/fx_quotes', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${process.env.STRIPE_SECRET_KEY}`,
            'Stripe-Version': '2025-04-30.preview',
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            'to_currency': currencyCode,
            'from_currencies[]': 'usd',
            'lock_duration': 'none',
            'usage[type]': 'payment',
          }),
        });
        const quoteData = await quoteResponse.json();
        const rateInfo = quoteData?.rates?.usd;
        if (rateInfo?.exchange_rate) rate = rateInfo.exchange_rate;
      } catch (rateErr) {
        console.error('Stripe exchange rate error:', rateErr);
      }
    }

    res.json({
      currency: data.currency_code || 'USD',
      country_code: data.country_code || 'US',
      exchangeRate: rate
    });
  } catch (err) {
    console.error('Location detection error:', err);
    res.json({ currency: 'USD', country_code: 'US', exchangeRate: 1 });
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
      return res.status(403).json({ error: 'Not authorized' });
    }

    const { data: version, error: versionError } = await supabaseAdmin
      .from('asset_versions')
      .select('file_path')
      .eq('asset_id', assetId)
      .eq('id', versionId)
      .single();

    if (versionError || !version) {
      return res.status(404).json({ error: 'Version not found' });
    }

    let filePath = version.file_path;
    if (filePath.startsWith('/')) filePath = filePath.substring(1);
    if (filePath.startsWith('assets/')) filePath = filePath.substring(7);

    const { data: signedUrlData, error: signedUrlError } = await supabaseAdmin
      .storage
      .from('assets')
      .createSignedUrl(filePath, 3600, { download: true });

    if (signedUrlError || !signedUrlData?.signedUrl) {
      console.error('Signed URL error:', signedUrlError);
      return res.status(500).json({ error: 'Failed to generate download URL' });
    }

    await auditLog({
      user_id: req.userId,
      action: 'download',
      resource: 'asset',
      resource_id: assetId.toString(),
      status: 'success',
      details: { version_id: versionId, file_path: filePath }
    });

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

    await auditLog({
      user_id: req.userId, action: 'profile_update', resource: 'user', status: 'success',
    });

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
      pagination: { page, limit, total: count, pages: Math.ceil(count / limit) }
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

    if (error || !asset) return res.status(404).json({ error: 'Asset not found' });
    res.json(asset);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Debug endpoint ────────────────────────────────────────────────────────────

app.get('/api/debug/session/:sessionId', authenticateToken, async (req, res) => {
  const { sessionId } = req.params;

  console.log('\n🔍 Debug session lookup:', sessionId);

  const { data: order, error: orderErr } = await supabaseAdmin
    .from('orders')
    .select('*')
    .eq('session_id', sessionId)
    .maybeSingle();

  console.log('   DB order:', order || 'NOT FOUND', orderErr?.message || '');

  let stripeSession = null;
  let lineItems = null;
  try {
    stripeSession = await stripe.checkout.sessions.retrieve(sessionId, {
      expand: ['line_items']
    });
    lineItems = stripeSession.line_items?.data?.map(i => i.price?.id);
    console.log('   Stripe session status:', stripeSession.status, '| payment_status:', stripeSession.payment_status);
    console.log('   Stripe metadata:', JSON.stringify(stripeSession.metadata));
    console.log('   Line item price IDs:', lineItems);
  } catch (e) {
    console.error('   Stripe retrieve error:', e.message);
    stripeSession = { error: e.message };
  }

  let matchedAssets = null;
  if (lineItems?.length) {
    const { data: allAssets } = await supabaseAdmin
      .from('assets')
      .select('id, title, stripe_price_id, stripe_prices_multi');

    matchedAssets = lineItems.map(priceId => {
      const byDefault = allAssets?.find(a => a.stripe_price_id === priceId);
      const byMulti = allAssets?.find(a =>
        a.stripe_prices_multi && Object.values(a.stripe_prices_multi).includes(priceId)
      );
      return {
        price_id: priceId,
        matched_by_stripe_price_id: byDefault ?? null,
        matched_by_stripe_prices_multi: byMulti ?? null,
      };
    });
  }

  res.json({
    order,
    stripe_payment_status: stripeSession?.payment_status,
    stripe_status: stripeSession?.status,
    stripe_metadata: stripeSession?.metadata,
    line_item_price_ids: lineItems,
    asset_matches: matchedAssets,
  });
});

// ── Static files & SPA fallback ───────────────────────────────────────────────

app.use(express.static(path.join(__dirname, '..')));

app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// ── Error handler ─────────────────────────────────────────────────────────────

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

// ── Stripe sync ───────────────────────────────────────────────────────────────

async function syncAssetsWithStripe() {
  console.log('🔄 Starting Stripe synchronization...');

  const currencies = ['usd', 'eur', 'gbp', 'jpy', 'cad', 'aud', 'chf', 'sek', 'nok', 'dkk'];
  const exchangeRates = { 'usd': 1 };

  try {
    const fxBody = new URLSearchParams({ 'to_currency': 'usd', 'lock_duration': 'none', 'usage[type]': 'payment' });
    for (const c of currencies.filter(c => c !== 'usd')) {
      fxBody.append('from_currencies[]', c);
    }
    const fxRes = await fetch('https://api.stripe.com/v1/fx_quotes', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.STRIPE_SECRET_KEY}`,
        'Stripe-Version': '2025-04-30.preview',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: fxBody,
    });
    const fxData = await fxRes.json();
    for (const [fromCurrency, info] of Object.entries(fxData?.rates || {})) {
      exchangeRates[fromCurrency] = 1 / info.exchange_rate;
    }
    console.log('✅ Live FX rates fetched from Stripe FX Quotes API');
  } catch (fxErr) {
    console.error('⚠️ FX Quotes fetch failed, falling back to hardcoded rates:', fxErr.message);
    Object.assign(exchangeRates, { eur: 0.92, gbp: 0.79, jpy: 149.50, cad: 1.36, aud: 1.53, chf: 0.88, sek: 10.50, nok: 10.70, dkk: 6.86 });
  }

  try {
    const { data: assets, error } = await supabaseAdmin
      .from('assets')
      .select('id, title, description, price, stripe_product_id, stripe_price_id');

    if (error) {
      console.error('❌ Failed to fetch assets:', error);
      return;
    }

    let syncedCount = 0, createdCount = 0, updatedCount = 0, errorCount = 0;

    for (const asset of assets) {
      try {
        let productId = asset.stripe_product_id;
        let priceId = asset.stripe_price_id;
        let needsUpdate = false;

        if (productId) {
          try {
            await stripe.products.retrieve(productId);
          } catch (err) {
            if (err.code === 'resource_missing') {
              console.log(`⚠️ Product ${productId} not found in Stripe, creating new one...`);
              productId = null;
            } else {
              throw err;
            }
          }
        }

        if (!productId) {
          const product = await stripe.products.create({
            name: asset.title,
            description: asset.description || '',
            metadata: { asset_id: asset.id.toString() },
          });
          productId = product.id;
          needsUpdate = true;
          createdCount++;
          console.log(`✨ Created new product for asset ${asset.id}: ${productId}`);
        }

        const priceIds = {};

        for (const currency of currencies) {
          const rate = exchangeRates[currency];
          const amount = Math.round(asset.price * rate * 100);

          try {
            const existingPrices = await stripe.prices.list({ product: productId, currency, limit: 1 });

            if (existingPrices.data.length > 0) {
              const existingPrice = existingPrices.data[0];
              if (existingPrice.unit_amount === amount && existingPrice.active) {
                priceIds[currency] = existingPrice.id;
                continue;
              } else {
                await stripe.prices.update(existingPrice.id, { active: false });
              }
            }

            const price = await stripe.prices.create({
              product: productId,
              unit_amount: amount,
              currency,
              metadata: { asset_id: asset.id.toString() },
            });
            priceIds[currency] = price.id;
            updatedCount++;
            console.log(`✨ Created new price for asset ${asset.id} in ${currency.toUpperCase()}: ${price.id}`);
          } catch (err) {
            console.error(`❌ Error creating price for ${currency}:`, err.message);
            errorCount++;
          }
        }

        if (priceIds['usd']) {
          priceId = priceIds['usd'];
          needsUpdate = true;
        }

        if (needsUpdate) {
          const { error: updateError } = await supabaseAdmin
            .from('assets')
            .update({
              stripe_product_id: productId,
              stripe_price_id: priceId,
              stripe_prices_multi: priceIds
            })
            .eq('id', asset.id);

          if (updateError) {
            console.error(`❌ Failed to update asset ${asset.id}:`, updateError);
            errorCount++;
          } else {
            console.log(`✅ Updated asset ${asset.id} with Stripe IDs`);
          }
        }

        syncedCount++;
      } catch (err) {
        console.error(`❌ Error syncing asset ${asset.id}:`, err.message);
        errorCount++;
      }
    }

    console.log('\n📊 Synchronization Complete:');
    console.log(`   Total assets  : ${assets.length}`);
    console.log(`   Synced        : ${syncedCount}`);
    console.log(`   New products  : ${createdCount}`);
    console.log(`   Prices updated: ${updatedCount}`);
    console.log(`   Errors        : ${errorCount}\n`);

  } catch (err) {
    console.error('❌ Stripe sync failed:', err);
  }
}

// ── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌐 Frontend served from: src/`);
  console.log(`🎯 Webhook endpoint: http://localhost:${PORT}/api/stripe-webhook`);
  console.log(`📁 Static files directory: ${path.join(__dirname, '..')}\n`);

  // Run Stripe sync in the background — does NOT block the server from
  // accepting requests (including webhooks) while it runs.
  //setTimeout(() => {
  //   syncAssetsWithStripe().catch(err =>
  //   console.error('❌ Background Stripe sync failed:', err)
  //  );
  // }, 5000); // 5s head-start so the server is fully ready first
});