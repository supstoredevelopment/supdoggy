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

app.use((req, res, next) => {
  const host = req.headers.host || '';
  if (host === 'supdoggy.store' || host === 'www.supdoggy.store') {
    return res.redirect(301, `https://supstore.dev${req.originalUrl}`);
  }
  next();
});

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

const getPriceMultiValues = (field) => {
  if (!field) return [];
  try {
    const obj = typeof field === 'string' ? JSON.parse(field) : field;
    return Object.values(obj);
  } catch {
    return [];
  }
};

const auditLog = async (data) => {
  try {
    const { error } = await supabaseAdmin.from('audit_logs').insert(data);
    if (error) console.error('⚠️ Audit log insert error:', error.message, '| data:', JSON.stringify(data));
  } catch (err) {
    console.error('⚠️ Audit log exception:', err.message);
  }
};

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    } else {
      console.log('❌ Origin BLOCKED:', origin);
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

app.use(express.json({
  limit: '10kb',
  verify: (req, res, buf) => {
    if (req.path === '/api/stripe-webhook') {
      req.rawBody = buf;
    }
  }
}));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));


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

app.post('/api/stripe-webhook', async (req, res) => {
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🎯 Webhook POST received at', new Date().toISOString());

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

  const payload = req.rawBody || req.body;
  console.log('📦 Payload type:', typeof payload, '| isBuffer:', Buffer.isBuffer(payload), '| length:', payload?.length);

  let event;
  try {
    event = stripe.webhooks.constructEvent(payload, sig, webhookSecret);
    console.log('✅ Webhook signature verified | type:', event.type, '| id:', event.id);
  } catch (err) {
    console.error('❌ Webhook signature verification failed:', err.message);
    return res.status(400).json({ error: 'Invalid signature' });
  }

  try {
    if (event.type === 'checkout.session.completed') {
      let session;
      try {
        session = await stripe.checkout.sessions.retrieve(event.data.object.id, {
          expand: ['line_items'],
        });
      } catch (err) {
        console.error('❌ Could not re-verify session from Stripe:', err.message);
        return res.status(500).json({ error: 'Session verification failed' });
      }

      console.log('\n💳 checkout.session.completed | session:', session.id, '| payment_status:', session.payment_status);

      const isPaid = session.payment_status === 'paid';
      const isFree = session.payment_status === 'no_payment_required';
      const isUnpaid = session.payment_status === 'unpaid';

      if (isUnpaid) {
        console.warn('⚠️ Payment is UNPAID — cancelling order');

        const orderId = session.metadata?.orderId;
        if (orderId) {
          const { error } = await supabaseAdmin
            .from('orders')
            .update({ status: 'cancelled' })
            .eq('id', orderId)
            .eq('status', 'pending');
          if (error) console.error('❌ Failed to cancel unpaid order:', error.message);
        } else {
          const { error } = await supabaseAdmin
            .from('orders')
            .update({ status: 'cancelled' })
            .eq('session_id', session.id)
            .eq('status', 'pending');
          if (error) console.error('❌ Fallback cancel failed:', error.message);
        }

        await auditLog({
          action: 'payment_unpaid',
          resource: 'order',
          status: 'cancelled',
          details: { session_id: session.id, payment_status: session.payment_status },
        });

        return res.json({ received: true, note: 'Order cancelled — payment not completed' });
      }

      if (!isPaid && !isFree) {
        console.warn('⚠️ Unexpected payment_status:', session.payment_status, '— skipping');
        return res.json({ received: true, note: 'Payment not confirmed — skipped' });
      }

      let userId = session.metadata?.userId || null;
      let orderId = session.metadata?.orderId || null;

      console.log('🔍 metadata — userId:', userId || '[MISSING]', '| orderId:', orderId || '[MISSING]');

      if (!userId || !orderId) {
        const { data: fallbackOrder, error: fallbackErr } = await supabaseAdmin
          .from('orders')
          .select('id, user_id, status')
          .eq('session_id', session.id)
          .maybeSingle();

        if (fallbackErr) {
          console.error('❌ Fallback 1 DB error:', fallbackErr.message);
        } else if (fallbackOrder) {
          console.log('✅ Fallback 1 resolved — order:', fallbackOrder.id, '| user:', fallbackOrder.user_id);
          userId = userId || fallbackOrder.user_id;
          orderId = orderId || fallbackOrder.id;
        } else {
          console.warn('⚠️ Fallback 1: no order found for session_id:', session.id);
        }
      }

      if (!userId || !orderId) {
        const customerEmail = session.customer_email || session.customer_details?.email;
        if (customerEmail) {
          const { data: auditRows, error: auditErr } = await supabaseAdmin
            .from('audit_logs')
            .select('user_id, resource_id, details, created_at')
            .eq('action', 'checkout_initiated')
            .eq('status', 'pending')
            .order('created_at', { ascending: false })
            .limit(20);

          if (auditErr) {
            console.error('❌ Fallback 2 audit log query error:', auditErr.message);
          } else if (auditRows?.length) {
            const amountDollars = session.amount_total / 100;
            const match = auditRows.find(r => {
              const d = r.details || {};
              return (
                Math.abs((d.amount || 0) - amountDollars) < 0.01 &&
                (d.currency || '').toUpperCase() === (session.currency || '').toUpperCase()
              );
            });

            if (match) {
              console.log('✅ Fallback 2 matched via audit log — user_id:', match.user_id);
              userId = userId || match.user_id;
              orderId = orderId || match.resource_id;
            } else {
              console.warn('⚠️ Fallback 2: no matching audit log entry');
            }
          }
        } else {
          console.warn('⚠️ Fallback 2: no customer email on session');
        }
      }

      if (userId && !orderId) {
        const { data: newOrder, error: newOrderErr } = await supabaseAdmin
          .from('orders')
          .insert({
            user_id: userId,
            session_id: session.id,
            total_amount: (session.amount_total || 0) / 100,
            status: 'completed',
            payment_date: new Date().toISOString(),
            currency: (session.currency || 'USD').toUpperCase(),
          })
          .select('id')
          .single();

        if (newOrderErr) {
          if (newOrderErr.code === '23505') {
            const { data: dup } = await supabaseAdmin
              .from('orders')
              .select('id')
              .eq('session_id', session.id)
              .maybeSingle();
            if (dup) {
              orderId = dup.id;
              console.log('✅ Fallback 3: duplicate resolved — existing order id:', orderId);
            }
          } else {
            console.error('❌ Fallback 3: failed to create order:', newOrderErr.message);
          }
        } else {
          orderId = newOrder.id;
          console.log('✅ Fallback 3: order created from webhook:', orderId);
        }
      }

      if (!userId || !orderId) {
        console.error('❌ UNRESOLVABLE — could not determine userId or orderId after all fallbacks');
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
        return res.json({ received: true, warning: 'Order not found — logged for manual review' });
      }

      console.log('✅ Resolution complete — userId:', userId, '| orderId:', orderId);

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

      if (existingOrder.status === 'completed') {
        console.log('ℹ️ Order already completed — skipping (idempotent):', orderId);
        return res.json({ received: true, note: 'Already completed' });
      }

      const { error: updateError } = await supabaseAdmin
        .from('orders')
        .update({
          status: 'completed',
          payment_date: new Date().toISOString(),
          session_id: session.id,
        })
        .eq('id', orderId);

      if (updateError) {
        console.error('❌ Failed to update order status:', updateError.message);
        return res.status(500).json({ error: 'Order update failed' });
      }
      console.log('✅ Order marked as completed:', orderId);

      let lineItems = [];
      try {
        const lineItemsPage = await stripe.checkout.sessions.listLineItems(session.id, { limit: 100 });
        lineItems = lineItemsPage.data;
        console.log('📦 Line items fetched, count:', lineItems.length);
      } catch (err) {
        console.error('❌ Failed to fetch line items:', err.message);
        return res.status(500).json({ error: 'Failed to fetch line items' });
      }

      const { data: allAssets, error: assetsErr } = await supabaseAdmin
        .from('assets')
        .select('id, title, stripe_price_id, stripe_prices_multi');

      if (assetsErr) {
        console.error('❌ Failed to fetch assets for matching:', assetsErr.message);
        return res.status(500).json({ error: 'Failed to fetch assets' });
      }

      let grantedCount = 0;
      let skippedCount = 0;

      for (const lineItem of lineItems) {
        const priceId = lineItem.price?.id;
        console.log('\n   📦 Line item — price_id:', priceId, '| qty:', lineItem.quantity);

        if (!priceId) {
          console.warn('   ⚠️ Line item has no price id, skipping');
          skippedCount++;
          continue;
        }

        let asset = allAssets.find(a => a.stripe_price_id === priceId);
        if (!asset) {
          asset = allAssets.find(a => getPriceMultiValues(a.stripe_prices_multi).includes(priceId));
        }

        if (!asset) {
          console.warn('   ⚠️ No asset matched price_id:', priceId);
          skippedCount++;
          continue;
        }

        console.log('   🎯 Matched asset:', asset.id, '|', asset.title);

        const { error: upsertError } = await supabaseAdmin
          .from('user_assets')
          .upsert(
            {
              user_id: userId,
              asset_id: asset.id,
              purchased_at: new Date().toISOString(),
            },
            { onConflict: 'user_id,asset_id', ignoreDuplicates: true }
          );

        if (upsertError) {
          console.error('   ❌ Failed to upsert user_asset:', upsertError.message, '| code:', upsertError.code);
        } else {
          console.log('   ✅ user_assets upserted — user_id:', userId, '| asset_id:', asset.id);
          grantedCount++;
        }
      }

      if (grantedCount === 0 && lineItems.length === 0) {
        const { data: checkoutAudit, error: auditQueryErr } = await supabaseAdmin
          .from('audit_logs')
          .select('details')
          .eq('user_id', userId)
          .eq('action', 'checkout_initiated')
          .eq('status', 'pending')
          .order('created_at', { ascending: false })
          .limit(5);

        if (!auditQueryErr && checkoutAudit?.length) {
          const matchingLog = checkoutAudit.find(r => {
            const d = r.details || {};
            return d.session_id === session.id || d.order_id === orderId;
          }) || checkoutAudit[0];

          const assetIds = matchingLog?.details?.asset_ids;
          if (Array.isArray(assetIds) && assetIds.length > 0) {
            console.log('🔍 Fallback 4: found asset_ids in audit log:', assetIds);
            for (const assetId of assetIds) {
              const { error: upsertError } = await supabaseAdmin
                .from('user_assets')
                .upsert(
                  {
                    user_id: userId,
                    asset_id: assetId,
                    purchased_at: new Date().toISOString(),
                  },
                  { onConflict: 'user_id,asset_id', ignoreDuplicates: true }
                );

              if (upsertError) {
                console.error('   ❌ Fallback 4: failed to grant asset:', assetId, upsertError.message);
              } else {
                console.log('   ✅ Fallback 4: asset granted:', assetId);
                grantedCount++;
              }
            }
          } else {
            console.warn('⚠️ Fallback 4: audit log found but no asset_ids recorded');
          }
        } else {
          console.warn('⚠️ Fallback 4: no matching checkout_initiated audit log found');
        }
      }

      console.log('\n📊 Grant summary — granted:', grantedCount, '| skipped:', skippedCount);

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
          payment_status: session.payment_status,
          assets_granted: grantedCount,
          line_items_skipped: skippedCount,
        },
      });

      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    }

    if (event.type === 'checkout.session.expired') {
      const session = event.data.object;
      const orderId = session.metadata?.orderId;

      console.log('\n🚫 checkout.session.expired | session:', session.id, '| orderId:', orderId || '[MISSING]');

      if (orderId) {
        const { error } = await supabaseAdmin
          .from('orders')
          .update({ status: 'cancelled' })
          .eq('id', orderId)
          .eq('status', 'pending');
        if (error) console.error('❌ Failed to cancel order:', error.message);
        else console.log('✅ Order cancelled:', orderId);
      } else {
        const { error } = await supabaseAdmin
          .from('orders')
          .update({ status: 'cancelled' })
          .eq('session_id', session.id)
          .eq('status', 'pending');
        if (error) console.warn('⚠️ Fallback cancel failed:', error.message);
        else console.log('✅ Order cancelled via session_id fallback');
      }
    }

    if (event.type === 'charge.refunded') {
      const charge = event.data.object;
      const orderId = charge.metadata?.orderId;

      console.log('\n💸 charge.refunded | charge:', charge.id, '| orderId:', orderId || '[MISSING]');

      if (orderId) {
        const { error } = await supabaseAdmin
          .from('orders')
          .update({ status: 'refunded' })
          .eq('id', orderId);
        if (error) console.error('❌ Failed to mark order refunded:', error.message);
        else console.log('✅ Order marked as refunded:', orderId);
      } else {
        const paymentIntentId = charge.payment_intent;

        if (paymentIntentId) {
          const sessions = await stripe.checkout.sessions.list({
            payment_intent: paymentIntentId,
            limit: 1,
          });
          const relatedSession = sessions.data?.[0];

          if (relatedSession) {
            const { data: matchedOrder, error: matchErr } = await supabaseAdmin
              .from('orders')
              .select('id')
              .eq('session_id', relatedSession.id)
              .maybeSingle();

            if (matchErr) {
              console.error('❌ DB error looking up order by session_id:', matchErr.message);
            } else if (matchedOrder) {
              const { error: refundErr } = await supabaseAdmin
                .from('orders')
                .update({ status: 'refunded' })
                .eq('id', matchedOrder.id);
              if (refundErr) console.error('❌ Failed to mark matched order refunded:', refundErr.message);
              else console.log('✅ Order refunded via payment_intent lookup:', matchedOrder.id);
            } else {
              await auditLog({
                action: 'refund_unmatched',
                resource: 'charge',
                status: 'needs_review',
                details: { charge_id: charge.id, payment_intent: paymentIntentId, related_session_id: relatedSession.id },
              });
            }
          } else {
            await auditLog({
              action: 'refund_unmatched',
              resource: 'charge',
              status: 'needs_review',
              details: { charge_id: charge.id, payment_intent: paymentIntentId, reason: 'No matching checkout session' },
            });
          }
        }
      }
    }

    res.json({ received: true });
  } catch (err) {
    console.error('❌ Webhook processing error:', err.message, err.stack);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-hashes'", "https://cdnjs.cloudflare.com", "https://js.stripe.com", "https://cdn.jsdelivr.net"],
        scriptSrcAttr: ["'unsafe-inline'", "'unsafe-hashes'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
        imgSrc: ["'self'", "data:", "https:", "blob:"],
        connectSrc: ["'self'", "https://api.stripe.com", "https://api.emailjs.com", "https://api.exchangerate-api.com", process.env.SUPABASE_URL, process.env.FRONTEND_URL || "'self'", "http://localhost:3000", "http://localhost:3001"].filter(Boolean),
        frameSrc: ["'self'", "https://js.stripe.com", "https://hooks.stripe.com", "https://www.youtube.com", "https://youtube.com", "https://supstore.betteruptime.com"],
        childSrc: ["'self'", "https://www.youtube.com", "https://youtube.com"],
        mediaSrc: ["'self'", "https://www.youtube.com", "https://youtube.com", "https://*.googlevideo.com"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
      },
    },
  })
);

app.use(cookieParser(SESSION_SECRET));
app.use(cors(corsOptions));

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
  const id = parseInt(item.id);
  if (!Number.isInteger(id) || id < 1) throw new Error('Invalid item ID');
  if (!Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > 100) {
    throw new Error('Invalid quantity');
  }
  return { id, quantity: item.quantity };
};

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

app.post('/api/cancel-order', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.body;

    if (!sessionId || typeof sessionId !== 'string' || sessionId.length > 200) {
      return res.status(400).json({ error: 'Invalid session ID' });
    }

    console.log('\n🚫 /api/cancel-order | userId:', req.userId, '| sessionId:', sessionId);

    let stripeSession;
    try {
      stripeSession = await stripe.checkout.sessions.retrieve(sessionId);
    } catch (err) {
      console.error('❌ Could not retrieve Stripe session:', err.message);
      return res.status(400).json({ error: 'Invalid session' });
    }

    if (stripeSession.payment_status === 'paid') {
      return res.status(400).json({ error: 'Session is already paid — order will not be cancelled' });
    }

    const { data: updatedBySession, error: sessionErr } = await supabaseAdmin
      .from('orders')
      .update({ status: 'cancelled' })
      .eq('session_id', sessionId)
      .eq('user_id', req.userId)
      .eq('status', 'pending')
      .select('id')
      .maybeSingle();

    if (sessionErr) {
      console.error('❌ DB error cancelling by session_id:', sessionErr.message);
      return res.status(500).json({ error: 'DB error' });
    }

    if (updatedBySession) {
      console.log('✅ Order cancelled by session_id:', updatedBySession.id);
      await auditLog({
        user_id: req.userId,
        action: 'order_cancelled',
        resource: 'order',
        resource_id: updatedBySession.id,
        status: 'cancelled',
        details: { session_id: sessionId, method: 'cancel_page' },
      });
      return res.json({ cancelled: true, orderId: updatedBySession.id });
    }

    const orderId = stripeSession.metadata?.orderId;
    if (orderId) {
      const { data: updatedByOrder, error: orderErr } = await supabaseAdmin
        .from('orders')
        .update({ status: 'cancelled' })
        .eq('id', orderId)
        .eq('user_id', req.userId)
        .eq('status', 'pending')
        .select('id')
        .maybeSingle();

      if (orderErr) {
        console.error('❌ DB error cancelling by orderId:', orderErr.message);
        return res.status(500).json({ error: 'DB error' });
      }

      if (updatedByOrder) {
        console.log('✅ Order cancelled by Stripe metadata orderId:', updatedByOrder.id);
        await auditLog({
          user_id: req.userId,
          action: 'order_cancelled',
          resource: 'order',
          resource_id: updatedByOrder.id,
          status: 'cancelled',
          details: { session_id: sessionId, method: 'cancel_page_metadata_fallback' },
        });
        return res.json({ cancelled: true, orderId: updatedByOrder.id });
      }
    }

    res.json({ cancelled: false, note: 'No pending order found' });

  } catch (err) {
    console.error('❌ /api/cancel-order error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/resolve-session', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.body;

    if (!sessionId || typeof sessionId !== 'string' || sessionId.length > 200) {
      return res.status(400).json({ error: 'Invalid session ID' });
    }

    let stripeSession;
    try {
      stripeSession = await stripe.checkout.sessions.retrieve(sessionId);
    } catch (err) {
      return res.status(400).json({ error: 'Invalid session ID' });
    }

    const paymentStatus = stripeSession.payment_status;
    const orderId = stripeSession.metadata?.orderId;

    console.log(`\n🔄 /api/resolve-session | session: ${sessionId} | payment_status: ${paymentStatus} | orderId: ${orderId}`);

    if (!orderId) {
      const { data: order } = await supabaseAdmin
        .from('orders')
        .select('id, status')
        .eq('session_id', sessionId)
        .eq('user_id', req.userId)
        .maybeSingle();

      if (!order) {
        return res.json({ resolved: false, note: 'No order found' });
      }

      return resolveOrder(res, order, paymentStatus, sessionId, req.userId);
    }

    const { data: order } = await supabaseAdmin
      .from('orders')
      .select('id, status')
      .eq('id', orderId)
      .eq('user_id', req.userId)
      .maybeSingle();

    if (!order) {
      return res.json({ resolved: false, note: 'Order not found for this user' });
    }

    return resolveOrder(res, order, paymentStatus, sessionId, req.userId);

  } catch (err) {
    console.error('❌ /api/resolve-session error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

async function resolveOrder(res, order, paymentStatus, sessionId, userId) {
  if (order.status === 'completed' && (paymentStatus === 'paid' || paymentStatus === 'no_payment_required')) {
    return res.json({ resolved: true, status: 'completed' });
  }

  const newStatus = (paymentStatus === 'paid' || paymentStatus === 'no_payment_required')
    ? 'completed'
    : 'cancelled';

  if (order.status === newStatus) {
    return res.json({ resolved: true, status: newStatus });
  }

  const { error } = await supabaseAdmin
    .from('orders')
    .update({ status: newStatus, ...(newStatus === 'completed' ? { payment_date: new Date().toISOString() } : {}) })
    .eq('id', order.id);

  if (error) {
    console.error('❌ resolve-session update failed:', error.message);
    return res.status(500).json({ error: 'DB update failed' });
  }

  await auditLog({
    user_id: userId,
    action: newStatus === 'completed' ? 'payment' : 'order_cancelled',
    resource: 'order',
    resource_id: order.id,
    status: newStatus,
    details: { session_id: sessionId, payment_status: paymentStatus, resolved_by: 'resolve-session' },
  });

  console.log(`✅ Order ${order.id} resolved to: ${newStatus}`);
  return res.json({ resolved: true, status: newStatus });
}

app.get('/api/session-assets/:sessionId', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params;
    if (!sessionId || typeof sessionId !== 'string' || sessionId.length > 200) {
      return res.status(400).json({ error: 'Invalid session ID' });
    }

    const { data: order, error: orderErr } = await supabaseAdmin
      .from('orders')
      .select('id, status')
      .eq('session_id', sessionId)
      .eq('user_id', req.userId)
      .maybeSingle();

    if (orderErr || !order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    if (order.status !== 'completed') {
      return res.json({ ready: false, assets: [] });
    }

    let lineItems = [];
    try {
      const page = await stripe.checkout.sessions.listLineItems(sessionId, { limit: 100 });
      lineItems = page.data;
    } catch (err) {
      return res.status(500).json({ error: 'Failed to fetch session line items' });
    }

    const priceIds = lineItems.map(li => li.price?.id).filter(Boolean);

    if (priceIds.length === 0) {
      return res.json({ ready: true, assets: [] });
    }

    const { data: allAssets, error: assetsErr } = await supabaseAdmin
      .from('assets')
      .select('id, title, stripe_price_id, stripe_prices_multi');

    if (assetsErr) return res.status(500).json({ error: 'Failed to fetch assets' });

    const matchedAssetIds = [];
    for (const priceId of priceIds) {
      const asset = allAssets.find(a => a.stripe_price_id === priceId) ||
        allAssets.find(a => getPriceMultiValues(a.stripe_prices_multi).includes(priceId));
      if (asset) matchedAssetIds.push(asset.id);
    }

    const { data: ownedAssets, error: ownedErr } = await supabaseAdmin
      .from('user_assets')
      .select('asset_id, assets(id, title, image_url, tag)')
      .eq('user_id', req.userId)
      .in('asset_id', matchedAssetIds);

    if (ownedErr) return res.status(500).json({ error: 'Failed to verify ownership' });

    const assets = ownedAssets.map(r => r.assets).filter(Boolean);
    return res.json({ ready: true, assets });

  } catch (err) {
    console.error('❌ /api/session-assets error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

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

async function getTestingConfig() {
  try {
    const { data, error } = await supabaseAdmin
      .from('config')
      .select('key, value')
      .in('key', ['testing_mode', 'locked']);
    if (error || !data) return { enabled: false, locked: false };
    const cfg = Object.fromEntries(data.map(r => [r.key, r.value]));
    return {
      enabled: cfg.testing_mode === true || cfg.testing_mode === 'true',
      locked: cfg.locked === true || cfg.locked === 'true',
    };
  } catch {
    return { enabled: false, locked: false };
  }
}

async function isTestingModeEnabled() {
  return (await getTestingConfig()).enabled;
}

app.get('/api/testing-mode', async (req, res) => {
  const config = await getTestingConfig();
  res.json(config);
});


async function getValidStripePriceId(asset, currency, productId) {
  const multi = typeof asset.stripe_prices_multi === 'string'
    ? JSON.parse(asset.stripe_prices_multi)
    : (asset.stripe_prices_multi || {});

  const priceId = multi[currency] || multi['usd'];

  if (priceId) {
    try {
      const price = await stripe.prices.retrieve(priceId);
      if (price.active) return priceId;
      console.warn(`⚠️ Price ${priceId} is inactive — will recreate`);
    } catch (err) {
      console.warn(`⚠️ Price ${priceId} not found in Stripe — will recreate`);
    }
  } else {
    console.warn(`⚠️ No price ID found for asset ${asset.id} in ${currency} — will create`);
  }

  // Verify product exists, recreate if not
  let validProductId = productId;
  if (validProductId) {
    try {
      await stripe.products.retrieve(validProductId);
    } catch (err) {
      console.warn(`⚠️ Product ${validProductId} not found in Stripe — will recreate`);
      validProductId = null;
    }
  }

  if (!validProductId) {
    const product = await stripe.products.create({
      name: asset.title,
      ...(asset.description ? { description: asset.description } : {}),
      metadata: { asset_id: asset.id.toString() },
    });
    validProductId = product.id;
    await supabaseAdmin.from('assets').update({
      stripe_product_id: validProductId,
    }).eq('id', asset.id);
    console.log(`✅ Recreated product for asset ${asset.id}: ${validProductId}`);
  }

  const rate = await getExchangeRate(currency);
  const amount = Math.round((asset.price / 2) * rate * 100);

  const newPrice = await stripe.prices.create({
    product: validProductId,
    unit_amount: amount,
    currency,
    metadata: { asset_id: asset.id.toString() },
  });

  const updatedMulti = { ...multi, [currency]: newPrice.id };
  await supabaseAdmin.from('assets').update({
    stripe_prices_multi: updatedMulti,
    ...(currency === 'usd' ? { stripe_price_id: newPrice.id } : {}),
  }).eq('id', asset.id);

  console.log(`✅ Created price for asset ${asset.id} in ${currency}: ${newPrice.id} (amount: ${amount})`);
  return newPrice.id;
}

async function getExchangeRate(currency) {
  if (currency === 'usd') return 1;
  try {
    const res = await fetch('https://api.stripe.com/v1/fx_quotes', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.STRIPE_SECRET_KEY}`,
        'Stripe-Version': '2025-04-30.preview',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        'to_currency': currency,
        'from_currencies[]': 'usd',
        'lock_duration': 'none',
        'usage[type]': 'payment',
      }),
    });
    const data = await res.json();
    return data?.rates?.usd?.exchange_rate || 1;
  } catch {
    const fallback = { eur: 0.92, gbp: 0.79, jpy: 149.50, cad: 1.36, aud: 1.53, chf: 0.88, sek: 10.50, nok: 10.70, dkk: 6.86 };
    return fallback[currency] || 1;
  }
}

app.post('/api/create-test-checkout', checkoutLimiter, authenticateToken, async (req, res) => {
  try {
    const testingEnabled = await isTestingModeEnabled();
    if (!testingEnabled) {
      return res.status(403).json({ error: 'Testing mode is not enabled' });
    }

    const { cart, currency } = req.body;
    const userId = req.userId;

    if (!Array.isArray(cart) || cart.length === 0 || cart.length > 100) {
      return res.status(400).json({ error: 'Invalid cart' });
    }

    const validatedCart = cart.map(validateCartItem);

    const { data: products, error: productsError } = await supabase
      .from('assets')
      .select('id, title, price')
      .in('id', validatedCart.map(item => item.id));

    if (productsError || !products) {
      return res.status(400).json({ error: 'Failed to fetch products' });
    }

    const productMap = new Map(products.map(p => [p.id, p]));
    let totalAmount = 0;
    const grantedAssets = [];

    for (const item of validatedCart) {
      const product = productMap.get(item.id);
      if (!product) return res.status(400).json({ error: `Product ${item.id} not found` });
      totalAmount += (product.price || 0) * item.quantity;

      const { error: upsertError } = await supabaseAdmin
        .from('user_assets')
        .upsert(
          {
            user_id: userId,
            asset_id: product.id,
            purchased_at: new Date().toISOString(),
          },
          { onConflict: 'user_id,asset_id', ignoreDuplicates: true }
        );

      if (upsertError) {
        console.error('❌ [TEST] Failed to grant asset:', product.id, upsertError.message);
        return res.status(500).json({ error: 'Failed to grant test asset' });
      }

      grantedAssets.push(product.id);
    }

    const testSessionId = `test_${crypto.randomUUID()}`;

    const { error: orderErr } = await supabaseAdmin.from('orders').insert({
      user_id: userId,
      session_id: testSessionId,
      total_amount: Math.round(totalAmount * 100) / 100,
      status: 'completed',
      payment_date: new Date().toISOString(),
      currency: (currency || 'USD').toUpperCase(),
    });

    if (orderErr) console.error('⚠️ [TEST] Failed to log test order:', orderErr.message);

    await auditLog({
      user_id: userId,
      action: 'test_purchase',
      resource: 'order',
      status: 'completed',
      details: {
        session_id: testSessionId,
        assets_granted: grantedAssets.length,
        amount: totalAmount,
        currency: (currency || 'USD').toUpperCase(),
        type: 'test',
      },
    });

    console.log('🧪 [TEST] Mock purchase complete — session:', testSessionId, '| assets:', grantedAssets);

    return res.json({ free: true, url: `${process.env.FRONTEND_URL}/p/success/?free=true&test=true` });
  } catch (err) {
    console.error('❌ [TEST] Test checkout error:', err.message);
    res.status(500).json({ error: 'Test checkout failed' });
  }
});

app.post('/api/create-checkout-session', checkoutLimiter, authenticateToken, async (req, res) => {
  try {
    console.log('\n🛒 Checkout | userId:', req.userId, '| email:', req.user.email, '| cart:', JSON.stringify(req.body.cart), '| currency:', req.body.currency);

    if (await isTestingModeEnabled()) {
      console.log('🧪 Testing mode ON — routing to mock checkout');
      const { cart: tCart, currency: tCurrency } = req.body;
      if (!Array.isArray(tCart) || tCart.length === 0 || tCart.length > 100) {
        return res.status(400).json({ error: 'Invalid cart' });
      }
      const validatedTestCart = tCart.map(validateCartItem);
      const { data: testProducts, error: testProductsError } = await supabase
        .from('assets')
        .select('id, title, price')
        .in('id', validatedTestCart.map(item => item.id));
      if (testProductsError || !testProducts) {
        return res.status(400).json({ error: 'Failed to fetch products' });
      }
      const testProductMap = new Map(testProducts.map(p => [p.id, p]));
      let testTotal = 0;
      for (const item of validatedTestCart) {
        const product = testProductMap.get(item.id);
        if (!product) return res.status(400).json({ error: `Product ${item.id} not found` });
        testTotal += (product.price || 0) * item.quantity;
        const { error: upsertError } = await supabaseAdmin.from('user_assets').upsert(
          {
            user_id: req.userId,
            asset_id: product.id,
            purchased_at: new Date().toISOString(),
          },
          { onConflict: 'user_id,asset_id', ignoreDuplicates: true }
        );
        if (upsertError) {
          return res.status(500).json({ error: 'Failed to grant test asset' });
        }
      }
      const testSessionId = `test_${crypto.randomUUID()}`;
      await supabaseAdmin.from('orders').insert({
        user_id: req.userId,
        session_id: testSessionId,
        total_amount: Math.round(testTotal * 100) / 100,
        status: 'completed',
        payment_date: new Date().toISOString(),
        currency: (tCurrency || 'USD').toUpperCase(),
      });
      await auditLog({
        user_id: req.userId,
        action: 'test_purchase',
        resource: 'order',
        status: 'completed',
        details: { session_id: testSessionId, amount: testTotal, type: 'test' },
      });
      console.log('🧪 [TEST] Mock purchase complete — session:', testSessionId);
      return res.json({ free: true, url: `${process.env.FRONTEND_URL}/p/success/?free=true&test=true` });
    }

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

    const productMap = new Map(products.map(p => [p.id, p]));

    const { data: alreadyOwned, error: ownershipErr } = await supabaseAdmin
      .from('user_assets')
      .select('asset_id')
      .eq('user_id', userId)
      .in('asset_id', validatedCart.map(i => i.id));

    if (ownershipErr) {
      console.error('❌ Failed to check ownership:', ownershipErr.message);
      return res.status(500).json({ error: 'Failed to verify ownership' });
    }

    const ownedSet = new Set((alreadyOwned || []).map(r => String(r.asset_id)));

    const freeItems = [];
    const paidItems = [];

    for (const item of validatedCart) {
      const product = productMap.get(item.id);
      if (!product) return res.status(400).json({ error: `Product ${item.id} not found` });

      if (ownedSet.has(String(product.id))) {
        console.log(`ℹ️ Skipping already-owned asset ${product.id} (${product.title})`);
        continue;
      }

      if (!product.price || product.price === 0) {
        freeItems.push({ item, product });
      } else {
        paidItems.push({ item, product });
      }
    }

    if (freeItems.length === 0 && paidItems.length === 0) {
      return res.json({ free: true, url: `${process.env.FRONTEND_URL}/p/success/?free=true&already_owned=true` });
    }

    const grantedFreeAssets = [];
    for (const { product } of freeItems) {
      const { error: upsertError } = await supabaseAdmin
        .from('user_assets')
        .upsert(
          {
            user_id: userId,
            asset_id: product.id,
            purchased_at: new Date().toISOString(),
          },
          { onConflict: 'user_id,asset_id', ignoreDuplicates: true }
        );

      if (upsertError) {
        console.error('❌ Failed to upsert free asset:', product.id, '|', upsertError.message);
        return res.status(500).json({ error: 'Failed to grant free asset' });
      }

      console.log(`✅ Free asset upserted — user_id: ${userId} | asset_id: ${product.id}`);
      grantedFreeAssets.push(product.id);
    }

    if (paidItems.length === 0) {
      const freeSessionId = `free_${crypto.randomUUID()}`;

      const { error: orderErr } = await supabaseAdmin.from('orders').insert({
        user_id: userId,
        session_id: freeSessionId,
        total_amount: 0,
        status: 'completed',
        payment_date: new Date().toISOString(),
        currency: (currency || 'USD').toUpperCase(),
      });
      if (orderErr) console.error('⚠️ Failed to log free order:', orderErr.message);

      await auditLog({
        user_id: userId,
        action: 'payment',
        resource: 'order',
        status: 'completed',
        details: {
          amount: 0,
          currency: (currency || 'USD').toUpperCase(),
          assets_granted: grantedFreeAssets.length,
          asset_ids: grantedFreeAssets,
          type: 'free',
        },
      });

      return res.json({ free: true, url: `${process.env.FRONTEND_URL}/p/success/?free=true` });
    }

    const lineItems = [];
    let totalAmount = 0;
    const checkoutCurrency = (currency || 'usd').toLowerCase();
    const paidAssetIds = [];

    for (const { item, product } of paidItems) {
      let stripePriceId;

      if (product.stripe_prices_multi) {
        const multi = typeof product.stripe_prices_multi === 'string'
          ? JSON.parse(product.stripe_prices_multi)
          : product.stripe_prices_multi;
        stripePriceId = await getValidStripePriceId(product, checkoutCurrency, product.stripe_product_id);
      }

      if (!stripePriceId) {
        return res.status(400).json({ error: `Product ${item.id} has no Stripe price configured` });
      }

      lineItems.push({ price: stripePriceId, quantity: item.quantity });
      totalAmount += (product.price / 2) * item.quantity;  // was product.price * item.quantity
      paidAssetIds.push(product.id);
    }

    let stripeSession;
    try {
      stripeSession = await stripe.checkout.sessions.create({
        customer_email: userEmail,
        line_items: lineItems,
        mode: 'payment',
        success_url: `${process.env.FRONTEND_URL}/p/success/?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.FRONTEND_URL}/p/cancel/?session_id={CHECKOUT_SESSION_ID}`,
        allow_promotion_codes: true,
        metadata: { userId },
      });
      console.log('✅ Stripe session created:', stripeSession.id);
    } catch (stripeErr) {
      console.error('❌ Stripe session creation failed:', stripeErr.message);
      return res.status(500).json({ error: 'Failed to create payment session', message: stripeErr.message });
    }

    const { data: order, error: orderError } = await supabaseAdmin
      .from('orders')
      .insert({
        user_id: userId,
        session_id: stripeSession.id,
        total_amount: Math.round(totalAmount * 100) / 100,
        status: 'pending',
        currency: checkoutCurrency.toUpperCase(),
      })
      .select()
      .single();

    if (orderError || !order) {
      console.error('❌ Order insert error:', orderError?.message);
      await auditLog({
        user_id: userId,
        action: 'checkout_initiated',
        resource: 'order',
        status: 'pending',
        details: {
          session_id: stripeSession.id,
          amount: Math.round(totalAmount * 100) / 100,
          currency: checkoutCurrency.toUpperCase(),
          asset_ids: paidAssetIds,
          error: orderError?.message,
          note: 'Order row insert failed — Stripe session still active',
        },
      });
      return res.json({ url: stripeSession.url });
    }

    console.log('✅ Order created:', order.id, '| session:', stripeSession.id);

    try {
      await stripe.checkout.sessions.update(stripeSession.id, {
        metadata: { userId, orderId: order.id },
      });
      console.log('🔗 Stripe metadata updated with orderId:', order.id);
    } catch (metaErr) {
      console.warn('⚠️ Could not patch Stripe metadata with orderId:', metaErr.message);
    }

    await auditLog({
      user_id: userId,
      action: 'checkout_initiated',
      resource: 'order',
      resource_id: order.id,
      status: 'pending',
      details: {
        session_id: stripeSession.id,
        order_id: order.id,
        amount: Math.round(totalAmount * 100) / 100,
        currency: checkoutCurrency.toUpperCase(),
        asset_ids: paidAssetIds,
      },
    });

    res.json({ url: stripeSession.url });

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

app.get('/api/user/purchases', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('user_assets')
      .select('asset_id')
      .eq('user_id', req.userId);

    if (error) return res.status(500).json({ error: 'Failed to fetch purchases' });
    res.json(data.map(d => String(d.asset_id)));
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/user-location', async (req, res) => {
  try {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim()
      || req.headers['x-real-ip']
      || req.connection.remoteAddress;

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

    res.json(data.map(d => d.assets));
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
      .select('id, version, created_at, release_notes, file_path, files')
      .eq('asset_id', assetId)
      .order('created_at', { ascending: false });

    if (error) return res.status(500).json({ error: 'Failed to fetch versions' });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/assets/review-aggregates', async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('asset_reviews')
      .select('asset_id, stars');

    if (error) return res.status(500).json({ error: 'Failed to fetch reviews' });

    const map = {};
    for (const row of data) {
      if (!map[row.asset_id]) map[row.asset_id] = { sum: 0, count: 0 };
      map[row.asset_id].sum += row.stars;
      map[row.asset_id].count += 1;
    }

    const result = {};
    for (const [id, val] of Object.entries(map)) {
      result[id] = {
        score: Math.round((val.sum / val.count) * 10) / 10,
        count: val.count,
      };
    }

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/assets/:id/reviews', async (req, res) => {
  try {
    const assetId = parseInt(req.params.id);
    if (!Number.isInteger(assetId) || assetId < 1) {
      return res.status(400).json({ error: 'Invalid asset ID' });
    }

    const { data: reviews, error } = await supabaseAdmin
      .from('asset_reviews')
      .select('id, stars, review_text, reviewer_name, created_at, user_id')
      .eq('asset_id', assetId)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Failed to fetch reviews:', error.message);
      return res.status(500).json({ error: 'Failed to fetch reviews' });
    }

    let userAlreadyReviewed = false;
    try {
      let token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) token = req.cookies.jwt;
      if (token) {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        userAlreadyReviewed = reviews.some(r => r.user_id === decoded.userId);
      }
    } catch (_) { }

    const safeReviews = reviews.map(({ user_id, ...rest }) => rest);
    res.json({ reviews: safeReviews, user_already_reviewed: userAlreadyReviewed });
  } catch (err) {
    console.error('GET reviews error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

const reviewLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: 'Too many reviews submitted, please try again later',
});

app.post('/api/assets/:id/reviews', reviewLimiter, authenticateToken, async (req, res) => {
  try {
    const assetId = parseInt(req.params.id);
    if (!Number.isInteger(assetId) || assetId < 1) {
      return res.status(400).json({ error: 'Invalid asset ID' });
    }

    const { stars, review_text } = req.body;

    const starsInt = parseInt(stars);
    if (!Number.isInteger(starsInt) || starsInt < 1 || starsInt > 5) {
      return res.status(400).json({ error: 'Stars must be between 1 and 5' });
    }

    if (!review_text || typeof review_text !== 'string') {
      return res.status(400).json({ error: 'Review text is required' });
    }
    const trimmedText = validator.trim(review_text);
    if (!validator.isLength(trimmedText, { min: 10, max: 2000 })) {
      return res.status(400).json({ error: 'Review must be between 10 and 2000 characters' });
    }

    const { count, error: purchaseErr } = await supabaseAdmin
      .from('user_assets')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', req.userId)
      .eq('asset_id', assetId);

    if (purchaseErr) {
      console.error('Purchase check error:', purchaseErr.message);
      return res.status(500).json({ error: 'Could not verify purchase' });
    }

    if (count === 0) {
      return res.status(403).json({ error: 'You must purchase this asset before reviewing it' });
    }

    const reviewerName = req.user.user_metadata?.full_name
      || req.user.email?.split('@')[0]
      || 'Verified Buyer';

    const { data: review, error: insertErr } = await supabaseAdmin
      .from('asset_reviews')
      .insert({
        asset_id: assetId,
        user_id: req.userId,
        reviewer_name: reviewerName,
        stars: starsInt,
        review_text: trimmedText,
      })
      .select('id, stars, review_text, reviewer_name, created_at')
      .single();

    if (insertErr) {
      if (insertErr.code === '23505') {
        return res.status(409).json({ error: 'You have already reviewed this asset' });
      }
      console.error('Review insert error:', insertErr.message);
      return res.status(500).json({ error: 'Failed to save review' });
    }

    await auditLog({
      user_id: req.userId,
      action: 'review_submitted',
      resource: 'asset',
      resource_id: String(assetId),
      status: 'success',
      details: { stars: starsInt, review_id: review.id },
    });

    res.status(201).json({ review });
  } catch (err) {
    console.error('POST review error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/download/:assetId/:versionId', authenticateToken, async (req, res) => {
  try {
    const assetId = parseInt(req.params.assetId);
    const versionId = parseInt(req.params.versionId);
    const requestedFile = req.query.file;

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
      .select('file_path, files')
      .eq('asset_id', assetId)
      .eq('id', versionId)
      .single();

    if (versionError || !version) {
      return res.status(404).json({ error: 'Version not found' });
    }

    let filePath;

    if (requestedFile && Array.isArray(version.files) && version.files.length > 0) {
      const fileEntry = version.files.find(f => f.name === requestedFile);
      if (!fileEntry) return res.status(404).json({ error: 'File not found in version' });
      filePath = fileEntry.path;
    } else {
      filePath = version.file_path;
    }

    if (!filePath) return res.status(404).json({ error: 'No file path found' });

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
      details: { version_id: versionId, file_path: filePath, file_name: requestedFile || null }
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
      .select('id, title, description, price, image_url, tag, is_top_selling, author', { count: 'exact' })
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
      .select('id, title, description, price, image_url, tag, is_top_selling, created_at, updated_at, author, video_url, extra_images')
      .eq('id', id)
      .single();

    if (error || !asset) return res.status(404).json({ error: 'Asset not found' });
    res.json(asset);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/debug/session/:sessionId', authenticateToken, async (req, res) => {
  const { sessionId } = req.params;

  const { data: order, error: orderErr } = await supabaseAdmin
    .from('orders')
    .select('*')
    .eq('session_id', sessionId)
    .maybeSingle();

  let stripeSession = null;
  let lineItems = null;
  try {
    stripeSession = await stripe.checkout.sessions.retrieve(sessionId, { expand: ['line_items'] });
    lineItems = stripeSession.line_items?.data?.map(i => i.price?.id);
  } catch (e) {
    stripeSession = { error: e.message };
  }

  let matchedAssets = null;
  if (lineItems?.length) {
    const { data: allAssets } = await supabaseAdmin
      .from('assets')
      .select('id, title, stripe_price_id, stripe_prices_multi');

    matchedAssets = lineItems.map(priceId => ({
      price_id: priceId,
      matched_by_stripe_price_id: allAssets?.find(a => a.stripe_price_id === priceId) ?? null,
      matched_by_stripe_prices_multi: allAssets?.find(a => getPriceMultiValues(a.stripe_prices_multi).includes(priceId)) ?? null,
    }));
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
    console.log('✅ Live FX rates fetched from Stripe');
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
              productId = null;
            } else {
              throw err;
            }
          }
        }

        if (!productId) {
          const product = await stripe.products.create({
            name: asset.title,
            ...(asset.description ? { description: asset.description } : {}),
            metadata: { asset_id: asset.id.toString() },
          });
          productId = product.id;
          needsUpdate = true;
          createdCount++;
          console.log(`✨ Created product for asset ${asset.id}: ${productId}`);
        }

        const priceIds = {};

        for (const currency of currencies) {
          const rate = exchangeRates[currency];
          const amount = Math.round((asset.price / 2) * rate * 100);

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
            console.log(`✨ Created price for asset ${asset.id} in ${currency.toUpperCase()}: ${price.id}`);
          } catch (err) {
            console.error(`❌ Error creating price for ${currency}:`, err.message);
            errorCount++;
          }
        }

        const hasNewPrices = Object.keys(priceIds).length > 0;
        if (priceIds['usd']) priceId = priceIds['usd'];

        const { error: updateError } = await supabaseAdmin.from('assets').update({
          stripe_product_id: productId,
          stripe_price_id: priceId,
          stripe_prices_multi: priceIds
        }).eq('id', asset.id);

        if (updateError) {
          console.error(`❌ Failed to update asset ${asset.id}:`, updateError);
          errorCount++;
        } else {
          console.log(`✅ Updrated asset ${asset.id} with Stripe IDs`);
        }

        syncedCount++;
      } catch (err) {
        console.error(`❌ Error syncing asset ${asset.id}:`, err.message);
        errorCount++;
      }
    }

    console.log(`\n📊 Sync complete — total: ${assets.length} | synced: ${syncedCount} | new products: ${createdCount} | prices updated: ${updatedCount} | errors: ${errorCount}\n`);

  } catch (err) {
    console.error('❌ Stripe sync failed:', err);
  }
}

const ROBUX_PER_USD = parseFloat(process.env.ROBUX_PER_USD || '80');


// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Resolve a Roblox username → userId via Roblox API.
 */
async function resolveRobloxUserId(username) {
  const res = await fetch('https://users.roblox.com/v1/usernames/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usernames: [username], excludeBannedUsers: true }),
  });
  if (!res.ok) throw new Error('Roblox user lookup failed');
  const data = await res.json();
  if (!data.data || data.data.length === 0) throw new Error('Roblox user not found');
  return { userId: data.data[0].id, displayName: data.data[0].displayName };
}

const ROBLOX_API_KEY = process.env.ROBLOX_API_KEY;
const ROBLOX_UNIVERSE_ID = process.env.ROBLOX_UNIVERSE_ID;

// Shared headers for all Open Cloud calls
function openCloudHeaders() {
  return {
    'Content-Type': 'application/json',
    'x-api-key': ROBLOX_API_KEY,
  };
}

async function createRobloxGamepass(name, description, robuxPrice) {
  const form = new FormData();
  form.append('name', name);
  form.append('description', description);
  form.append('price', robuxPrice.toString());
  form.append('isForSale', 'true');

  const res = await fetch(
    `https://apis.roblox.com/game-passes/v1/universes/${ROBLOX_UNIVERSE_ID}/game-passes`,
    {
      method: 'POST',
      headers: {
        'x-api-key': ROBLOX_API_KEY,
        // NO Content-Type here — fetch sets it automatically with the correct boundary
      },
      body: form,
    }
  );

  const text = await res.text();
  console.log('Roblox gamepass create response:', res.status, text);

  if (!res.ok) {
    throw new Error(`Failed to create Roblox gamepass: ${res.status} — ${text}`);
  }

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Roblox returned non-JSON: ${text}`);
  }

  const gamepassId = data.gamePassId;
  if (!gamepassId) throw new Error(`No gamepass ID in response: ${JSON.stringify(data)}`);

  return {
    gamepassId,
    gamepassUrl: `https://www.roblox.com/game-pass/${gamepassId}`,
  };
}

async function deactivateGamepass(gamepassId) {
  try {
    const form = new FormData();
    form.append('isForSale', 'false');

    const res = await fetch(
      `https://apis.roblox.com/game-passes/v1/universes/${ROBLOX_UNIVERSE_ID}/game-passes/${gamepassId}`,
      {
        method: 'PATCH',
        headers: {
          'x-api-key': ROBLOX_API_KEY,
        },
        body: form,
      }
    );

    if (!res.ok) {
      const text = await res.text();
      console.warn('⚠️ Gamepass deactivation failed:', text);
    } else {
      console.log('✅ Gamepass deactivated:', gamepassId);
    }
  } catch (err) {
    console.warn('⚠️ Could not deactivate gamepass:', err.message);
  }
}

async function checkGamepassOwnership(robloxUserId, gamepassId) {
  try {
    const res = await fetch(
      `https://inventory.roblox.com/v1/users/${robloxUserId}/items/GamePass/${gamepassId}`,
      {
        headers: {
          // No auth needed — this is a public endpoint
          'Accept': 'application/json',
        }
      }
    );

    if (!res.ok) {
      console.warn('⚠️ Ownership check failed with status:', res.status);
      return false;
    }

    const data = await res.json();
    console.log('Ownership check response:', JSON.stringify(data));

    // Returns { data: [] } if not owned, { data: [{...}] } if owned
    return Array.isArray(data.data) && data.data.length > 0;

  } catch (err) {
    console.warn('⚠️ Ownership check failed:', err.message);
    return false;
  }
}

// getRobloxCsrfToken — DELETE THIS, no longer needed anywhere.

// ── Rate limiter for Robux endpoints ─────────────────────────────────────────

const robuxLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: 'Too many requests, please slow down.',
});


app.post('/api/robux/create-gamepass', robuxLimiter, authenticateToken, async (req, res) => {
  try {
    const { robloxUsername, cart, totalRobux } = req.body;

    // --- Validation ---
    if (!robloxUsername || typeof robloxUsername !== 'string' ||
      !/^[a-zA-Z0-9_]{3,20}$/.test(robloxUsername)) {
      return res.status(400).json({ error: 'Invalid Roblox username' });
    }
    if (!Array.isArray(cart) || cart.length === 0) {
      return res.status(400).json({ error: 'Cart is empty' });
    }
    if (!Number.isInteger(totalRobux) || totalRobux < 1 || totalRobux > 100000) {
      return res.status(400).json({ error: 'Invalid Robux amount' });
    }

    const userId = req.userId;
    const validatedCart = cart.map(item => validateCartItem({ ...item, quantity: item.quantity || 1 }));

    // --- Fetch & verify products ---
    const { data: products, error: prodErr } = await supabase
      .from('assets')
      .select('id, title, price')
      .in('id', validatedCart.map(i => i.id));

    if (prodErr || !products) {
      return res.status(400).json({ error: 'Failed to fetch products' });
    }

    let expectedRobuxBeforeDiscount = 0;
    for (const item of validatedCart) {
      const product = products.find(p => p.id === item.id);
      if (!product) return res.status(400).json({ error: `Product ${item.id} not found` });
      expectedRobuxBeforeDiscount += Math.ceil(product.price * ROBUX_PER_USD) * item.quantity;
    }
    const expectedRobux = Math.ceil(expectedRobuxBeforeDiscount * 0.5);

    if (expectedRobux !== totalRobux) {
      console.warn(`⚠️ Robux mismatch — client: ${totalRobux} | server: ${expectedRobux}`);
      return res.status(400).json({ error: 'Price mismatch. Please contact support to create a manual order.' });
    }

    // --- Resolve Roblox user ---
    let robloxUserId, robloxDisplayName;
    try {
      ({ userId: robloxUserId, displayName: robloxDisplayName } = await resolveRobloxUserId(robloxUsername));
    } catch (err) {
      return res.status(400).json({ error: `Roblox user "${robloxUsername}" not found.` });
    }

    console.log(`🎮 Robux checkout | user: ${userId} | roblox: ${robloxUsername} (${robloxUserId}) | R$${expectedRobux}`);

    // --- Create Roblox gamepass ---
    const gpName = `SupStore Order - ${robloxUsername} - ${Date.now()}`;
    const gpDesc = `One-time purchase pass for SupStore order by ${robloxUsername}. Do not buy if you did not initiate this purchase.`;

    let gamepassId, gamepassUrl;
    try {
      ({ gamepassId, gamepassUrl } = await createRobloxGamepass(gpName, gpDesc, expectedRobux));
    } catch (err) {
      console.error('❌ Gamepass creation error:', err.message);
      return res.status(500).json({ error: 'Failed to create Roblox gamepass. Please try again.' });
    }

    console.log(`✅ Gamepass created: ${gamepassId} | URL: ${gamepassUrl}`);

    // --- Create pending order in DB ---
    const { data: order, error: orderErr } = await supabaseAdmin
      .from('orders')
      .insert({
        user_id: userId,
        session_id: `robux_${gamepassId}`,
        total_amount: expectedRobux / ROBUX_PER_USD, // store in USD equivalent
        status: 'pending',
        currency: 'RBX',
      })
      .select('id')
      .single();

    if (orderErr || !order) {
      console.error('❌ Robux order insert error:', orderErr?.message);
      return res.status(500).json({ error: 'Failed to create order' });
    }

    // --- Store Robux-specific metadata ---
    const { error: metaErr } = await supabaseAdmin
      .from('robux_orders')
      .insert({
        order_id: order.id,
        user_id: userId,
        roblox_username: robloxUsername,
        roblox_user_id: robloxUserId.toString(),
        gamepass_id: gamepassId.toString(),
        robux_amount: expectedRobux,
        asset_ids: validatedCart.map(i => i.id),
        status: 'pending',
      });

    if (metaErr) {
      console.error('❌ robux_orders insert error:', metaErr.message);
      // Non-fatal — order still exists
    }

    await auditLog({
      user_id: userId,
      action: 'robux_checkout_initiated',
      resource: 'order',
      resource_id: order.id,
      status: 'pending',
      details: {
        roblox_username: robloxUsername,
        roblox_user_id: robloxUserId,
        gamepass_id: gamepassId,
        robux_amount: expectedRobux,
        asset_ids: validatedCart.map(i => i.id),
      },
    });

    res.json({
      orderId: order.id,
      gamepassId,
      gamepassUrl,
      robuxAmount: expectedRobux,
    });

  } catch (err) {
    console.error('❌ /api/robux/create-gamepass error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── GET /api/robux/check-payment/:orderId ─────────────────────────────────────
//
//  Polled by the frontend every 5s.
//  Checks if the Roblox user now owns the gamepass.
//  If yes: marks order complete, grants assets, deactivates gamepass.

app.get('/api/robux/check-payment/:orderId', authenticateToken, async (req, res) => {
  try {
    const orderId = req.params.orderId;
    if (!orderId || typeof orderId !== 'string') {
      return res.status(400).json({ error: 'Invalid order ID' });
    }

    // Fetch the robux_orders row
    const { data: robuxOrder, error: robuxErr } = await supabaseAdmin
      .from('robux_orders')
      .select('*')
      .eq('order_id', orderId)
      .eq('user_id', req.userId)
      .maybeSingle();

    if (robuxErr || !robuxOrder) {
      return res.status(404).json({ error: 'Order not found' });
    }

    if (robuxOrder.status === 'completed') {
      return res.json({ paid: true });
    }
    if (robuxOrder.status === 'cancelled') {
      return res.json({ paid: false, cancelled: true });
    }

    // Check Roblox ownership
    const owns = await checkGamepassOwnership(
      robuxOrder.roblox_user_id,
      robuxOrder.gamepass_id
    );

    if (!owns) {
      return res.json({ paid: false });
    }

    // ── Payment confirmed! ──────────────────────────────────

    console.log(`✅ Robux payment confirmed | order: ${orderId} | gamepass: ${robuxOrder.gamepass_id}`);

    // Mark robux_orders as completed
    await supabaseAdmin
      .from('robux_orders')
      .update({ status: 'completed', paid_at: new Date().toISOString() })
      .eq('order_id', orderId);

    // Mark main order as completed
    await supabaseAdmin
      .from('orders')
      .update({ status: 'completed', payment_date: new Date().toISOString() })
      .eq('id', orderId);

    // Grant assets
    const assetIds = robuxOrder.asset_ids;
    let grantedCount = 0;

    for (const assetId of assetIds) {
      const { error: upsertErr } = await supabaseAdmin
        .from('user_assets')
        .upsert(
          {
            user_id: req.userId,
            asset_id: assetId,
            purchased_at: new Date().toISOString(),
          },
          { onConflict: 'user_id,asset_id', ignoreDuplicates: true }
        );

      if (upsertErr) {
        console.error(`❌ Failed to grant asset ${assetId}:`, upsertErr.message);
      } else {
        grantedCount++;
      }
    }

    console.log(`🎁 Assets granted: ${grantedCount}/${assetIds.length}`);

    // Deactivate gamepass so it can't be resold
    await deactivateGamepass(robuxOrder.gamepass_id);

    await auditLog({
      user_id: req.userId,
      action: 'robux_payment',
      resource: 'order',
      resource_id: orderId,
      status: 'completed',
      details: {
        roblox_username: robuxOrder.roblox_username,
        gamepass_id: robuxOrder.gamepass_id,
        robux_amount: robuxOrder.robux_amount,
        assets_granted: grantedCount,
      },
    });

    res.json({ paid: true, assetsGranted: grantedCount });

  } catch (err) {
    console.error('❌ /api/robux/check-payment error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/robux/webhook', async (req, res) => {
  try {
    const { secret, robloxUserId, gamepassId } = req.body;

    if (!secret || secret !== process.env.ROBLOX_WEBHOOK_SECRET) {
      console.warn('⚠️ Invalid Roblox webhook secret');
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (!robloxUserId || !gamepassId) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    console.log(`\n🎮 Roblox webhook | userId: ${robloxUserId} | gamepassId: ${gamepassId}`);

    // Find the pending robux order for this gamepass
    const { data: robuxOrder, error } = await supabaseAdmin
      .from('robux_orders')
      .select('*')
      .eq('gamepass_id', gamepassId.toString())
      .eq('roblox_user_id', robloxUserId.toString())
      .eq('status', 'pending')
      .maybeSingle();

    if (error || !robuxOrder) {
      console.warn('⚠️ No matching pending robux order for gamepass:', gamepassId);
      return res.json({ received: true, matched: false });
    }

    // Mark as completed
    await supabaseAdmin
      .from('robux_orders')
      .update({ status: 'completed', paid_at: new Date().toISOString() })
      .eq('order_id', robuxOrder.order_id);

    await supabaseAdmin
      .from('orders')
      .update({ status: 'completed', payment_date: new Date().toISOString() })
      .eq('id', robuxOrder.order_id);

    // Grant assets
    for (const assetId of robuxOrder.asset_ids) {
      await supabaseAdmin
        .from('user_assets')
        .upsert(
          {
            user_id: robuxOrder.user_id,
            asset_id: assetId,
            purchased_at: new Date().toISOString(),
          },
          { onConflict: 'user_id,asset_id', ignoreDuplicates: true }
        );
    }

    await deactivateGamepass(gamepassId);

    await auditLog({
      user_id: robuxOrder.user_id,
      action: 'robux_payment',
      resource: 'order',
      resource_id: robuxOrder.order_id,
      status: 'completed',
      details: { source: 'roblox_webhook', gamepass_id: gamepassId, roblox_user_id: robloxUserId },
    });

    console.log('✅ Robux webhook processed successfully');
    res.json({ received: true, matched: true });

  } catch (err) {
    console.error('❌ /api/robux/webhook error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Health check helpers ──────────────────────────────────────────────────────

const HEALTH_TIMEOUT = 6000;

function withTimeout(promise, ms = HEALTH_TIMEOUT) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('timeout')), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

function fmtResult(settled) {
  return settled.status === 'fulfilled'
    ? settled.value
    : { status: 'error', error: settled.reason?.message || 'unknown' };
}

// ── Individual checks ─────────────────────────────────────────────────────────

async function checkStripeApi() {
  const t = Date.now();
  // Proves secret key works and Stripe API is reachable
  await stripe.balance.retrieve();
  return { status: 'ok', detail: 'API key valid', latency_ms: Date.now() - t };
}

async function checkStripePrices() {
  const t = Date.now();
  // Pull a sample of assets that have Stripe price IDs and verify they're still active
  const { data: assets, error } = await supabaseAdmin
    .from('assets')
    .select('id, title, stripe_price_id')
    .not('stripe_price_id', 'is', null)
    .limit(3);

  if (error) throw new Error(`DB error: ${error.message}`);
  if (!assets?.length) return { status: 'ok', detail: 'no assets to check', latency_ms: Date.now() - t };

  const results = [];
  for (const asset of assets) {
    try {
      const price = await stripe.prices.retrieve(asset.stripe_price_id);
      results.push({
        asset_id: asset.id,
        price_id: asset.stripe_price_id,
        active: price.active,
      });
    } catch (err) {
      results.push({
        asset_id: asset.id,
        price_id: asset.stripe_price_id,
        active: false,
        error: err.message,
      });
    }
  }

  const allActive = results.every((r) => r.active);
  return {
    status: allActive ? 'ok' : 'degraded',
    detail: allActive ? 'sampled prices are active' : 'one or more prices inactive or missing',
    checked: results.length,
    prices: results,
    latency_ms: Date.now() - t,
  };
}

async function checkStripeFx() {
  const t = Date.now();
  const res = await fetch('https://api.stripe.com/v1/fx_quotes', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.STRIPE_SECRET_KEY}`,
      'Stripe-Version': '2025-04-30.preview',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      to_currency: 'eur',
      'from_currencies[]': 'usd',
      lock_duration: 'none',
      'usage[type]': 'payment',
    }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const rate = data?.rates?.usd?.exchange_rate;
  if (!rate) throw new Error('no exchange rate returned');
  return { status: 'ok', detail: 'FX USD→EUR reachable', usd_to_eur: rate, latency_ms: Date.now() - t };
}

async function checkSupabaseDb() {
  const t = Date.now();
  const { count, error } = await supabaseAdmin
    .from('assets')
    .select('*', { count: 'exact', head: true });
  if (error) throw new Error(error.message);
  return { status: 'ok', detail: `assets table reachable (${count} rows)`, latency_ms: Date.now() - t };
}

async function checkSupabaseStorage() {
  const t = Date.now();
  const { data, error } = await supabaseAdmin.storage.from('assets').list('', { limit: 1 });
  if (error) throw new Error(error.message);
  return { status: 'ok', detail: 'storage bucket reachable', latency_ms: Date.now() - t };
}

async function checkSupabaseAuth() {
  const t = Date.now();
  // Verify the admin auth client can make calls (doesn't expose user data)
  const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 1 });
  if (error) throw new Error(error.message);
  return { status: 'ok', detail: 'auth admin reachable', latency_ms: Date.now() - t };
}

async function checkRobloxPublic() {
  const t = Date.now();
  const res = await fetch('https://users.roblox.com/v1/users/1');
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  if (!data?.id) throw new Error('unexpected response shape');
  return { status: 'ok', detail: 'Roblox Users API reachable', latency_ms: Date.now() - t };
}

async function checkRobloxOpenCloud() {
  const t = Date.now();
  if (!process.env.ROBLOX_API_KEY || !process.env.ROBLOX_UNIVERSE_ID) {
    return { status: 'skipped', detail: 'ROBLOX_API_KEY or ROBLOX_UNIVERSE_ID not configured' };
  }
  // List game passes — lightweight read that proves the API key and universe ID are valid
  const res = await fetch(
    `https://apis.roblox.com/game-passes/v1/universes/${process.env.ROBLOX_UNIVERSE_ID}/game-passes?limit=1`,
    { headers: { 'x-api-key': process.env.ROBLOX_API_KEY } }
  );
  if (res.status === 401) throw new Error('API key invalid or unauthorized');
  if (res.status === 404) throw new Error('Universe ID not found');
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return { status: 'ok', detail: 'Open Cloud API key valid', latency_ms: Date.now() - t };
}

// ── Health endpoint ───────────────────────────────────────────────────────────

app.get('/api/health', async (req, res) => {
  const start = Date.now();

  const [
    stripeApi,
    stripePrices,
    stripeFx,
    supabaseDb,
    supabaseStorage,
    supabaseAuth,
    robloxPublic,
    robloxOpenCloud,
  ] = await Promise.allSettled([
    withTimeout(checkStripeApi()),
    withTimeout(checkStripePrices()),
    withTimeout(checkStripeFx()),
    withTimeout(checkSupabaseDb()),
    withTimeout(checkSupabaseStorage()),
    withTimeout(checkSupabaseAuth()),
    withTimeout(checkRobloxPublic()),
    withTimeout(checkRobloxOpenCloud()),
  ]);

  const services = {
    stripe: {
      api: fmtResult(stripeApi),
      prices: fmtResult(stripePrices),
      fx_rates: fmtResult(stripeFx),
    },
    supabase: {
      database: fmtResult(supabaseDb),
      storage: fmtResult(supabaseStorage),
      auth: fmtResult(supabaseAuth),
    },
    roblox: {
      public_api: fmtResult(robloxPublic),
      open_cloud: fmtResult(robloxOpenCloud),
    },
  };

  // Flatten all leaf statuses to determine overall health
  const allStatuses = [
    services.stripe.api,
    services.stripe.prices,
    services.stripe.fx_rates,
    services.supabase.database,
    services.supabase.storage,
    services.supabase.auth,
    services.roblox.public_api,
    services.roblox.open_cloud,
  ].map((s) => s.status);

  const hasError = allStatuses.includes('error');
  const hasDegraded = allStatuses.includes('degraded');
  const overallStatus = hasError ? 'error' : hasDegraded ? 'degraded' : 'ok';

  res.status(200).json({
    status: overallStatus,
    timestamp: new Date().toISOString(),
    response_ms: Date.now() - start,
    services,
  });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌐 Frontend served from: src/`);
  console.log(`🎯 Webhook endpoint: http://localhost:${PORT}/api/stripe-webhook`);
  console.log(`📁 Static files directory: ${path.join(__dirname, '..')}\n`);

  setTimeout(() => {
    syncAssetsWithStripe().catch(err =>
      console.error('❌ Background Stripe sync failed:', err)
    );
  }, 5000);
});
