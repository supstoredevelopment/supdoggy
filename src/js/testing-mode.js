(async function () {
    'use strict';

    // ── 1. Check testing mode ─────────────────────────────────────────────────

    let testingEnabled = false;
    try {
        const res = await fetch('/api/testing-mode');
        if (res.ok) {
            const data = await res.json();
            testingEnabled = data.enabled === true;
        }
    } catch {
        // Silently fail — never break the page
        return;
    }

    if (!testingEnabled) return;

    // ── 2. Inject styles ──────────────────────────────────────────────────────

    const style = document.createElement('style');
    style.textContent = `
    /* ── Testing mode banner ── */
    #supstore-test-banner {
      position: fixed;
      top: 16px;
      right: 16px;
      z-index: 99999;
      background: #ff2222;
      color: #fff;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 0.72rem;
      font-weight: 800;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      padding: 6px 14px;
      border-radius: 6px;
      box-shadow: 0 0 0 2px rgba(255,34,34,0.4), 0 4px 16px rgba(255,34,34,0.35);
      display: flex;
      align-items: center;
      gap: 6px;
      user-select: none;
      animation: supstore-pulse 2.4s ease-in-out infinite;
      pointer-events: none;
    }

    #supstore-test-banner .dot {
      width: 7px;
      height: 7px;
      background: #fff;
      border-radius: 50%;
      animation: supstore-blink 1.2s ease-in-out infinite;
      flex-shrink: 0;
    }

    @keyframes supstore-pulse {
      0%, 100% { box-shadow: 0 0 0 2px rgba(255,34,34,0.4), 0 4px 16px rgba(255,34,34,0.35); }
      50%       { box-shadow: 0 0 0 4px rgba(255,34,34,0.6), 0 4px 24px rgba(255,34,34,0.55); }
    }

    @keyframes supstore-blink {
      0%, 100% { opacity: 1; }
      50%       { opacity: 0.2; }
    }

    /* ── Tester welcome modal ── */
    #supstore-tester-overlay {
      position: fixed;
      inset: 0;
      z-index: 999999;
      background: rgba(0, 0, 0, 0.82);
      backdrop-filter: blur(18px);
      -webkit-backdrop-filter: blur(18px);
      display: flex;
      align-items: center;
      justify-content: center;
      animation: supstore-fadein 0.35s ease;
    }

    @keyframes supstore-fadein {
      from { opacity: 0; }
      to   { opacity: 1; }
    }

    #supstore-tester-card {
      background: #0d0d0d;
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 20px;
      padding: 3rem 2.8rem 2.5rem;
      max-width: 480px;
      width: calc(100% - 3rem);
      text-align: center;
      box-shadow: 0 0 80px rgba(255,34,34,0.18), 0 30px 60px rgba(0,0,0,0.6);
      animation: supstore-slidein 0.4s cubic-bezier(0.22, 1, 0.36, 1);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    @keyframes supstore-slidein {
      from { transform: translateY(30px) scale(0.97); opacity: 0; }
      to   { transform: translateY(0) scale(1);       opacity: 1; }
    }

    #supstore-tester-card .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(255,34,34,0.12);
      border: 1px solid rgba(255,34,34,0.35);
      color: #ff4444;
      font-size: 0.72rem;
      font-weight: 800;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      padding: 5px 14px;
      border-radius: 50px;
      margin-bottom: 1.6rem;
    }

    #supstore-tester-card .badge .dot {
      width: 6px;
      height: 6px;
      background: #ff4444;
      border-radius: 50%;
      animation: supstore-blink 1.2s ease-in-out infinite;
    }

    #supstore-tester-card h2 {
      color: #fff;
      font-size: 2rem;
      font-weight: 800;
      letter-spacing: -0.03em;
      margin-bottom: 0.75rem;
      line-height: 1.15;
    }

    #supstore-tester-card p {
      color: rgba(255,255,255,0.6);
      font-size: 0.98rem;
      line-height: 1.7;
      margin-bottom: 1.1rem;
    }

    #supstore-tester-card .tip-box {
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 10px;
      padding: 1rem 1.2rem;
      margin: 1.4rem 0 2rem;
      text-align: left;
    }

    #supstore-tester-card .tip-box p {
      margin: 0;
      font-size: 0.88rem;
      color: rgba(255,255,255,0.5);
    }

    #supstore-tester-card .tip-box strong {
      color: rgba(255,255,255,0.85);
    }

    #supstore-tester-continue {
      width: 100%;
      padding: 0.9rem 1.5rem;
      background: linear-gradient(135deg, #cc0000, #ff2222);
      color: #fff;
      border: none;
      border-radius: 10px;
      font-family: inherit;
      font-size: 1rem;
      font-weight: 700;
      cursor: pointer;
      transition: transform 0.2s ease, box-shadow 0.2s ease;
      box-shadow: 0 4px 20px rgba(255, 34, 34, 0.35);
    }

    #supstore-tester-continue:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 28px rgba(255, 34, 34, 0.5);
    }

    #supstore-tester-continue:active {
      transform: translateY(0);
    }
  `;
    document.head.appendChild(style);

    // ── 3. Inject the banner ──────────────────────────────────────────────────

    const banner = document.createElement('div');
    banner.id = 'supstore-test-banner';
    banner.innerHTML = '<span class="dot"></span> Testing Mode';
    document.body.appendChild(banner);

    // ── 4. Tester welcome modal (homepage only, once per session) ─────────────

    const isHomepage = window.location.pathname === '/' ||
        window.location.pathname === '/index.html';
    const alreadySeen = sessionStorage.getItem('supstore_tester_welcomed');

    if (isHomepage && !alreadySeen) {
        const overlay = document.createElement('div');
        overlay.id = 'supstore-tester-overlay';
        overlay.innerHTML = `
      <div id="supstore-tester-card">
        <div class="badge"><span class="dot"></span> Testing Mode Active</div>
        <h2>Hello, Tester!</h2>
        <p>
          Thanks for helping us make SupStore better. You're accessing the site
          with <strong style="color:#fff">testing mode enabled</strong> your
          feedback is incredibly valuable to us.
        </p>
        <p>
          Feel free to browse, add things to your cart, and go through the full
          checkout flow. <strong style="color:#fff">No real money will be charged</strong>
          purchases are simulated and assets are granted instantly.
        </p>
        <div class="tip-box">
          <p>
            <strong>🧪 What's different in testing mode?</strong><br>
            Payments are fake so Stripe is never contacted. Orders are completed
            immediately and assets appear in your dashboard as normal. The red
            <strong>TESTING MODE</strong> badge in the corner will remind you.
          </p>
        </div>
        <button id="supstore-tester-continue">Continue to SupStore →</button>
      </div>
    `;
        document.body.appendChild(overlay);

        document.getElementById('supstore-tester-continue').addEventListener('click', () => {
            overlay.style.animation = 'supstore-fadein 0.25s ease reverse forwards';
            setTimeout(() => overlay.remove(), 250);
            sessionStorage.setItem('supstore_tester_welcomed', '1');
        });
    }
})();