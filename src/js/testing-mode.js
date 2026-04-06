(async function () {
    'use strict';

    let config = { enabled: false, locked: false };
    try {
        const res = await fetch('/api/testing-mode');
        if (res.ok) config = await res.json();
    } catch {
        return;
    }

    // ── LOCKED MODE ────────────────────────────────────────────────
    if (config.locked) {
        const VALID_UID = 'cdf93381-6dd0-4722-9b7e-ec59dfda50f9';

        const style = document.createElement('style');
        style.textContent = `
      #st-lock-overlay {
        position: fixed; inset: 0; z-index: 9999999;
        background: #080808;
        display: flex; align-items: center; justify-content: center;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        animation: st-fadein 0.4s ease;
      }
      @keyframes st-fadein { from { opacity: 0; } to { opacity: 1; } }

      #st-lock-card {
        background: #0d0d0d;
        border: 1px solid rgba(255,255,255,0.09);
        border-radius: 20px;
        padding: 3rem 2.8rem 2.5rem;
        max-width: 460px;
        width: calc(100% - 3rem);
        text-align: center;
        box-shadow: 0 0 80px rgba(220,38,38,0.12), 0 30px 60px rgba(0,0,0,0.6);
        transition: transform 0.6s cubic-bezier(0.22,1,0.36,1), opacity 0.6s ease;
      }
      #st-lock-card.st-unlocking { transform: scale(0.95) translateY(-20px); opacity: 0; }

      .st-lock-icon { width: 56px; height: 56px; margin: 0 auto 1.5rem; }
      .st-lock-icon svg { width: 56px; height: 56px; }
      .st-shackle { transition: transform 0.4s ease, opacity 0.4s ease; transform-origin: bottom center; }
      #st-lock-card.st-unlocking .st-shackle { transform: translateY(-5px) rotate(-20deg); opacity: 0.2; }

      #st-lock-card h2 {
        color: #fff; font-size: 1.85rem; font-weight: 800;
        letter-spacing: -0.03em; margin: 0 0 0.65rem; line-height: 1.2;
      }
      #st-lock-card p {
        color: rgba(255,255,255,0.48); font-size: 0.95rem;
        line-height: 1.65; margin: 0 0 1.5rem;
      }
      .st-divider { border: none; border-top: 1px solid rgba(255,255,255,0.07); margin: 1.4rem 0; }
      .st-unlock-label {
        font-size: 0.72rem; font-weight: 800; letter-spacing: 0.12em;
        text-transform: uppercase; color: rgba(255,255,255,0.25); margin-bottom: 0.65rem;
      }
      #st-uid-input {
        width: 100%; box-sizing: border-box;
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 10px; padding: 0.75rem 1rem;
        color: #fff; font-family: 'Inter', monospace;
        font-size: 0.87rem; letter-spacing: 0.02em;
        outline: none; transition: border-color 0.2s, box-shadow 0.2s;
        margin-bottom: 0.75rem;
      }
      #st-uid-input:focus {
        border-color: rgba(220,38,38,0.45);
        box-shadow: 0 0 0 3px rgba(220,38,38,0.12);
      }
      #st-uid-input.st-error {
        border-color: rgba(220,38,38,0.7);
        box-shadow: 0 0 0 3px rgba(220,38,38,0.18);
        animation: st-shake 0.35s ease;
      }
      @keyframes st-shake {
        0%,100% { transform: translateX(0); }
        20% { transform: translateX(-8px); }
        40% { transform: translateX(8px); }
        60% { transform: translateX(-5px); }
        80% { transform: translateX(5px); }
      }
      #st-unlock-btn {
        width: 100%; padding: 0.88rem;
        background: rgba(220,38,38,0.12);
        border: 1px solid rgba(220,38,38,0.3);
        border-radius: 10px; color: #ff6666;
        font-family: inherit; font-size: 0.95rem; font-weight: 700;
        cursor: pointer; transition: background 0.2s, transform 0.15s;
      }
      #st-unlock-btn:hover { background: rgba(220,38,38,0.22); }
      #st-unlock-btn:active { transform: scale(0.98); }
      #st-error-msg {
        font-size: 0.82rem; color: #ff6666;
        margin-top: 0.55rem; min-height: 1.1em;
        opacity: 0; transition: opacity 0.2s;
      }
      #st-error-msg.st-visible { opacity: 1; }
      #st-success {
        display: none; padding: 0.5rem 0;
      }
      #st-success .st-check {
        width: 52px; height: 52px;
        background: rgba(34,197,94,0.1);
        border: 1px solid rgba(34,197,94,0.28);
        border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        margin: 0 auto 1rem;
      }
      #st-success p { color: rgba(255,255,255,0.65); font-size: 0.95rem; }
      #st-success strong { color: #fff; }
    `;
        document.head.appendChild(style);

        const overlay = document.createElement('div');
        overlay.id = 'st-lock-overlay';
        overlay.innerHTML = `
      <div id="st-lock-card">
        <div class="st-lock-icon">
          <svg viewBox="0 0 56 56" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect x="10" y="26" width="36" height="24" rx="5"
              fill="rgba(220,38,38,0.12)" stroke="rgba(220,38,38,0.45)" stroke-width="1.5"/>
            <path class="st-shackle" d="M18 26V20a10 10 0 0 1 20 0v6"
              stroke="rgba(220,38,38,0.55)" stroke-width="2.5" stroke-linecap="round" fill="none"/>
            <circle cx="28" cy="37" r="3.5" fill="rgba(220,38,38,0.65)"/>
            <rect x="26.5" y="38" width="3" height="5" rx="1.5" fill="rgba(220,38,38,0.65)"/>
          </svg>
        </div>
        <h2>Testing session closed</h2>
        <p>This testing session has now been closed.<br>Public access is restricted.</p>
        <hr class="st-divider">
        <div class="st-unlock-label">Unlock with user ID</div>
        <input id="st-uid-input" type="text"
          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          autocomplete="off" spellcheck="false">
        <button id="st-unlock-btn">Unlock access</button>
        <div id="st-error-msg">Invalid user ID — access denied.</div>
        <div id="st-success">
          <div class="st-check">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
              <path d="M5 13l4 4L19 7" stroke="rgba(34,197,94,0.85)"
                stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>
          <p><strong>Access granted.</strong> Loading SupStore…</p>
        </div>
      </div>
    `;
        document.body.appendChild(overlay);

        function tryUnlock() {
            const input = document.getElementById('st-uid-input');
            const errorMsg = document.getElementById('st-error-msg');
            const card = document.getElementById('st-lock-card');
            const val = input.value.trim().toLowerCase();

            errorMsg.classList.remove('st-visible');
            input.classList.remove('st-error');

            if (val === VALID_UID) {
                document.getElementById('st-unlock-btn').style.display = 'none';
                input.style.display = 'none';
                document.querySelector('.st-unlock-label').style.display = 'none';
                document.querySelector('.st-divider').style.display = 'none';
                document.getElementById('st-error-msg').style.display = 'none';
                document.getElementById('st-success').style.display = 'block';
                card.classList.add('st-unlocking');
                setTimeout(() => overlay.remove(), 1800);
            } else {
                input.classList.add('st-error');
                errorMsg.classList.add('st-visible');
                setTimeout(() => input.classList.remove('st-error'), 400);
            }
        }

        document.getElementById('st-unlock-btn').addEventListener('click', tryUnlock);
        document.getElementById('st-uid-input').addEventListener('keydown', e => {
            if (e.key === 'Enter') tryUnlock();
        });

        return; // Don't show the testing banner
    }


    if (!config.enabled) return;

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