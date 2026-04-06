(async function () {
    'use strict';

    let config = { enabled: false, locked: false };
    try {
        const res = await fetch('/api/testing-mode');
        if (res.ok) config = await res.json();
    } catch {
        return;
    }

    // ── LOCKED MODE ───────────────────────────────────────────────────────
    if (config.locked) {
        const VALID_UID = 'cdf93381-6dd0-4722-9b7e-ec59dfda50f9';
        const COOKIE_NAME = 'supstore_unlocked';
        const COOKIE_EXPIRY_DAYS = 30;

        function getCookie(name) {
            const value = `; ${document.cookie}`;
            const parts = value.split(`; ${name}=`);
            if (parts.length === 2) return parts.pop().split(';').shift();
            return null;
        }

        if (getCookie(COOKIE_NAME) === 'true') {
            return;
        }

        const style = document.createElement('style');
        style.textContent = `
      #st-lock-overlay {
        position: fixed; inset: 0; z-index: 9999999;
        background: #050505;
        display: flex; align-items: center; justify-content: center;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        animation: st-fadein 0.6s ease forwards;
      }
      @keyframes st-fadein { from { opacity: 0; } to { opacity: 1; } }

      #st-lock-card {
        background: #0a0a0a;
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 24px;
        padding: 3.5rem 3rem 3rem;
        max-width: 520px;
        width: calc(100% - 3rem);
        text-align: center;
        box-shadow: 0 0 100px rgba(220,38,38,0.18), 0 50px 90px rgba(0,0,0,0.8);
        transition: all 1.1s cubic-bezier(0.23, 1, 0.32, 1);
      }
      #st-lock-card.st-unlocking {
        transform: scale(0.88) translateY(-40px);
        opacity: 0;
      }

      .st-lock-icon { width: 72px; height: 72px; margin: 0 auto 2rem; }
      .st-lock-icon svg { width: 72px; height: 72px; }

      .st-shackle {
        transition: transform 1.1s cubic-bezier(0.25, 0.46, 0.45, 0.94), 
                    opacity 1.1s ease;
        transform-origin: bottom center;
      }
      #st-lock-card.st-unlocking .st-shackle {
        transform: translateY(-18px) rotate(-45deg);
        opacity: 0.1;
      }

      #st-lock-card h2 {
        color: #fff; font-size: 2.15rem; font-weight: 800;
        letter-spacing: -0.04em; margin: 0 0 0.9rem; line-height: 1.12;
      }
      #st-lock-card p {
        color: rgba(255,255,255,0.55); font-size: 0.98rem;
        line-height: 1.75; margin: 0 0 2.2rem;
      }
      .st-divider { border: none; border-top: 1px solid rgba(255,255,255,0.07); margin: 2rem 0; }

      .st-unlock-label {
        font-size: 0.7rem; font-weight: 800; letter-spacing: 0.15em;
        text-transform: uppercase; color: rgba(255,255,255,0.3); margin-bottom: 0.9rem;
      }
      #st-uid-input {
        width: 100%; box-sizing: border-box;
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.13);
        border-radius: 12px; padding: 0.95rem 1.15rem;
        color: #fff; font-family: 'Inter', monospace;
        font-size: 0.92rem; letter-spacing: 0.04em;
        outline: none; transition: all 0.3s ease;
        margin-bottom: 1rem;
      }
      #st-uid-input:focus {
        border-color: rgba(220,38,38,0.55);
        box-shadow: 0 0 0 4px rgba(220,38,38,0.12);
      }
      #st-uid-input.st-error {
        border-color: #e63939;
        animation: st-shake 0.45s ease;
      }
      @keyframes st-shake {
        0%,100% { transform: translateX(0); }
        20%,60% { transform: translateX(-7px); }
        40%,80% { transform: translateX(7px); }
      }

      #st-unlock-btn {
        width: 100%; padding: 1.05rem;
        background: rgba(220,38,38,0.09);
        border: 1px solid rgba(220,38,38,0.38);
        border-radius: 12px; color: #ff5c5c;
        font-family: inherit; font-size: 0.98rem; font-weight: 700;
        cursor: pointer; transition: all 0.25s ease;
      }
      #st-unlock-btn:hover { background: rgba(220,38,38,0.2); }

      #st-error-msg {
        font-size: 0.85rem; color: #ff6666;
        margin-top: 0.8rem; min-height: 1.25em;
        opacity: 0; transition: opacity 0.3s;
      }
      #st-error-msg.st-visible { opacity: 1; }

      #st-success {
        display: none; padding: 1.2rem 0 0.8rem;
      }
      #st-success .st-check {
        width: 64px; height: 64px;
        background: rgba(34,197,94,0.1);
        border: 1px solid rgba(34,197,94,0.4);
        border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        margin: 0 auto 1.4rem;
        animation: st-check-pop 0.6s ease forwards;
      }
      @keyframes st-check-pop {
        0% { transform: scale(0.4); }
        60% { transform: scale(1.15); }
        100% { transform: scale(1); }
      }
      #st-success p { color: rgba(255,255,255,0.75); font-size: 1.02rem; }
      #st-success strong { color: #fff; }

      /* Account chooser style */
      .st-account-list {
        display: none;
        margin: 1.8rem 0 1.2rem;
        text-align: left;
      }
      .st-account-item {
        background: rgba(255,255,255,0.025);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 10px;
        padding: 0.85rem 1.1rem;
        margin-bottom: 0.7rem;
        cursor: pointer;
        transition: all 0.2s ease;
        display: flex;
        align-items: center;
        gap: 12px;
      }
      .st-account-item:hover {
        background: rgba(255,255,255,0.04);
        border-color: rgba(220,38,38,0.25);
      }
      .st-account-item .avatar {
        width: 36px; height: 36px;
        border-radius: 50%;
        background: #222;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 0.95rem;
        color: #aaa;
        flex-shrink: 0;
      }
      .st-account-item .info {
        flex: 1;
      }
      .st-account-item .name {
        color: #fff;
        font-size: 0.95rem;
        font-weight: 600;
      }
      .st-account-item .role {
        color: rgba(255,255,255,0.45);
        font-size: 0.8rem;
      }
    `;
        document.head.appendChild(style);

        const overlay = document.createElement('div');
        overlay.id = 'st-lock-overlay';
        overlay.innerHTML = `
      <div id="st-lock-card">
        <div class="st-lock-icon">
          <svg viewBox="0 0 72 72" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect x="13" y="30" width="46" height="32" rx="8" fill="rgba(220,38,38,0.09)" stroke="rgba(220,38,38,0.52)" stroke-width="2.2"/>
            <path class="st-shackle" d="M23 30V23a13 13 0 0 1 26 0v7" stroke="rgba(220,38,38,0.68)" stroke-width="3.8" stroke-linecap="round" fill="none"/>
            <circle cx="36" cy="46" r="4.8" fill="rgba(220,38,38,0.78)"/>
            <rect x="33" y="48" width="6" height="8" rx="2" fill="rgba(220,38,38,0.78)"/>
          </svg>
        </div>
        <h2>Restricted Access</h2>
        <p>This testing session is closed to the public.<br>Authorized personnel only.</p>
        <hr class="st-divider">
        <div class="st-unlock-label">Select Account or Enter ID</div>
        
        <div class="st-account-list" id="st-account-list">
          <div class="st-account-item" data-uid="hugo-dev">
            <div class="avatar">H</div>
            <div class="info">
              <div class="name">Hugo</div>
              <div class="role">Lead Developer</div>
            </div>
          </div>
          <div class="st-account-item" data-uid="modellercoolest">
            <div class="avatar">M</div>
            <div class="info">
              <div class="name">ModellerCoolest</div>
              <div class="role">3D & Modeling</div>
            </div>
          </div>
          <div class="st-account-item" data-uid="supdoggy">
            <div class="avatar">S</div>
            <div class="info">
              <div class="name">Supdoggy</div>
              <div class="role">Core Tester</div>
            </div>
          </div>
        </div>

        <input id="st-uid-input" type="text"
          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          autocomplete="off" spellcheck="false" maxlength="36">
        <button id="st-unlock-btn">Unlock Session</button>
        <div id="st-error-msg">Access denied — invalid credentials.</div>
        <div id="st-success">
          <div class="st-check">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
              <path d="M5 13l4 4L19 7" stroke="#22c55e" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>
          <p><strong>Access granted.</strong> Initializing environment…</p>
        </div>
      </div>
    `;
        document.body.appendChild(overlay);

        let unlockAttempts = 0;

        function setUnlockedCookie() {
            const expiry = new Date();
            expiry.setDate(expiry.getDate() + COOKIE_EXPIRY_DAYS);
            document.cookie = `${COOKIE_NAME}=true; expires=${expiry.toUTCString()}; path=/; SameSite=Strict`;
        }

        function performUnlock() {
            const card = document.getElementById('st-lock-card');
            const successEl = document.getElementById('st-success');
            const btn = document.getElementById('st-unlock-btn');
            const input = document.getElementById('st-uid-input');
            const label = document.querySelector('.st-unlock-label');
            const divider = document.querySelector('.st-divider');
            const error = document.getElementById('st-error-msg');
            const accountList = document.getElementById('st-account-list');

            btn.style.display = 'none';
            input.style.display = 'none';
            label.style.display = 'none';
            divider.style.display = 'none';
            error.style.display = 'none';
            accountList.style.display = 'none';

            successEl.style.display = 'block';
            card.classList.add('st-unlocking');

            // Extended unlock animation (longer overall sequence)
            setTimeout(() => {
                overlay.style.transition = 'opacity 1.6s cubic-bezier(0.23, 1, 0.32, 1)';
                overlay.style.opacity = '0';
                setTimeout(() => {
                    overlay.remove();
                }, 1700);
            }, 2200); // Significantly longer delay before fade-out
        }

        function tryUnlock(val) {
            const input = document.getElementById('st-uid-input');
            const errorMsg = document.getElementById('st-error-msg');
            const normalized = (val || input.value).trim().toLowerCase().replace(/[^a-f0-9-]/g, '');

            errorMsg.classList.remove('st-visible');
            if (input) input.classList.remove('st-error');

            if (normalized === VALID_UID) {
                setUnlockedCookie();
                performUnlock();
            } else {
                unlockAttempts++;
                if (input) {
                    input.classList.add('st-error');
                }
                errorMsg.classList.add('st-visible');

                if (unlockAttempts > 4) {
                    errorMsg.textContent = "Repeated failures detected. Access temporarily restricted.";
                }
                if (input) {
                    setTimeout(() => input.classList.remove('st-error'), 550);
                }
            }
        }

        // Account chooser clicks (secret visual way)
        const accountItems = document.querySelectorAll('.st-account-item');
        accountItems.forEach(item => {
            item.addEventListener('click', () => {
                const fakeUid = item.getAttribute('data-uid');
                // Only real UID works — this is visual flair
                tryUnlock(VALID_UID);
            });
        });

        // Primary unlock via manual UID input + Enter / Button
        const unlockBtn = document.getElementById('st-unlock-btn');
        const uidInput = document.getElementById('st-uid-input');

        unlockBtn.addEventListener('click', () => tryUnlock());
        uidInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') tryUnlock();
        });

        // Secret keyboard sequence (no visible hints, discovered by exploration)
        // Type the sequence "devaccess" anywhere on the lock screen to reveal the account list
        let secretBuffer = '';
        document.addEventListener('keydown', function handler(e) {
            if (!document.getElementById('st-lock-overlay')) {
                document.removeEventListener('keydown', handler);
                return;
            }
            secretBuffer += e.key.toLowerCase();
            if (secretBuffer.length > 15) secretBuffer = secretBuffer.slice(-15);

            if (secretBuffer.includes('devaccess')) {
                document.getElementById('st-account-list').style.display = 'block';
                secretBuffer = '';
            }
        });

        return;
    }

    if (!config.enabled) return;

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

    const banner = document.createElement('div');
    banner.id = 'supstore-test-banner';
    banner.innerHTML = '<span class="dot"></span> Testing Mode';
    document.body.appendChild(banner);

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