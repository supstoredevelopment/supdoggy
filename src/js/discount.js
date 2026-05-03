/**
 * discount.js — single source of truth for the 50 % release discount.
 * Include this file on every page that shows prices or discount UI.
 *
 * Usage:
 *   <script src="/js/discount.js"></script>
 *
 *   if (DISCOUNT.active()) { ... }           // boolean
 *   DISCOUNT.apply(price)                    // number → discounted price
 *   DISCOUNT.displayPrice(price)             // string → HTML price block
 *   DISCOUNT.startCountdown('elementId')     // wires up a live countdown
 */

const DISCOUNT = (() => {
    // ── Configure here ──────────────────────────────────────────────────────────
    const END_DATE = new Date('2026-05-03T21:59:59Z');   // May 3 end of day UTC
    const RATE = 0.5;                                 // 50 % off
    const ROBUX_RATE = 263;                                 // R$ per $1 USD
    // ────────────────────────────────────────────────────────────────────────────

    function active() {
        return Date.now() < END_DATE.getTime();
    }

    function apply(usdPrice) {
        return active() ? usdPrice * RATE : usdPrice;
    }

    /** Returns an HTML string for use inside .innerHTML */
    function displayPrice(usdPrice, opts = {}) {
        const { showRobux = false, accentColor = '#00d4ff' } = opts;
        const isFree = usdPrice === 0;

        if (isFree) {
            return `<span style="color:${accentColor};font-weight:800;">FREE</span>`;
        }

        if (!active()) {
            const robuxPart = showRobux
                ? ` <span style="font-size:.76rem;color:#aaa;">(${Math.ceil(usdPrice * ROBUX_RATE)} R$)</span>`
                : '';
            return `<span style="font-weight:700;">$${usdPrice.toFixed(2)}</span>${robuxPart}`;
        }

        const discounted = usdPrice * RATE;
        const robuxPart = showRobux
            ? ` <span style="font-size:.76rem;color:#aaa;">(${Math.ceil(discounted * ROBUX_RATE)} R$)</span>`
            : '';

        return `
      <span style="text-decoration:line-through;color:#888;font-size:.78rem;">$${usdPrice.toFixed(2)}</span>
      <span style="color:${accentColor};font-weight:700;font-size:.98rem;">$${discounted.toFixed(2)}</span>
      ${robuxPart}`.trim();
    }

    /**
     * Wires a live countdown into an element.
     * If the discount is not active the element is hidden and the callback
     * `onExpired` is called immediately.
     */
    function startCountdown(elementId, { onExpired } = {}) {
        const el = document.getElementById(elementId);
        if (!el) return;

        function tick() {
            const remaining = Math.max(0, Math.floor((END_DATE - Date.now()) / 1000));

            if (remaining <= 0) {
                clearInterval(timer);
                el.style.display = 'none';
                if (typeof onExpired === 'function') onExpired();
                return;
            }

            const d = Math.floor(remaining / 86400);
            const h = Math.floor((remaining % 86400) / 3600);
            const m = Math.floor((remaining % 3600) / 60);
            const s = remaining % 60;

            el.innerHTML = `
        <span>${d}d</span>
        <span>${String(h).padStart(2, '0')}h</span>
        <span>${String(m).padStart(2, '0')}m</span>
        <span>${String(s).padStart(2, '0')}s</span>`;
        }

        if (!active()) {
            el.style.display = 'none';
            if (typeof onExpired === 'function') onExpired();
            return;
        }

        tick();
        const timer = setInterval(tick, 1000);
    }

    return { active, apply, displayPrice, startCountdown, END_DATE, RATE, ROBUX_RATE };
})();