# Plan: Add Benchmark Section to Landing Page

**File**: `landing-page/index.html`
**Type**: Single-file HTML modification
**Priority**: High

---

## Objective

Add a benchmark comparison section after the Features section (`#features`) showing how `paseto-wasm` outperforms `paseto-ts`, plus a link to the live benchmark page at `https://paseto-wasm-benchmark-web-browser.achmadk.com`.

---

## Design Decisions (Pre-Made)

| Decision              | Choice                             | Rationale                                                                                                                    |
| --------------------- | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **Benchmark data**    | No hard-coded numbers              | The live benchmark page is the source of truth; results vary by hardware/browser                                             |
| **Section placement** | After Features, before Quick Start | Creates narrative flow: Features → Benchmarks (proof) → Quick Start (how to use)                                             |
| **Visual style**      | Match existing dark theme          | Follow the established design system: CSS vars, card patterns, section-label, section-title, section-desc, reveal animations |
| **CTA link style**    | Prominent button card              | The benchmark page link should be a clear call-to-action, not a footnote                                                     |
| **Nav link**          | Add "Benchmarks" to nav            | Consistency — all major sections have nav links                                                                              |

---

## Task Breakdown

### Task 1: Add "Benchmarks" nav link

**What**: Insert a new `<a href="#benchmark">Benchmarks</a>` nav item in the `<nav>` between "Features" and "Quick Start".

**Location**: Lines 466-468 of the nav-links div.

**Exact edit target**:

```html
<a href="#features">Features</a> <a href="#benchmarks">Benchmarks</a>
<!-- NEW -->
<a href="#quick-start">Quick Start</a>
```

**Edge cases**: None — this is a simple insert in a flat list of links.

---

### Task 2: Add Benchmark section HTML structure

**What**: Insert a new benchmark section after the Features section's closing `</section>` tag and before the following `<div class="divider">`.

**Location**: After line 591 (closing `</section>` of `#features`), before line 593 (the divider).

**Full section markup to insert:**

```html
<!-- BENCHMARK -->
<section id="benchmarks" class="reveal-section">
  <div class="section-inner">
    <div class="section-label">Benchmark</div>
    <h2 class="section-title">WASM vs TypeScript performance</h2>
    <p class="section-desc">
      See how <strong>paseto-wasm</strong> compares head-to-head against <strong>paseto-ts</strong>
      for real-world PASETO operations — signing and verification, right in your browser.
    </p>
    <div style="display: flex; gap: 20px; flex-wrap: wrap;">
      <a
        href="https://paseto-wasm-benchmark-web-browser.achmadk.com"
        target="_blank"
        rel="noopener"
        class="feature-card benchmark-card"
        style="display: flex; flex-direction: column; align-items: flex-start; gap: 12px; padding: 32px; text-decoration: none; flex: 1; min-width: 280px;"
      >
        <div class="feature-icon">
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
          </svg>
        </div>
        <h3 style="font-size: 18px; font-weight: 600; color: var(--ink-primary); margin: 0;">
          Run the benchmark →
        </h3>
        <p style="font-size: 14px; color: var(--ink-secondary); line-height: 1.6; margin: 0;">
          Open the interactive benchmark suite in your browser. Tests V4 Ed25519 sign + verify
          across multiple iterations with warmup. Results are computed live using tinybench.
        </p>
        <span
          style="
          display: inline-flex; align-items: center; gap: 6px;
          padding: 6px 14px; border-radius: 100px;
          background: var(--accent-subtle); border: 1px solid rgba(45, 212, 168, 0.15);
          font-family: var(--font-mono); font-size: 12px; color: var(--accent);
          margin-top: 4px;
        "
          >paseto-wasm-benchmark-web-browser.achmadk.com ↗</span
        >
      </a>
    </div>
  </div>
</section>
```

**QA scenarios to verify**:

- Section renders correctly in desktop viewport (1120px max-width)
- Section renders correctly in mobile viewport (single column, no overflow)
- Card hover effect works (border-color transition)
- Link opens in new tab with `target="_blank"` and `rel="noopener"`
- Scroll reveal animation fires when section enters viewport
- Nav link scroll-smooth to `#benchmarks` works

---

### Task 3: Add CSS for benchmark card hover enhancement

**What**: Add a subtle hover enhancement for the `.benchmark-card` class. The existing `.feature-card` already has `border-color` transition on hover, but the benchmark card is also a CTA link — add a very slight lift effect.

**Location**: Append inside the existing style block, after the `.feature-card:hover` rule around line 209.

**CSS to add**:

```css
.benchmark-card {
  transition:
    border-color 0.2s,
    transform 0.2s;
}
.benchmark-card:hover {
  border-color: var(--accent);
  transform: translateY(-2px);
}
```

**Edge cases**:

- The `translateY(-2px)` should only apply when `prefers-reduced-motion` is not set. The existing reveal-section already handles this pattern at root level, and the card is inside `.reveal-section`, so this is a minor enhancement that respects reduced motion naturally.

---

### Task 4: Add benchmark card stagger animation entry

**What**: If we want the benchmark card to have a stagger animation when revealed (matching the pattern of `.feature-card` and `.api-card`), add an animation entry for `.benchmark-card` in the stagger section.

**Location**: After the feature-card stagger block (lines 371-381), add:

```css
.reveal-section.visible .benchmark-card {
  opacity: 0;
  transform: translateY(20px);
  animation: cardReveal 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}
.reveal-section.visible .benchmark-card {
  animation-delay: 0.12s;
}
```

**Decision**: ✅ **Include this** — it matches the visual consistency of the page. The card should fade+slide in when scrolled into view, same as feature cards and API cards.

---

### Task 5: Final verification

**Verification checklist**:

- [ ] `vp check` passes (lint, format, type check)
- [ ] Open the page in a browser
- [ ] Nav link "Benchmarks" appears and scrolls to section
- [ ] Benchmark section renders correctly with card
- [ ] Link opens benchmark page in new tab
- [ ] Scroll reveal animation works (scroll down past Features)
- [ ] Mobile layout: card is full-width, no overflow
- [ ] Reduced-motion: no animations, card is visible immediately

---

## Implementation Order

1. Task 1: Add nav link (3 lines, trivial)
2. Task 3: Add CSS rules (6 lines, no dependencies)
3. Task 4: Add stagger animation (3 lines, no dependencies)
4. Task 2: Add section HTML (~35 lines, content body)
5. Task 5: Final verification

All CSS changes can be applied in parallel (same file, different locations — no conflict).

---

## Files Changed

- `landing-page/index.html` — nav link (+1 line), section HTML (+~40 lines), CSS rules (+8 lines), stagger animation (+4 lines)

## Total Estimated Changes

~53 lines added, 0 lines removed. Single file.
