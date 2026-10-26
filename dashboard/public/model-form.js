// The model form: provider, key, Test, model, seal. One implementation, two
// hosts.
//
// It began inline in advisor.html, as the no-model takeover. The Settings page
// is its second home, and a second copy of a key field is the one whose
// reveal, focusout and clear somebody forgets. So the markup, the style, the
// behaviour and the four sentences a seal can end with all live here, and a
// page supplies only what is genuinely its own: which nodes are being sealed,
// which line arms them, and what to do afterwards.
//
// Loaded with a plain <script src> like fleet-chip.js and peer-fetch.js. There
// is no bundler in this product and adding one is an ADR, not a convenience.
//
// What a host page supplies (all optional except targets):
//
//   home        'setup' | 'row' | 'settings' — which of the closing sentences
//               to say. The words are the same; what follows them differs.
//   targets()   the seal's targets, e.g. ['self'] or ['self','stock-node2'].
//   armCmd()    the one line that arms, absolute, for the machine that runs it.
//   armRead()   a promise of {armed, remaining_s, reason} — or a synthesised
//               one for a set of nodes, with its own `text`. null means the
//               dashboard could not say, which is not the same as unarmed.
//   installDir() the directory for the "Alternative" block, or null to leave
//               that block off (it names a menu that only exists on the host
//               being sealed, so it is wrong for a peer).
//   onJob(s)    every seal-job status, so the host can paint per-node rows.
//   onSealed(j) the single-target outcome, after this file has said its piece.
//
// The endpoints are the Settings ones on both pages: /api/settings/model/test,
// /seal/begin, /seal, /seal/job/:id. The Advisor tab posts targets:['self'].
(function () {
  'use strict';

  // ── Providers ───────────────────────────────────────────────────────
  // The descriptor rides in the option text rather than in a second line,
  // because a <select> has one line to say it in and "Anthropic" alone does
  // not say hosted.
  var PROVIDERS = [
    { id: 'xai',       name: 'xAI',        note: 'Grok, hosted',   base: 'https://api.x.ai/v1',        shape: 'openai',    cred: 'model-api-key-xai' },
    { id: 'openai',    name: 'OpenAI',     note: 'GPT, hosted',    base: 'https://api.openai.com/v1',  shape: 'openai',    cred: 'model-api-key-openai' },
    { id: 'anthropic', name: 'Anthropic',  note: 'Claude, hosted', base: 'https://api.anthropic.com',  shape: 'anthropic', cred: 'model-api-key-anthropic' }
  ];

  // The base_url an Advisor reports, back to the brand an operator picked.
  // A base this table does not know returns null and the caller falls back to
  // the host name, which is true if plain.
  function providerFor(baseUrl) {
    var b = String(baseUrl || '');
    for (var i = 0; i < PROVIDERS.length; i++) {
      if (b === PROVIDERS[i].base) return PROVIDERS[i];
    }
    return null;
  }

  function esc(x) {
    return String(x === null || x === undefined ? '' : x)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // ── Style ───────────────────────────────────────────────────────────
  // Injected once, by the file that owns the markup it styles. Two pages ship
  // this form and neither of them should carry a copy of its rules: a colour
  // fixed on one page and not the other is how the card ended up dark in
  // light mode the first time.
  var CSS = [
    '.ap-model-step { margin: 16px 0 0; }',
    /* Step headings, and under step 1 the field labels. A step is the thing
       to do; a label names a field. Same case, two weights. */
    '.ap-model-stephead { margin: 0 0 8px; font-size: 13px; letter-spacing: .04em; text-transform: uppercase;',
    '  color: var(--text); display: flex; align-items: center; }',
    '.ap-model-stephead[hidden] { display: none; }',
    '.ap-model-step .ap-model-stephead { margin-top: 0; }',
    '.ap-model-note { margin: 0 0 8px; font-size: 13px; color: var(--text-dim); }',
    /* The four controls on one line: provider, key, Test, model. Read left to
       right, in the order they are used. Test sits right after the key it
       tests, and the model list comes after Test because that is what fills
       it. Grid, not flex: the column widths are the point, and flex-basis
       negotiation gave a different answer at every viewport. Column counts
       follow the responsive standards. The provider column is
       max-content, not a fixed cap: a <select> is as wide as its longest
       option, and a cap clipped "Anthropic (Claude, hosted)" to "hoste". */
    '.ap-model-line { display: grid; align-items: end; gap: 10px 12px;',
    '  grid-template-columns: max-content minmax(260px, 1fr) auto minmax(180px, 280px); }',
    '.ap-model-field { display: flex; flex-direction: column; gap: 6px; min-width: 0; }',
    '.ap-model-field h3 { margin: 0; font-size: 11.5px; letter-spacing: .05em;',
    '  text-transform: uppercase; color: var(--text-dim); }',
    /* One height for all four, so the tops line up as exactly as the bottoms
       do. 16px on the fields, not 14: anything smaller makes iOS zoom the
       whole page on focus, and the zoom carries the right-hand control out
       of view. */
    '.ap-model-line select, .ap-model-line input { height: 40px; font-size: 16px; padding: 0 11px;',
    '  border-radius: 8px; border: 1px solid var(--border);',
    '  background: var(--bg-soft); color: inherit; width: 100%; min-width: 0; }',
    '.ap-model-line select[disabled] { opacity: .55; }',
    '.ap-model-line .ap-model-btn { height: 40px; }',
    /* The key field and its reveal. The button sits inside the field's border
       so the pair reads as one control. */
    '.ap-model-keywrap { position: relative; }',
    '.ap-model-keywrap input { padding-right: 42px; }',
    '.ap-model-eye { position: absolute; right: 1px; top: 1px; bottom: 1px; width: 38px;',
    '  display: flex; align-items: center; justify-content: center; padding: 0;',
    '  border: 0; border-radius: 0 7px 7px 0; background: transparent;',
    '  color: var(--text-dim); cursor: pointer; }',
    '.ap-model-eye:hover { color: inherit; }',
    '.ap-model-eye:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }',
    '.ap-model-eye svg { width: 18px; height: 18px; display: block; }',
    '.ap-model-eye .eyeoff { display: none; }',
    '.ap-model-eye[aria-pressed="true"] .eyeon { display: none; }',
    '.ap-model-eye[aria-pressed="true"] .eyeoff { display: block; }',
    '.ap-model-btn { min-height: 40px; padding: 0 16px; border-radius: 8px;',
    '  border: 1px solid var(--border);',
    '  background: var(--surface-hi); color: inherit; cursor: pointer; font-size: 14px; }',
    '.ap-model-btn[disabled] { opacity: .55; cursor: default; }',
    '.ap-model-primary { border-color: var(--accent); }',
    '.ap-model-verdict { margin-top: 8px; font-size: 13px; min-height: 18px; }',
    '.ap-model-verdict.wait { color: var(--text-dim); }',
    '.ap-model-verdict.ok { color: var(--green); }',
    '.ap-model-verdict.bad { color: var(--red); }',
    '.ap-model-foot { margin: 18px 0 0; font-size: 12px; color: var(--text-dim); }',
    /* The other way in, labelled as one. Set like the step labels above it,
       so it reads as a heading for the command under it, not as a question. */
    '.ap-model-alt { font-size: 12px; letter-spacing: .04em; text-transform: uppercase; color: var(--text); }',
    /* The outcome row. Done first, the sentence beside it and taking the
       width; a next block carrying a command wraps under the sentence. */
    '.ap-model-after { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 14px; margin-top: 10px; }',
    '.ap-model-after .ap-model-verdict { margin-top: 0; flex: 1 1 260px; order: 1; }',
    '.ap-model-after .ap-model-next { order: 0; margin: 0; }',
    '.ap-model-after .ap-model-next.block { order: 2; flex: 1 1 100%; }',
    '.ap-model-after .ap-model-next[hidden] { display: none; }',
    '#apModelRotate { margin-top: 10px; }',
    /* The step tip: the info-icon and its popover, as Settings draws them.
       Resting, the popover sits under its icon, invisible; shown, positionTip
       hangs it off the icon, clamped inside the viewport. */
    '.ap-info { display: inline-flex; align-items: center; justify-content: center; width: 13px; height: 13px;',
    '  margin-left: 7px; border-radius: 50%; border: 1px solid var(--text-muted); color: var(--text-muted);',
    '  font-family: Georgia, "Times New Roman", serif; font-style: italic; font-weight: 700; font-size: 9px;',
    '  line-height: 1; cursor: help; position: relative; text-transform: none; letter-spacing: 0; }',
    '.ap-info::before { content: "i"; position: relative; top: -0.5px; }',
    '.ap-info:hover, .ap-info:focus, .ap-info:focus-within { color: var(--accent); border-color: var(--accent); outline: none; }',
    '.ap-info-tip { position: absolute; top: 100%; left: 0; transform: translate(-100%, -100%);',
    '  width: max-content; min-width: 220px; max-width: 320px; padding: 12px 11px 10px;',
    '  background: var(--surface-hi); border: 1px solid var(--border-hi); border-radius: 7px;',
    '  box-shadow: 0 12px 28px rgba(0, 0, 0, .45); font-family: var(--sans); font-size: 11.5px; line-height: 1.5;',
    '  font-weight: 400; font-style: normal; color: var(--text-dim); text-align: left; text-transform: none;',
    '  letter-spacing: 0; white-space: normal; opacity: 0; pointer-events: none; transition: opacity 160ms ease 80ms; z-index: 60; }',
    '.ap-info:hover .ap-info-tip, .ap-info:focus .ap-info-tip, .ap-info:focus-within .ap-info-tip { opacity: 1; pointer-events: auto; }',
    '.ap-info-title { display: block; font-weight: 700; color: var(--text); margin-bottom: 4px; font-size: 12px; }',
    '@media (prefers-reduced-motion: reduce) { .ap-info-tip { transition: none; } }',
    /* Every host-side command is a block on its own line, absolute, with
       nothing after it. An operator copied an inline hint including the comma
       that followed it and the shell answered "No such file or directory"
       (2026-09-01). Each carries its own copy button: the command is meant to
       be pasted into a terminal on another machine, and selecting text out of
       a <pre> with a mouse is the step that goes wrong. */
    '.ap-cmd { margin: 6px 0; padding: 5px 5px 5px 10px; border-radius: 8px;',
    '  display: flex; align-items: center; gap: 8px;',
    '  border: 1px solid var(--border); background: var(--bg-soft); }',
    '.ap-cmd code { font-family: var(--mono); font-size: 12.5px; white-space: pre;',
    '  flex: 1 1 auto; min-width: 0; overflow-x: auto; padding: 3px 0; }',
    '.ap-cmd-copy { flex: 0 0 auto; display: inline-flex; align-items: center; gap: 5px;',
    '  height: 28px; padding: 0 9px; border-radius: 6px; border: 1px solid var(--border);',
    '  background: var(--surface-hi); color: var(--text-dim); cursor: pointer;',
    '  font: inherit; font-size: 11.5px; letter-spacing: .03em; }',
    '.ap-cmd-copy:hover { color: inherit; }',
    '.ap-cmd-copy:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }',
    '.ap-cmd-copy svg { width: 14px; height: 14px; display: block; }',
    '.ap-cmd-copy .ok { display: none; }',
    '.ap-cmd-copy.did { color: var(--green); border-color: var(--green); }',
    '.ap-cmd-copy.did .ok { display: block; }',
    '.ap-cmd-copy.did .cp { display: none; }',
    /* The arm line. Amber while the host is not armed, green while it is, and
       muted while nobody has said: a state pill and a sentence, the sentence
       carrying the minutes. */
    '.ap-arm { margin: 0 0 10px; padding: 9px 12px; border-radius: 8px; border: 1px solid var(--border);',
    '  display: flex; gap: 12px; align-items: center; flex-wrap: wrap; font-size: 13px; }',
    // display:flex beats the user agent's [hidden], so the retired block
    // says so with the same weight; a bare hidden attribute would do nothing.
    '.ap-arm[hidden] { display: none !important; }',
    '.ap-arm-st { font-family: var(--mono); font-size: 11px; font-weight: 700; letter-spacing: .08em;',
    '  padding: 2px 9px; border-radius: 999px; border: 1px solid var(--border); color: var(--text-muted); }',
    '.ap-arm[data-armed="no"] { border-color: rgba(var(--amber-rgb), .5); }',
    '.ap-arm[data-armed="no"] .ap-arm-st { color: var(--amber); border-color: var(--amber); }',
    '.ap-arm[data-armed="yes"] { border-color: rgba(var(--green-rgb), .5); }',
    '.ap-arm[data-armed="yes"] .ap-arm-st { color: var(--green); border-color: var(--green); }',
    '#apModelArmHow { margin-bottom: 12px; }',
    '#apModelArmHow .ap-model-foot { margin-top: 0; }',
    '@media (max-width: 1099px) {',
    '  .ap-model-line { grid-template-columns: max-content minmax(0, 1fr) auto; }',
    '  #apModelPickStep { grid-column: 1 / -1; }',
    '}',
    '@media (max-width: 720px) {',
    '  .ap-model-line { grid-template-columns: 1fr; }',
    '  #apModelPickStep { grid-column: auto; }',
    '  .ap-model-btn { width: 100%; }',
    '}'
  ].join('\n');

  function injectStyle() {
    if (document.getElementById('apModelFormStyle')) return;
    var s = document.createElement('style');
    s.id = 'apModelFormStyle';
    s.textContent = CSS;
    document.head.appendChild(s);
  }

  var CMD_COPY = '<button type="button" class="ap-cmd-copy" aria-label="Copy this command">'
    + '<svg class="cp" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></svg>'
    + '<svg class="ok" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>'
    + '<span class="lbl">copy</span></button>';

  function cmdHtml(cmd) {
    return '<pre class="ap-cmd"><code>' + esc(cmd) + '</code>' + CMD_COPY + '</pre>';
  }

  // Copy on any command block, anywhere on the page. Delegated, because most
  // of them are built and rebuilt in strings. What is copied is the code
  // element's text, exactly: never the label, never the line around it.
  // Idempotent, because two pages call it and one of them called it before
  // this file existed.
  function wireCopyButtons() {
    if (window.__apCmdCopyWired) return;
    window.__apCmdCopyWired = true;
    document.addEventListener('click', function (e) {
      var b = e.target.closest && e.target.closest('.ap-cmd-copy');
      if (!b) return;
      var pre = b.closest('.ap-cmd');
      var code = pre && pre.querySelector('code');
      if (!code) return;
      var text = code.textContent;
      var lbl = b.querySelector('.lbl');
      var done = function () {
        b.classList.add('did'); if (lbl) lbl.textContent = 'copied';
        setTimeout(function () { b.classList.remove('did'); if (lbl) lbl.textContent = 'copy'; }, 1600);
      };
      var fallback = function () {
        var ta = document.createElement('textarea');
        ta.value = text; ta.setAttribute('readonly', '');
        ta.style.cssText = 'position:fixed;top:-1000px;opacity:0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); } catch { /* nothing more to try */ }
        ta.remove();
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallback(); done(); });
      } else { fallback(); done(); }
    });
  }

  // A tip on a step heading: the Settings page's info-icon shape, carried
  // here so both hosts show the same one. The body is set by textContent, so
  // a host's words are words.
  function tipHtml(id, title, body) {
    return '<span class="ap-info" tabindex="0" role="button" aria-label="' + esc(title) + '">'
      + '<span class="ap-info-tip"><span class="ap-info-title">' + esc(title) + '</span>'
      + '<span id="' + id + '">' + esc(body) + '</span></span></span>';
  }

  // ── Markup ──────────────────────────────────────────────────────────
  // One row: provider, key, Test, model. The model column is emptied and
  // disabled until the key is tested rather than removed: taking a column out
  // of a four-column grid rebuilds the row under the operator's cursor, and
  // the row is what they are reading.
  // Three steps, numbered in the order they happen, each with a tip that
  // says what the step does and why. The fields under step 1 carry plain
  // labels: numbering them made "1. Provider, 2. API key, 3. Model" read as
  // three steps before the real second one, and the operator asked for one
  // (the lab aggregator, 2026-09-03).
  var TEMPLATE = [
    '<div id="apModelForm">',
    '  <h3 class="ap-model-stephead" id="apModelPickHead">1. Choose the model and paste its key'
    + tipHtml('apModelPickTip', 'What step 1 does',
        'Pick the provider, paste an API key from your account there, and press Test. Test asks '
      + 'the provider which models this key can reach and fills the model list; nothing is stored '
      + 'yet. Then pick the model the Advisor should use.') + '</h3>',
    '  <div class="ap-model-line">',
    '    <div class="ap-model-field">',
    '      <h3 id="apModelProviderLbl">Provider</h3>',
    '      <select id="apModelProviders" aria-labelledby="apModelProviderLbl"></select>',
    '    </div>',
    '    <div class="ap-model-field">',
    '      <h3 id="apModelKeyLbl">API key</h3>',
    '      <div class="ap-model-keywrap">',
    '        <input type="password" id="apModelKey" autocomplete="off" spellcheck="false"',
    '               placeholder="paste the key" aria-labelledby="apModelKeyLbl">',
    // The reveal. A pasted key is unreadable by design, and an operator who
    // cannot check what landed in the field finds out only when the provider
    // refuses it. It never persists: the field goes back to a password on
    // Test, on Seal, and the moment focus leaves the form.
    '        <button type="button" class="ap-model-eye" id="apModelReveal"',
    '                aria-pressed="false" aria-label="Show the key">',
    '          <svg class="eyeon" viewBox="0 0 24 24" fill="none" stroke="currentColor"',
    '               stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">',
    '            <path d="M1.8 12S5.5 5.2 12 5.2 22.2 12 22.2 12 18.5 18.8 12 18.8 1.8 12 1.8 12Z"/>',
    '            <circle cx="12" cy="12" r="3.1"/>',
    '          </svg>',
    '          <svg class="eyeoff" viewBox="0 0 24 24" fill="none" stroke="currentColor"',
    '               stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">',
    '            <path d="M9.9 5.5A9.6 9.6 0 0 1 12 5.2c6.5 0 10.2 6.8 10.2 6.8a18 18 0 0 1-3.3 4.2"/>',
    '            <path d="M6.4 6.6A17.7 17.7 0 0 0 1.8 12S5.5 18.8 12 18.8a9.9 9.9 0 0 0 4.2-.9"/>',
    '            <path d="M9.9 9.9a3.1 3.1 0 0 0 4.3 4.3"/>',
    '            <path d="M3 3l18 18"/>',
    '          </svg>',
    '        </button>',
    '      </div>',
    '    </div>',
    '    <div class="ap-model-field">',
    '      <button type="button" class="ap-model-btn" id="apModelTest">Test</button>',
    '    </div>',
    '    <div class="ap-model-field" id="apModelPickStep">',
    '      <h3 id="apModelPickLbl">Model</h3>',
    '      <select id="apModelPick" aria-labelledby="apModelPickLbl" disabled>',
    '        <option value="">test the key first</option>',
    '      </select>',
    '    </div>',
    '  </div>',
    '  <div class="ap-model-verdict" id="apModelVerdict" aria-live="polite"></div>',
    '',
    '  <div class="ap-model-step" id="apModelSealStep" hidden>',
    // Two steps, numbered in the order they happen. The window opens first
    // (root, on the host), the seal spends it second (the passkey, here). One
    // heading over both had the arm line reading as a step AFTER the passkey,
    // and an operator ran it after a seal that had already succeeded
    // (the lab aggregator, 2026-09-03).
    //
    // The arming. The sealer seals once per arming, and only root can arm: the
    // window is what keeps a dashboard account from pointing the Advisor at an
    // endpoint of its own choosing. The dashboard can stat the marker and no
    // more, which is enough to say "armed, twelve minutes left" or to print
    // the one line that arms it. The Seal button is enabled only when this
    // says armed; the sealer is still the authority and can still refuse.
    '    <h3 class="ap-model-stephead"><span id="apModelArmHead">2. Run this command on the host</span>'
    + tipHtml('apModelArmTip', 'What step 2 does', '') + '</h3>',
    '    <div class="ap-arm" id="apModelArm" data-armed="unknown" aria-live="polite">',
    '      <span class="ap-arm-st" id="apModelArmSt">CHECKING</span>',
    '      <span class="ap-arm-txt" id="apModelArmTxt">Reading whether this is armed for a seal...</span>',
    '    </div>',
    '    <div id="apModelArmHow" hidden>',
    '      <p class="ap-model-foot" id="apModelArmLead">Sealing from the browser needs root to open a',
    '        fifteen-minute window first. Over SSH or at the console, run:</p>',
    '      <pre class="ap-cmd"><code id="apModelArmCmd"></code>' + CMD_COPY + '</pre>',
    '      <p class="ap-model-foot">This page notices on its own once it is armed, and step 3 opens.</p>',
    '    </div>',
    '    <h3 class="ap-model-stephead"><span id="apModelSealHead">3. Seal it with your passkey</span>'
    + tipHtml('apModelSealTip', 'What step 3 does', '') + '</h3>',
    '    <p class="ap-model-note" id="apModelSealNote">Your passkey approves this, the way it approves',
    '      every other change. The Advisor restarts to pick the key up, which waits for any question',
    '      already running.</p>',
    '    <button type="button" class="ap-model-btn ap-model-primary" id="apModelSeal" disabled>Seal with my passkey</button>',
    // The outcome. One row: what comes next on the left (Done, or Open the
    // Advisor), the sentence beside it, so the button sits right under the
    // fields once the steps above it have retired. A next block that carries
    // a command (the seal the Advisor did not confirm) drops under the
    // sentence instead; a command beside a sentence is two things to read at
    // once.
    '    <div class="ap-model-after">',
    '      <div class="ap-model-next" id="apModelNext" hidden></div>',
    '      <div class="ap-model-verdict" id="apModelSealVerdict" aria-live="polite"></div>',
    '    </div>',
    // Two sentences and an ordering, because revoking first breaks every node
    // that has not taken the change yet. A product that quietly leaves a live
    // credential behind has misled its operator.
    '    <p class="ap-model-foot" id="apModelRotate" hidden>Sealing a new key does not revoke the old one.'
    + ' Until you revoke it at the provider, anything still holding it can spend on your account.'
    + ' Revoke it there once every node reads IN SYNC.</p>',
    // What comes after a seal. Filled in from what the Advisor itself reported
    // once it came back, never from the fact that the seal returned: the first
    // real one returned "sealed" with the Advisor reporting no model, and the
    // card sat there with nothing to do.
    '  </div>',
    '',
    // The alternative, on the host itself. Rendered only when the host page
    // gives a directory, because the menu it names exists on the machine being
    // sealed and nowhere else: printing it for a peer would be this box's path
    // wearing another box's name.
    '  <div id="apModelAlt" hidden>',
    '    <p class="ap-model-foot"><strong class="ap-model-alt">Alternative:</strong> Run this on this',
    '      dashboard&rsquo;s own server, over SSH or at the console:</p>',
    // The id sits on the <pre>, and the directory in its own span inside the
    // code, exactly as it did inline: the command is "bash " plus a path the
    // SERVER reported, never one this page invented. No sudo: the menu runs as
    // the operator and asks for sudo on the steps that need it (#955).
    '    <pre class="ap-cmd" id="apModelAltCmd"><code>bash <span id="apModelDir">$HOME/aperire-one</span></code>' + CMD_COPY + '</pre>',
    '    <p class="ap-model-foot">Then choose <strong>3) Advisor</strong>, then <strong>6) Set up / change the model</strong>.</p>',
    '  </div>',
    '</div>'
  ].join('\n');

  // ── The passkey ─────────────────────────────────────────────────────
  // The WebAuthn call, with the base64url conversions the API needs. This is
  // a second copy of advisor.html's startAssertion, deliberately: that one is
  // what every OTHER ceremony on the Advisor tab runs through, and making the
  // whole approval path depend on this file loading would trade a duplicated
  // thirty lines of base64 plumbing for a single point of failure.
  function assertPasskey(begin) {
    var o = begin.options;
    var b64 = function (s) {
      s = String(s).replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) s += '=';
      var bin = atob(s), out = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out.buffer;
    };
    var ub64 = function (buf) {
      var b = new Uint8Array(buf), s = '';
      for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    return navigator.credentials.get({
      publicKey: {
        challenge: b64(o.challenge),
        rpId: o.rpId,
        timeout: o.timeout,
        userVerification: o.userVerification || 'required',
        allowCredentials: (o.allowCredentials || []).map(function (c) {
          return { type: 'public-key', id: b64(c.id) };
        })
      }
    }).then(function (c) {
      if (!c) throw new Error('no passkey was returned');
      return {
        id: c.id, rawId: ub64(c.rawId), type: c.type,
        response: {
          authenticatorData: ub64(c.response.authenticatorData),
          clientDataJSON: ub64(c.response.clientDataJSON),
          signature: ub64(c.response.signature),
          userHandle: c.response.userHandle ? ub64(c.response.userHandle) : null
        },
        clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {}
      };
    });
  }

  // ── What a node's row says while a seal runs ────────────────────────
  // Never a bare spinner: every wait carries a truthful phrase keyed on the
  // step the host is actually on.
  function stateText(state, reason) {
    switch (state) {
      case 'queued':      return 'Waiting its turn.';
      case 'sealing':     return 'Sealing the key, then the node’s Advisor is restarting.';
      case 'sealed':      return 'Sealed.';
      case 'refused':     return 'Refused: ' + (reason || 'the node did not say why.');
      case 'unreachable': return 'Unreachable: ' + (reason || 'this dashboard could not reach it.');
      default:            return 'No state reported yet.';
    }
  }

  // What a FINISHED target reads as. One copy, because the form says it about
  // one node and the Settings page says it about each of several, and two
  // copies of these four sentences is the duplication the extraction removed.
  //
  // `submitted` is the model the operator chose, used when the target does not
  // carry one back: the job's target shape is not required to repeat it, and
  // "reports the model configured" is a worse sentence than naming it.
  function sealedSentence(t, submitted) {
    var name = t.model || submitted || 'the model';
    if (t.state !== 'sealed') {
      // `detail` is the sentence, `reason` the code behind it. The sentence
      // first: a row that read "Unreachable: unavailable" (the aggregator, 2026-09-04)
      // hid the one line that said what to run.
      return { cls: (t.state === 'refused' || t.state === 'unreachable') ? 'bad' : 'wait',
        text: stateText(t.state, t.detail || t.reason) };
    }
    // model_configured is the Advisor's own status, read back after the
    // restart. The sealer's "service active" is not it, and the first real
    // seal (2026-09-01) had the service active and the model unconfigured at
    // the same time.
    if (t.model_configured === true) {
      return { cls: 'ok', text: 'Sealed. The Advisor is back and reports ' + name + ' configured.' };
    }
    if (t.model_configured === false) {
      return { cls: 'bad', text: 'The key was sealed and the Advisor restarted, but it reports no model configured.' };
    }
    return { cls: 'wait', text: 'Sealed, and the Advisor restarted. It has not reported its model yet.' };
  }

  // ── Mount ───────────────────────────────────────────────────────────
  function mount(host, opts) {
    opts = opts || {};
    injectStyle();
    wireCopyButtons();

    var wrap = document.createElement('div');
    wrap.innerHTML = TEMPLATE;
    var form = wrap.firstElementChild;
    host.appendChild(form);

    var provider = PROVIDERS[0];
    var armTimer = null;
    var armGen = 0;
    var armLast = null;
    var jobTimer = null;

    var $ = function (id) { return document.getElementById(id); };
    function say(el, cls, text) {
      if (!el) return;
      el.className = 'ap-model-verdict ' + cls;
      el.textContent = text;
    }

    // ── The key's reveal is a look, never a state ────────────────────
    function keyHide() {
      var f = $('apModelKey'), b = $('apModelReveal');
      if (f) f.type = 'password';
      if (b) { b.setAttribute('aria-pressed', 'false'); b.setAttribute('aria-label', 'Show the key'); }
    }
    function keyToggle() {
      var f = $('apModelKey'), b = $('apModelReveal');
      if (!f || !b) return;
      var show = f.type === 'password';
      f.type = show ? 'text' : 'password';
      b.setAttribute('aria-pressed', String(show));
      b.setAttribute('aria-label', show ? 'Hide the key' : 'Show the key');
    }

    // A key that reached one provider says nothing about another, so the model
    // list and the seal step go back to where they were. The model column is
    // emptied and disabled rather than hidden: it is one of four cells in a
    // row the operator is reading, and removing it rebuilds the row under
    // them.
    function resetChoice() {
      var pick = $('apModelPick');
      if (pick) { pick.innerHTML = '<option value="">test the key first</option>'; pick.disabled = true; }
      var seal = $('apModelSealStep');
      if (seal) seal.hidden = true;
      say($('apModelVerdict'), '', '');
      armSync();
    }

    function renderProviders() {
      var sel = $('apModelProviders');
      if (!sel || sel.options.length) return;
      PROVIDERS.forEach(function (p) {
        var o = document.createElement('option');
        o.value = p.id;
        o.textContent = p.name + ' (' + p.note + ')';
        sel.appendChild(o);
      });
      sel.value = provider.id;
      sel.addEventListener('change', function () {
        for (var i = 0; i < PROVIDERS.length; i++) {
          if (PROVIDERS[i].id === sel.value) { provider = PROVIDERS[i]; break; }
        }
        resetChoice();
      });
    }

    // ── Test ─────────────────────────────────────────────────────────
    function test() {
      var btn = $('apModelTest');
      var keyEl = $('apModelKey');
      var out = $('apModelVerdict');
      var key = keyEl ? keyEl.value.replace(/\s/g, '') : '';
      // Unconditionally, and before the request rather than on its verdict: a
      // key left legible because the provider happened to refuse is the same
      // key left legible.
      keyHide();
      if (!key) { say(out, 'bad', 'Paste a key first.'); return; }
      btn.disabled = true;
      say(out, 'wait', 'Asking ' + provider.name + ' which models this key reaches...');
      fetch('/api/settings/model/test', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-aperire-csrf': '1' },
        credentials: 'same-origin',
        body: JSON.stringify({ base_url: provider.base, shape: provider.shape, key: key })
      }).then(function (r) { return r.json(); }).then(function (j) {
        btn.disabled = false;
        if (!j || !j.ok) {
          say(out, 'bad', (j && (j.error || j.detail)) || 'The provider did not answer.');
          return;
        }
        var sel = $('apModelPick');
        sel.innerHTML = '';
        (j.models || []).forEach(function (m) {
          var o = document.createElement('option');
          o.value = m; o.textContent = m;
          sel.appendChild(o);
        });
        if (!sel.options.length) {
          // A key that works and a provider that lists nothing is not a
          // failure. A provider can ship a model before its list catches up,
          // and the list should not become the ceiling.
          var o = document.createElement('option');
          o.value = ''; o.textContent = 'the provider listed no models';
          sel.appendChild(o);
        }
        say(out, 'ok', 'Connected. ' + provider.name + ' answered in '
          + (j.latency_ms / 1000).toFixed(1) + 's, and this key reaches '
          + (j.models || []).length + ' model' + ((j.models || []).length === 1 ? '' : 's') + '.');
        sel.disabled = false;
        $('apModelSealStep').hidden = false;
        // The seal step is on the page now, so the arm line starts reading.
        // Until it answers armed, the Seal button stays disabled.
        armSync();
      }).catch(function (e) {
        btn.disabled = false;
        say(out, 'bad', 'The dashboard could not run the test: ' + e.message);
      });
    }

    // ── The arm poll ─────────────────────────────────────────────────
    // Runs while the seal step is laid out, every five seconds. It reads a
    // stat of a marker; it cannot arm and it cannot read the file. What it
    // can do is enable Seal only when pressing it could work, and print the
    // one line that arms when it would not.
    function sealVisible() {
      // The arm block, not the step: after a confirmed seal the step stays
      // (it holds the outcome) and the arm block is retired, and a poll
      // against a retired block would only re-render what nobody can see.
      var arm = $('apModelArm');
      // A child of a hidden parent keeps its own computed display, so
      // laid-out is the question, not the hidden attribute.
      return !!arm && arm.getClientRects().length > 0;
    }
    function armRender(st) {
      var arm = $('apModelArm'), pill = $('apModelArmSt'), txt = $('apModelArmTxt');
      var how = $('apModelArmHow'), seal = $('apModelSeal');
      if (!arm || !pill || !txt) return;
      armLast = st;
      if (!st) {
        arm.dataset.armed = 'unknown';
        pill.textContent = 'UNREAD';
        txt.textContent = 'The dashboard could not say whether this is armed. It asks again in a moment.';
        if (how) how.hidden = true;
        if (seal) seal.disabled = true;
        return;
      }
      var cmd = $('apModelArmCmd');
      if (cmd && opts.armCmd) cmd.textContent = opts.armCmd();
      // The tip says why the line leads with the update (#812), so it follows
      // the line: an update run in another terminal flips both on this poll.
      var armTipNow = $('apModelArmTip');
      if (armTipNow && opts.armTip) armTipNow.textContent = opts.armTip();
      if (st.armed) {
        var mins = Math.floor((st.remaining_s || 0) / 60);
        arm.dataset.armed = 'yes';
        pill.textContent = 'ARMED';
        txt.textContent = st.text || ((mins >= 1 ? (mins + ' min') : ((st.remaining_s || 0) + ' s'))
          + ' left in the window. One seal spends it.');
        if (how) how.hidden = true;
        if (seal) seal.disabled = false;
        return;
      }
      arm.dataset.armed = 'no';
      pill.textContent = 'NOT ARMED';
      txt.textContent = st.text || (st.reason === 'expired'
        ? 'The last window closed. Sealing needs a fresh one.'
        : st.reason === 'future'
          ? 'The arming marker is dated in the future, which reads as a clock problem on that host. Check the clock, then arm again.'
          : 'No arming window is open.');
      if (how) how.hidden = false;
      if (seal) seal.disabled = true;
    }
    // A read in flight when the seal lands must not paint the block it was
    // read for. The seal spends the window, retirePrecondition() hides the
    // block, and a read that started before it and resolved after it wrote
    // NOT ARMED and the arm line back under the green "Sealed" (the lab aggregator,
    // 2026-09-03: the operator ran the line again, after the seal). The
    // generation ticks on every retire; a stale read is dropped.
    function armReadNow() {
      if (!sealVisible()) return Promise.resolve();
      if (!opts.armRead) { armRender(null); return Promise.resolve(); }
      var gen = armGen;
      var paint = function (st) { if (gen === armGen && sealVisible()) armRender(st); };
      return Promise.resolve(opts.armRead())
        .then(function (st) { paint(st && typeof st.armed === 'boolean' ? st : null); })
        .catch(function () { paint(null); });
    }
    // Start or stop the poll to match what is on the page. A timer left
    // running against a hidden step would fetch nothing (armReadNow checks),
    // but one that never started would leave Seal dead after Test.
    function armSync() {
      var want = sealVisible();
      if (want && !armTimer) {
        armReadNow();
        armTimer = setInterval(armReadNow, 5000);
      } else if (!want && armTimer) {
        clearInterval(armTimer); armTimer = null;
      }
    }

    // ── The seal ─────────────────────────────────────────────────────
    // One request that can take a minute and a half, most of it the Advisor
    // draining and restarting. A bare spinner for that long reads as a hang,
    // so the line says which part is happening, in the order it happens.
    function sealSteps(out) {
      var beats = [
        [0,     'Waiting for your passkey...'],
        [1,     'Sealing the key...'],
        [4000,  'Wiring it into the Advisor service...'],
        [7000,  'Restarting the Advisor. It finishes any question already running first, so this can take a minute...'],
        [60000, 'Still restarting. Reading the service back before saying anything...']
      ];
      var timers = [];
      return {
        passkeyDone: function () {
          beats.slice(1).forEach(function (b) {
            timers.push(setTimeout(function () { say(out, 'wait', b[1]); }, b[0]));
          });
        },
        stop: function () { timers.forEach(clearTimeout); }
      };
    }

    // After a seal a node accepted. Four sentences, for the four things an
    // Advisor can have said about its model afterwards, and only the first is
    // a success. `model_configured` is the Advisor's own status, read back
    // after the restart; the sealer's "service active" is not it, and the
    // first real seal (2026-09-01) had the service active and the model
    // unconfigured at the same time.
    function sealed(out, j) {
      var next = $('apModelNext');
      var home = (typeof opts.home === 'function' ? opts.home() : opts.home) || 'setup';
      var line = sealedSentence({ state: 'sealed', model: j.model, model_configured: j.model_configured });
      var rotate = $('apModelRotate');
      if (next) { next.hidden = true; next.innerHTML = ''; next.classList.remove('block'); }
      if (rotate) rotate.hidden = true;
      if (j.model_configured === true) retirePrecondition();
      if (j.model_configured === true && home !== 'setup') {
        // A change, made where the Advisor was already on the page. There is
        // nothing to open; what there is to do is say the one thing a
        // rotation leaves undone.
        say(out, line.cls, line.text);
        if (next) {
          next.innerHTML = '<button type="button" class="ap-model-btn" id="apModelDone">Done</button>';
          next.hidden = false;
        }
        if (rotate) rotate.hidden = false;
        return;
      }
      if (j.model_configured === true) {
        say(out, line.cls, line.text);
        if (next) {
          next.innerHTML = '<button type="button" class="ap-model-btn ap-model-primary" id="apModelOpen">Open the Advisor</button>';
          next.hidden = false;
        }
        return;
      }
      if (j.model_configured === false) {
        say(out, line.cls, line.text + ' The setup did not finish on the host. On that host, read '
          + 'what the Advisor said as it came up:');
        if (next) {
          next.classList.add('block');
          next.innerHTML = cmdHtml('sudo journalctl -u aperire-advisord -n 50 --no-pager')
            + '<p class="ap-model-foot">Its config is ' + esc(j.config || 'advisor/state/model.json')
            + '. The credential ' + esc(j.credential || '') + ' is on the host and the arming is spent, '
            + 'so a second seal needs it armed again first; the arm line above says how.</p>';
          next.hidden = false;
        }
        return;
      }
      say(out, line.cls, line.text + ' This settles on its own once it does.');
    }

    // After a seal the Advisor confirmed, the arm line and the Seal button
    // have done their work and come off the page. Left in place they read as
    // the next thing to do: the seal spends the window, so the poll's next
    // read says NOT ARMED with the arm line under it, beside the green
    // "Sealed" (the lab aggregator, 2026-09-02, the operator stopped and asked). A seal
    // the Advisor did NOT confirm keeps them: that text points at the arm
    // line for the second attempt. reset() brings them back for the next job.
    // The step heading that carries a given label span.
    function stepHead(id) { var el = $(id); return el ? el.closest('.ap-model-stephead') : null; }
    // The note and the lead are shown only when the host gave them words.
    // Has the precondition block been retired by a finished seal?
    //
    // It has to be a flag rather than a read of `hidden`, because renderWords
    // runs on every arm poll and noteSync below would otherwise un-hide the
    // step-3 note it had just retired: a condition already met, painted back
    // under the green sentence a few seconds later. That is the same class of
    // bug as the arm read that landed after a seal (the lab aggregator, 2026-09-03),
    // and it only became reachable once the note had text in it.
    var preconditionRetired = false;
    function noteSync() {
      var note = $('apModelSealNote'), lead = $('apModelArmLead');
      if (note) note.hidden = preconditionRetired || !note.textContent.trim();
      if (lead) lead.hidden = !lead.textContent.trim();
    }
    function retirePrecondition() {
      preconditionRetired = true;
      var arm = $('apModelArm'), how = $('apModelArmHow'), seal = $('apModelSeal');
      var armHead = stepHead('apModelArmHead'), sealHead = stepHead('apModelSealHead'), note = $('apModelSealNote');
      if (armHead) armHead.hidden = true;
      if (arm) arm.hidden = true;
      if (how) how.hidden = true;
      if (sealHead) sealHead.hidden = true;
      if (note) note.hidden = true;
      if (seal) seal.hidden = true;
      if (armTimer) { clearInterval(armTimer); armTimer = null; }
      armGen++;
    }
    function restorePrecondition() {
      preconditionRetired = false;
      var arm = $('apModelArm'), seal = $('apModelSeal');
      var armHead = stepHead('apModelArmHead'), sealHead = stepHead('apModelSealHead');
      if (armHead) armHead.hidden = false;
      if (arm) arm.hidden = false;
      if (sealHead) sealHead.hidden = false;
      noteSync();
      if (seal) seal.hidden = false;
    }

    // A finished single-target outcome, applied whole: what the page says, and
    // what the page then does about it. One entry point, so a walk driving an
    // ending drives the same path a real job does.
    function sealedOutcome(out, j) {
      sealed(out, j);
      if (opts.onSealed) opts.onSealed(j);
    }

    function stopJob() { if (jobTimer) { clearTimeout(jobTimer); jobTimer = null; } }

    // Read the job until it is done, every two seconds. Never the key, never
    // the hash: the job status carries neither and this never asks for them.
    function pollJob(jobId, out, steps, submitted) {
      var tick = function () {
        fetch('/api/settings/model/seal/job/' + encodeURIComponent(jobId), { credentials: 'same-origin' })
          .then(function (r) { return r.json(); })
          .then(function (st) {
            if (opts.onJob) opts.onJob(st, { model: submitted });
            if (!st || !st.done) { jobTimer = setTimeout(tick, 2000); return; }
            steps.stop();
            stopJob();
            armReadNow();
            var rows = (st.targets || []);
            if (rows.length === 1) {
              var t = rows[0];
              var j = {
                ok: t.state === 'sealed',
                label: t.label,
                // The chosen model, when the target did not carry one back.
                model: t.model || submitted || null,
                model_configured: t.model_configured === undefined ? null : t.model_configured,
                credential: t.credential || '',
                config: t.config || '',
                detail: t.detail || t.reason || ''
              };
              if (!j.ok) {
                say(out, 'bad', stateText(t.state, t.detail || t.reason));
                if (opts.onSealed) opts.onSealed(j);
              } else {
                sealedOutcome(out, j);
              }
              return;
            }
            var okCount = rows.filter(function (r) { return r.state === 'sealed'; }).length;
            var bad = rows.length - okCount;
            if (bad === 0 && rows.every(function (r) { return r.model_configured === true; })) retirePrecondition();
            say(out, bad ? 'bad' : 'ok', okCount + ' of ' + rows.length + ' sealed'
              + (bad ? ', ' + bad + ' did not. Each row below says which and why.' : '. Each row below says what its Advisor reported.'));
            if (opts.onSealed) opts.onSealed({ ok: bad === 0, targets: rows });
          })
          .catch(function () {
            // A poll that did not land is not a failure of the seal. Ask
            // again; the job outlives one dropped request.
            jobTimer = setTimeout(tick, 2000);
          });
      };
      tick();
    }

    function seal() {
      var btn = $('apModelSeal');
      var keyEl = $('apModelKey');
      var out = $('apModelSealVerdict');
      var model = ($('apModelPick') || {}).value || '';
      var key = keyEl ? keyEl.value.replace(/\s/g, '') : '';
      var targets = (opts.targets ? opts.targets() : ['self']) || [];
      keyHide();
      if (!key) { say(out, 'bad', 'The key field is empty.'); return; }
      if (!model) { say(out, 'bad', 'Choose a model first.'); return; }
      if (!targets.length) { say(out, 'bad', 'Choose at least one node first.'); return; }
      // The button is disabled while nothing is armed; this is the belt behind
      // it, so a click that slipped through does not spend a passkey ceremony
      // on a seal that will be refused.
      if (!armLast || !armLast.armed) {
        say(out, 'bad', 'This is not armed for a seal. The arm line above says how.');
        armReadNow();
        return;
      }
      btn.disabled = true;
      var steps = sealSteps(out);
      say(out, 'wait', 'Waiting for your passkey...');

      fetch('/api/settings/model/seal/begin', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-aperire-csrf': '1' },
        credentials: 'same-origin',
        body: JSON.stringify({
          targets: targets, base_url: provider.base, shape: provider.shape,
          model: model, credential_name: provider.cred
        })
      }).then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) throw new Error(j.detail || j.error || ('the dashboard refused: ' + r.status));
          return j;
        });
      }).then(function (begin) {
        return assertPasskey(begin).then(function (assertion) {
          steps.passkeyDone();
          return fetch('/api/settings/model/seal', {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'x-aperire-csrf': '1' },
            credentials: 'same-origin',
            body: JSON.stringify({ challenge_id: begin.challenge_id, response: assertion, key: key })
          });
        });
      }).then(function (r) {
        return r.json().then(function (j) { return { status: r.status, body: j }; });
      }).then(function (r) {
        // The key is gone from this page from here on: the field is cleared
        // the moment the server has it, and never repopulated.
        if (keyEl) keyEl.value = '';
        if (!r.body || !r.body.job_id) {
          steps.stop();
          armReadNow();
          say(out, 'bad', (r.body && (r.body.detail || r.body.error)) || 'The dashboard refused to start the seal.');
          return;
        }
        if (opts.onJob) {
          opts.onJob({ job_id: r.body.job_id, done: false, targets: (r.body.targets || targets).map(function (l) {
            return { label: l, state: 'queued' };
          }) }, { model: model });
        }
        pollJob(r.body.job_id, out, steps, model);
      }).catch(function (e) {
        steps.stop();
        stopJob();
        armReadNow();
        say(out, 'bad', e && e.name === 'NotAllowedError'
          ? 'The passkey was not approved, so nothing was sealed.'
          : ('Nothing was sealed: ' + (e.message || e)));
      });
    }

    // ── Wiring, once, on the form itself ─────────────────────────────
    renderProviders();
    $('apModelTest').addEventListener('click', test);
    $('apModelSeal').addEventListener('click', seal);
    $('apModelReveal').addEventListener('click', keyToggle);
    // Focus leaving the form hides the key again. focusout carries where focus
    // went, so moving between the field and its own eye button does not count
    // as leaving; a relatedTarget of null (the window lost focus altogether)
    // does, which is the case this exists for.
    form.addEventListener('focusout', function (e) {
      if (!form.contains(e.relatedTarget)) keyHide();
    });
    // Done and Open the Advisor are rebuilt in a string each time, so they are
    // reached by delegation rather than by a listener that would be attached
    // to an element already replaced.
    form.addEventListener('click', function (e) {
      var t = e.target;
      if (!t || !t.id) return;
      if (t.id === 'apModelDone' && opts.onDone) opts.onDone();
      if (t.id === 'apModelOpen' && opts.onOpenAdvisor) opts.onOpenAdvisor();
    });

    // The three sentences that name the machine. Rule (c) for host-side
    // commands: the copy around a command says which box to run it on, and
    // this page and Settings are looking at different boxes.
    function renderWords() {
      var head = $('apModelSealHead'), note = $('apModelSealNote'), lead = $('apModelArmLead');
      var armHead = $('apModelArmHead');
      if (armHead && opts.armHeading) armHead.textContent = opts.armHeading();
      if (head && opts.sealHeading) head.textContent = opts.sealHeading();
      if (note && opts.sealNote) note.textContent = opts.sealNote();
      if (lead && opts.armLead) lead.textContent = opts.armLead();
      var armTip = $('apModelArmTip'), sealTip = $('apModelSealTip');
      if (armTip && opts.armTip) armTip.textContent = opts.armTip();
      if (sealTip && opts.sealTip) sealTip.textContent = opts.sealTip();
      noteSync();
      var cmd = $('apModelArmCmd');
      if (cmd && opts.armCmd) cmd.textContent = opts.armCmd();
    }

    // A shown tip hangs off its icon (absolute, so it follows the page when
    // the page moves under it) and is clamped inside the viewport sideways;
    // it flips above the icon when the fold below is short. The form is never
    // inside a scrolling box, so nothing clips it. Settings' own tips sit in
    // table wraps and are fixed to the viewport instead; a tip fixed at focus
    // time here was left behind when the page settled after a scroll.
    function positionTip(icon) {
      var tip = icon.querySelector('.ap-info-tip');
      if (!tip) return;
      var r = icon.getBoundingClientRect(), vw = window.innerWidth, margin = 8;
      var vh = (window.visualViewport && window.visualViewport.height) || window.innerHeight;
      tip.style.transform = 'none';
      var w = tip.offsetWidth, h = tip.offsetHeight;
      var left = r.left + r.width / 2 - w / 2;
      if (left + w > vw - margin) left = vw - margin - w;
      if (left < margin) left = margin;
      var below = vh - r.bottom >= h + margin || r.top <= vh - r.bottom;
      tip.style.left = (left - r.left).toFixed(1) + 'px';
      tip.style.top = below ? (r.height + 4).toFixed(1) + 'px' : (-4 - h).toFixed(1) + 'px';
    }
    function restTip(icon) {
      var tip = icon.querySelector('.ap-info-tip');
      if (!tip) return;
      setTimeout(function () {
        if (icon.matches(':hover') || icon === document.activeElement || icon.contains(document.activeElement)) return;
        tip.style.transform = ''; tip.style.left = ''; tip.style.top = '';
      }, 300);
    }
    form.addEventListener('mouseover', function (e) {
      var icon = e.target.closest && e.target.closest('.ap-info');
      if (icon && !(e.target.closest && e.target.closest('.ap-info-tip'))) positionTip(icon);
    });
    form.addEventListener('mouseout', function (e) {
      var icon = e.target.closest && e.target.closest('.ap-info');
      if (icon && !icon.contains(e.relatedTarget) && icon !== document.activeElement) restTip(icon);
    });
    form.addEventListener('focusin', function (e) {
      var icon = e.target.closest && e.target.closest('.ap-info');
      if (icon) positionTip(icon);
    });
    form.addEventListener('focusout', function (e) {
      var icon = e.target.closest && e.target.closest('.ap-info');
      if (icon) restTip(icon);
    });

    function renderAlternative() {
      var alt = $('apModelAlt'), dirEl = $('apModelDir');
      var dir = opts.installDir ? opts.installDir() : null;
      if (!alt || !dirEl) return;
      if (!dir) { alt.hidden = true; return; }
      dirEl.textContent = dir + '/aperire-one';
      alt.hidden = false;
    }
    renderAlternative();
    renderWords();

    // ── The controller ───────────────────────────────────────────────
    return {
      el: form,
      // Move the form to another host. Its listeners and its field values
      // survive a move; the key deliberately does not, because a key pasted
      // for one job must not turn up prefilled for another.
      //
      // Not on every call. A poll that asks for the home the form is already
      // in must leave it alone: resetting there wiped a key mid-paste and a
      // live verdict a few seconds after it was said (CI, 2026-09-02).
      place: function (target, reset) {
        var moved = form.parentNode !== target;
        if (moved) target.appendChild(form);
        if (moved || reset) this.reset();
        renderAlternative();
        renderWords();
        armSync();
      },
      reset: function () {
        var keyEl = $('apModelKey');
        if (keyEl) keyEl.value = '';
        keyHide();
        restorePrecondition();
        resetChoice();
        say($('apModelSealVerdict'), '', '');
        var next = $('apModelNext'), rotate = $('apModelRotate');
        if (next) { next.hidden = true; next.innerHTML = ''; next.classList.remove('block'); }
        if (rotate) rotate.hidden = true;
        stopJob();
      },
      // Prefill the provider from what an Advisor reports. The key is never
      // prefilled: this page never has it.
      setProviderByBase: function (baseUrl) {
        var p = providerFor(baseUrl);
        if (!p) return;
        provider = p;
        var sel = $('apModelProviders');
        if (sel) sel.value = p.id;
      },
      focusKey: function () { var k = $('apModelKey'); if (k) k.focus(); },
      clearKey: function () { var k = $('apModelKey'); if (k) k.value = ''; keyHide(); },
      hideKey: keyHide,
      armSync: armSync,
      armRefresh: armReadNow,
      sealVerdictEl: function () { return $('apModelSealVerdict'); },
      sealedOutcome: sealedOutcome,
      renderAlternative: renderAlternative,
      renderWords: renderWords
    };
  }

  // At load, not at mount. The command block (.ap-cmd) is styled here now, and
  // the Advisor tab prints command blocks outside this form: the invitation
  // card, the trust remedy, the journal line after a seal. Waiting for a mount
  // that a sealed host never performs left those unstyled, and an unwrapped
  // command ran the page off the side at 390 (theme-walk, 2026-09-02).
  injectStyle();

  window.ApModelForm = {
    PROVIDERS: PROVIDERS,
    providerFor: providerFor,
    // The one implementation of the assertion this product has on a settings
    // surface. Settings' operator controls promote and add administrators,
    // which is a privilege grant and asks for the acting admin's passkey the
    // same way a seal does; exporting it is what keeps that from becoming a
    // third copy of the base64 plumbing.
    assertPasskey: assertPasskey,
    stateText: stateText,
    sealedSentence: sealedSentence,
    cmdHtml: cmdHtml,
    wireCopyButtons: wireCopyButtons,
    mount: mount
  };
})();
