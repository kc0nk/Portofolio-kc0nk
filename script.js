const nav = document.querySelector('.nav');
const menuToggle = document.querySelector('.menu-toggle');
const navLinks = [...document.querySelectorAll('.nav a')];
const sections = [...document.querySelectorAll('main section[id]')];

menuToggle?.addEventListener('click', () => {
  const open = nav.classList.toggle('open');
  menuToggle.setAttribute('aria-expanded', String(open));
});

navLinks.forEach(link => link.addEventListener('click', () => {
  nav.classList.remove('open');
  menuToggle?.setAttribute('aria-expanded', 'false');
}));

const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (!entry.isIntersecting) return;
    navLinks.forEach(link => link.classList.toggle('active', link.getAttribute('href') === `#${entry.target.id}`));
    entry.target.querySelectorAll('.reveal').forEach(el => el.classList.add('visible'));
  });
}, { rootMargin: '-35% 0px -50% 0px', threshold: 0 });
sections.forEach(section => observer.observe(section));

document.querySelectorAll('.filter').forEach(button => {
  button.addEventListener('click', () => {
    document.querySelectorAll('.filter').forEach(b => b.classList.remove('active'));
    button.classList.add('active');
    const filter = button.dataset.filter;
    document.querySelectorAll('.writeup-card').forEach(card => {
      card.hidden = filter !== 'all' && card.dataset.category !== filter;
    });
  });
});

// Markdown writeup viewer (served over the same origin)
const mdModal = document.querySelector('.md-modal');
const mdContent = document.querySelector('.md-content');
const mdTitle = document.querySelector('.md-title');

const escapeHtml = (str) => str.replace(/[&<>\"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','\\':'&#92;','"':'&quot;'}[ch]));

const highlightCode = (source, lang) => {
  let s = escapeHtml(source);
  // Keep highlighting deliberately lightweight and safe: the source is escaped first.
  if (/^(python|py|sage|javascript|js|typescript|ts|bash|sh|shell|c|cpp|rust|go|php|ruby|java)$/i.test(lang)) {
    s = s.replace(/(#[^\n]*|\/\/[^\n]*)/g, '<span class="tok-comment">$1</span>');
    s = s.replace(/(&quot;.*?&quot;|&#39;.*?&#39;|`.*?`)/g, '<span class="tok-string">$1</span>');
    s = s.replace(/\b(def|class|return|if|else|elif|for|while|in|import|from|as|try|except|with|assert|lambda|True|False|None|function|const|let|var|new|public|private|static|fn|match|use|package)\b/g, '<span class="tok-keyword">$1</span>');
    s = s.replace(/\b(ZZ|matrix|vector|IntegerLattice|map|range|print|len|int|str|bytes|open|sum)\b/g, '<span class="tok-function">$1</span>');
    s = s.replace(/\b\d+(?:\.\d+)?\b/g, '<span class="tok-number">$&</span>');
  }
  return s;
};

const inlineMd = (str) => escapeHtml(str)
  .replace(/`([^`]+)`/g, '<code>$1</code>')
  .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
  .replace(/\*([^*]+)\*/g, '<em>$1</em>');

function codeWindow(source, lang) {
  const lines = source.split('\n');
  const lineNumbers = lines.map((_, i) => `<span>${i + 1}</span>`).join('');
  const highlighted = highlightCode(source, lang);
  return `<div class="code-window" data-lang="${escapeHtml(lang || 'text')}">
    <div class="code-window-bar"><span class="code-dot red"></span><span class="code-dot yellow"></span><span class="code-dot green"></span><span class="code-lang">${escapeHtml(lang || 'TEXT')}</span></div>
    <div class="code-window-body"><div class="code-line-numbers">${lineNumbers}</div><pre><code>${highlighted}</code></pre></div>
    <div class="code-window-scroll"><span></span></div>
  </div>`;
}

function formulaBlock(source) {
  const formula = escapeHtml(source.trim())
    .replace(/\n+/g, '<br>')
    .replace(/\b(mod|det)\b/g, '<span class="math-op">$1</span>');
  return `<div class="formula-card"><div class="formula-label">EQUATION / CONSTRAINT</div><div class="formula-body">${formula}</div></div>`;
}

function markdownToHtml(md) {
  const lines = md.replace(/\r/g, '').split('\n');
  let html = '';
  let inCode = false, codeLang = '', code = [];
  let inMath = false, math = [];
  let inList = false;
  const closeList = () => { if (inList) { html += '</ul>'; inList = false; } };
  const closeMath = () => { if (inMath) { html += formulaBlock(math.join('\n')); inMath = false; math = []; } };

  for (const line of lines) {
    if (line.trim() === '$$' || line.trim() === '\\[') {
      if (!inMath) { closeList(); inMath = true; math = []; }
      continue;
    }
    if (line.trim() === '\\]') { closeMath(); continue; }
    if (inMath) { math.push(line); continue; }

    if (line.startsWith('```')) {
      if (!inCode) { closeList(); inCode = true; codeLang = line.slice(3).trim(); code = []; }
      else {
        // `text` blocks are treated as mathematical constraint blocks when they contain equation notation.
        const raw = code.join('\n');
        const isFormula = /^(text|formula|math)?$/i.test(codeLang) && /(?:≡|≤|≥|\bmod\b|\^\d|\|\||∑|∏|[A-Za-z]·[A-Za-z])/.test(raw);
        html += isFormula ? formulaBlock(raw) : codeWindow(raw, codeLang || 'text');
        inCode = false; code = []; codeLang = '';
      }
      continue;
    }
    if (inCode) { code.push(line); continue; }
    if (/^### /.test(line)) { closeList(); html += `<h4>${inlineMd(line.slice(4))}</h4>`; continue; }
    if (/^## /.test(line)) { closeList(); html += `<h3>${inlineMd(line.slice(3))}</h3>`; continue; }
    if (/^# /.test(line)) { closeList(); html += `<h2>${inlineMd(line.slice(2))}</h2>`; continue; }
    if (/^- /.test(line)) { if (!inList) { html += '<ul>'; inList = true; } html += `<li>${inlineMd(line.slice(2))}</li>`; continue; }
    if (!line.trim()) { closeList(); continue; }
    closeList(); html += `<p>${inlineMd(line)}</p>`;
  }
  closeMath();
  closeList();
  return html;
}

async function openMarkdown(url, title) {
  if (!mdModal || !mdContent) return;
  mdTitle.textContent = title || 'CTF Writeup';
  mdContent.innerHTML = '<p class=\"md-loading\">Loading writeup…</p>';
  mdModal.classList.add('open');
  mdModal.setAttribute('aria-hidden', 'false');
  document.body.classList.add('modal-open');
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    mdContent.innerHTML = markdownToHtml(text);
  } catch (err) {
    mdContent.innerHTML = `<p class=\"md-error\">Unable to load ${escapeHtml(url)}. Run the portfolio through a local web server (for example <code>python -m http.server 8080</code>).</p>`;
  }
}

document.querySelectorAll('.writeup-open').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    openMarkdown(link.dataset.md, link.dataset.title);
  });
});
document.querySelectorAll('[data-close-md]').forEach(el => el.addEventListener('click', () => {
  mdModal?.classList.remove('open');
  mdModal?.setAttribute('aria-hidden', 'true');
  document.body.classList.remove('modal-open');
}));

window.addEventListener('load', () => {
  document.querySelectorAll('.hero .reveal').forEach((el, i) => setTimeout(() => el.classList.add('visible'), 120 + i * 120));
});

// Certificate lightbox
const certModal = document.querySelector('.cert-modal');
const certModalImage = document.querySelector('.cert-modal-image');
const certModalCaption = document.querySelector('.cert-modal-caption');

document.querySelectorAll('.cert-card').forEach(card => {
  card.addEventListener('click', () => {
    certModalImage.src = card.dataset.image;
    certModalImage.alt = card.dataset.title || 'Certificate';
    certModalCaption.textContent = card.dataset.title || '';
    certModal.classList.add('open');
    certModal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
  });
});
document.querySelectorAll('[data-close-cert]').forEach(el => el.addEventListener('click', () => {
  certModal.classList.remove('open');
  certModal.setAttribute('aria-hidden', 'true');
  document.body.classList.remove('modal-open');
}));
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    certModal?.classList.remove('open');
    certModal?.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('modal-open');
  }
});


// FPS-style crosshair cursor + click/shoot feedback
const crosshair = document.querySelector('.crosshair-cursor');
if (crosshair && window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
  let raf = 0;
  let mx = -100, my = -100;
  const updateCursor = () => {
    crosshair.style.left = `${mx}px`;
    crosshair.style.top = `${my}px`;
    raf = 0;
  };
  window.addEventListener('mousemove', (e) => {
    mx = e.clientX;
    my = e.clientY;
    if (!raf) raf = requestAnimationFrame(updateCursor);
    crosshair.classList.add('ready');
  }, { passive:true });
  window.addEventListener('mouseleave', () => crosshair.classList.remove('ready'));
  window.addEventListener('mousedown', () => {
    crosshair.classList.remove('shooting');
    void crosshair.offsetWidth;
    crosshair.classList.add('shooting');
  });
  crosshair.addEventListener('animationend', () => crosshair.classList.remove('shooting'));
}

// Unified BrunnerCTF category archive
const eventTabs = [...document.querySelectorAll('.event-tab')];
const eventChallenges = [...document.querySelectorAll('.event-challenge')];
const eventPanels = [...document.querySelectorAll('.event-panel')];
function showEventCategory(filter){
  eventTabs.forEach(tab => {
    const active = tab.dataset.eventFilter === filter;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', String(active));
  });
  eventPanels.forEach(panel => panel.classList.toggle('hidden', panel.dataset.eventPanel !== filter));
  eventChallenges.forEach(card => {
    const visible = filter === 'all' || card.dataset.eventCategory === filter;
    card.classList.toggle('is-hidden', !visible);
  });
}
eventTabs.forEach(tab => tab.addEventListener('click', () => showEventCategory(tab.dataset.eventFilter)));

// Unified BrunnerCTF archive modal
const brunnerCard = document.querySelector('#brunnerEventCard');
const brunnerModal = document.querySelector('#brunnerModal');
const brunnerOpen = () => { brunnerModal?.classList.add('open'); brunnerModal?.setAttribute('aria-hidden','false'); document.body.classList.add('modal-open'); };
const brunnerClose = () => { brunnerModal?.classList.remove('open'); brunnerModal?.setAttribute('aria-hidden','true'); document.body.classList.remove('modal-open'); };
brunnerCard?.addEventListener('click', brunnerOpen);
brunnerCard?.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); brunnerOpen(); } });
document.querySelectorAll('[data-close-brunner]').forEach(el => el.addEventListener('click', brunnerClose));
document.querySelectorAll('.brunner-cat').forEach(btn => btn.addEventListener('click', () => {
  const cat = btn.dataset.cat;
  document.querySelectorAll('.brunner-cat').forEach(b => b.classList.toggle('active', b === btn));
  document.querySelectorAll('.brunner-info').forEach(info => info.classList.toggle('hidden', info.dataset.brunnerInfo !== cat));
  document.querySelectorAll('.brunner-challenge').forEach(card => card.classList.toggle('hidden', cat !== 'all' && card.dataset.catItem !== cat));
}));
document.addEventListener('keydown', e => { if (e.key === 'Escape') brunnerClose(); });
