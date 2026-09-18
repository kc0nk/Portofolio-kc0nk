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
  const safe = escapeHtml(source.trim());
  const lines = source.trim().split('\n');
  const nums = lines.map((_, i) => `<span>${i + 1}</span>`).join('');
  const body = safe.replace(/\b(mod|det|gcd|rank|trace)\b/g, '<span class="tok-function">$1</span>')
    .replace(/(≡|≤|≥|=|\+|-|\*|\/|\^|\||·|∈)/g, '<span class="tok-operator">$1</span>');
  return `<div class="code-window formula-window" data-lang="MATH / CONSTRAINT">
    <div class="code-window-bar"><span class="code-dot red"></span><span class="code-dot yellow"></span><span class="code-dot green"></span><span class="code-lang">MATH / CONSTRAINT</span></div>
    <div class="code-window-body"><div class="code-line-numbers">${nums}</div><pre><code>${body}</code></pre></div>
    <div class="code-window-scroll"><span></span></div>
  </div>`;
}

function flagWindow(flag) {
  const lines = flag.trim().split('\n');
  const nums = lines.map((_, i) => `<span>${i + 1}</span>`).join('');
  const body = escapeHtml(flag.trim()).replace(/(pwnsec\{[^}]+\})/gi, '<span class="tok-flag">$1</span>');
  return `<div class="code-window flag-window" data-lang="FLAG">
    <div class="code-window-bar"><span class="code-dot red"></span><span class="code-dot yellow"></span><span class="code-dot green"></span><span class="code-lang">FLAG</span></div>
    <div class="code-window-body"><div class="code-line-numbers">${nums}</div><pre><code>${body}</code></pre></div>
    <div class="code-window-scroll"><span></span></div>
  </div>`;
}

function markdownToHtml(md) {
  const lines = md.replace(/\r/g, '').split('\n');
  let html = '';
  let inCode = false, codeLang = '', code = [];
  let inMath = false, math = [];
  let inList = false, listType = null;
  let inQuote = false, quote = [];

  const closeList = () => {
    if (!inList) return;
    html += `</${listType === 'ol' ? 'ol' : 'ul'}>`;
    inList = false;
    listType = null;
  };

  const closeMath = () => {
    if (!inMath) return;
    html += formulaBlock(math.join('\n'));
    inMath = false;
    math = [];
  };

  const closeQuote = () => {
    if (!inQuote) return;
    const meaningful = quote.filter(line => line.trim() !== '');
    if (meaningful.length) {
      html += `<blockquote>${meaningful.map(line => `<p>${inlineMd(line)}</p>`).join('')}</blockquote>`;
    }
    inQuote = false;
    quote = [];
  };

  // Markdown table separator: |---|---|, | :--- | ---: |, etc.
  const isTableSeparator = (line) => {
    const cells = splitTableRow(line);
    return cells.length >= 2 && cells.every(cell => /^:?-{3,}:?$/.test(cell));
  };

  const splitTableRow = (line) => {
    let value = line.trim();
    if (value.startsWith('|')) value = value.slice(1);
    if (value.endsWith('|') && !value.endsWith('\\|')) value = value.slice(0, -1);
    return value.split(/(?<!\\)\|/).map(cell => cell.replace(/\\\|/g, '|').trim());
  };

  const renderTable = (headerLine, separatorLine, rows) => {
    const headers = splitTableRow(headerLine);
    const separators = splitTableRow(separatorLine);
    const aligns = headers.map((_, i) => {
      const cell = separators[i] || '';
      const left = cell.startsWith(':');
      const right = cell.endsWith(':');
      return left && right ? 'center' : right ? 'right' : left ? 'left' : '';
    });
    const head = headers.map((cell, i) =>
      `<th${aligns[i] ? ` style="text-align:${aligns[i]}"` : ''}>${inlineMd(cell)}</th>`
    ).join('');
    const body = rows.map(row => {
      const cells = splitTableRow(row);
      return `<tr>${headers.map((_, i) =>
        `<td${aligns[i] ? ` style="text-align:${aligns[i]}"` : ''}>${inlineMd(cells[i] || '')}</td>`
      ).join('')}</tr>`;
    }).join('');
    return `<div class="md-table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Fenced code blocks ALWAYS become the VS Code/macOS editor snapshot.
    if (/^\s*```/.test(line)) {
      if (!inCode) {
        closeList();
        closeQuote();
        inCode = true;
        codeLang = line.replace(/^\s*```/, '').trim() || 'text';
        code = [];
      } else {
        html += codeWindow(code.join('\n'), codeLang);
        inCode = false;
        code = [];
        codeLang = '';
      }
      continue;
    }
    if (inCode) {
      code.push(line);
      continue;
    }

    // Display math blocks as editor-style math snapshots.
    if (inMath) {
      if (trimmed === '$$' || trimmed === '\\]') {
        closeMath();
      } else {
        math.push(line);
      }
      continue;
    }
    if (trimmed === '$$' || trimmed === '\\[') {
      closeList();
      closeQuote();
      inMath = true;
      math = [];
      continue;
    }

    // Horizontal rule.
    if (/^\s*(?:---+|\*\*\*+|___+)\s*$/.test(line)) {
      closeList();
      closeQuote();
      html += '<hr>';
      continue;
    }

    // Table must be checked BEFORE normal paragraphs/lists.
    if (line.includes('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
      closeList();
      closeQuote();
      const rows = [];
      let j = i + 2;
      while (j < lines.length && lines[j].includes('|') && lines[j].trim() !== '') {
        rows.push(lines[j]);
        j++;
      }
      html += renderTable(line, lines[i + 1], rows);
      i = j - 1;
      continue;
    }

    // Blockquote. Empty `>` lines are treated as spacing, not visible text.
    if (/^\s*>/.test(line)) {
      closeList();
      if (!inQuote) {
        inQuote = true;
        quote = [];
      }
      quote.push(line.replace(/^\s*>\s?/, ''));
      continue;
    }
    if (inQuote) closeQuote();

    if (/^###\s+/.test(line)) {
      closeList();
      html += `<h4>${inlineMd(line.replace(/^###\s+/, ''))}</h4>`;
      continue;
    }
    if (/^##\s+/.test(line)) {
      closeList();
      html += `<h3>${inlineMd(line.replace(/^##\s+/, ''))}</h3>`;
      continue;
    }
    if (/^#\s+/.test(line)) {
      closeList();
      html += `<h2>${inlineMd(line.replace(/^#\s+/, ''))}</h2>`;
      continue;
    }

    const unordered = line.match(/^\s*[-*+]\s+(.*)$/);
    const ordered = line.match(/^\s*\d+[.)]\s+(.*)$/);
    if (unordered || ordered) {
      const wanted = ordered ? 'ol' : 'ul';
      if (!inList || listType !== wanted) {
        closeList();
        html += `<${wanted}>`;
        inList = true;
        listType = wanted;
      }
      html += `<li>${inlineMd((ordered || unordered)[1])}</li>`;
      continue;
    }

    if (!trimmed) {
      closeList();
      continue;
    }

    closeList();
    html += `<p>${inlineMd(line)}</p>`;
  }

  if (inCode) html += codeWindow(code.join('\n'), codeLang || 'text');
  closeMath();
  closeList();
  closeQuote();
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
    const resolvedUrl = new URL(url, document.baseURI).href;
    const res = await fetch(resolvedUrl);
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

// PwnSec CTF 2026 archive
const pwnsecCard = document.querySelector('#pwnsecEventCard');
const pwnsecModal = document.querySelector('#pwnsecModal');
const pwnsecOpen = () => { pwnsecModal?.classList.add('open'); pwnsecModal?.setAttribute('aria-hidden','false'); document.body.classList.add('modal-open'); };
const pwnsecClose = () => { pwnsecModal?.classList.remove('open'); pwnsecModal?.setAttribute('aria-hidden','true'); document.body.classList.remove('modal-open'); };
pwnsecCard?.addEventListener('click', e => { if (!e.target.closest('a')) pwnsecOpen(); });
pwnsecCard?.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pwnsecOpen(); } });
document.querySelectorAll('[data-close-pwnsec]').forEach(el => el.addEventListener('click', pwnsecClose));
document.querySelectorAll('[data-pwnsec-cat]').forEach(btn => btn.addEventListener('click', () => {
  const cat = btn.dataset.pwnsecCat;
  document.querySelectorAll('[data-pwnsec-cat]').forEach(b => b.classList.toggle('active', b === btn));
  document.querySelectorAll('.pwnsec-challenge').forEach(card => card.classList.toggle('hidden', cat !== 'all' && card.dataset.catItem !== cat));
  const visible = [...document.querySelectorAll('.pwnsec-challenge')].filter(c => !c.classList.contains('hidden')).length;
  const info = document.querySelector('#pwnsecInfo');
  if (info) info.innerHTML = `<strong>${visible}</strong><span>challenge write-ups archived</span><p>Setiap challenge mempunyai folder dan file <code>writeup.md</code> sendiri.</p>`;
}));
document.querySelectorAll('.pwnsec-challenge .writeup-open').forEach(link => link.addEventListener('click', e => e.stopPropagation()));

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
