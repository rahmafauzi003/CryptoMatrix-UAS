(() => {
  'use strict';

  const STORAGE_KEY = 'ruangsandi-theme';
  const root = document.documentElement;

  function preferredTheme() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved === 'light' || saved === 'dark') return saved;
    } catch (_) {}
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function applyTheme(theme) {
    root.dataset.theme = theme;
    try { localStorage.setItem(STORAGE_KEY, theme); } catch (_) {}
    document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
      const dark = theme === 'dark';
      button.setAttribute('aria-pressed', String(dark));
      button.setAttribute('title', dark ? 'Gunakan mode terang' : 'Gunakan mode gelap');
      const label = button.querySelector('[data-theme-label]');
      const icon = button.querySelector('[data-theme-icon]');
      if (label) label.textContent = dark ? 'Terang' : 'Gelap';
      if (icon) icon.textContent = dark ? '☀' : '◐';
    });
  }

  function init() {
    applyTheme(root.dataset.theme || preferredTheme());

    document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
      button.addEventListener('click', () => {
        applyTheme(root.dataset.theme === 'dark' ? 'light' : 'dark');
      });
    });

    const menuButton = document.querySelector('[data-menu-toggle]');
    const menu = document.querySelector('[data-site-menu]');
    if (menuButton && menu) {
      menuButton.addEventListener('click', () => {
        const open = menu.classList.toggle('is-open');
        menuButton.setAttribute('aria-expanded', String(open));
      });
    }

    const page = document.body.dataset.algorithm;
    if (page) {
      document.querySelectorAll('[data-algorithm-link]').forEach((link) => {
        if (link.dataset.algorithmLink === page) link.classList.add('is-active');
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
