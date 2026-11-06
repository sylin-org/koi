// Exact shared Sylin card foil interaction. Presentation only: this reads the
// pointer and card geometry, and writes five CSS custom properties.
(() => {
  function arm(root = document) {
    for (const card of root.querySelectorAll('.tcg')) {
      if (card.dataset.foilArmed === 'true') continue;
      card.dataset.foilArmed = 'true';
      card.addEventListener('pointermove', event => {
        const box = card.getBoundingClientRect();
        const x = ((event.clientX - box.left) / box.width) * 100;
        const y = ((event.clientY - box.top) / box.height) * 100;
        card.style.setProperty('--mx', `${x.toFixed(1)}%`);
        card.style.setProperty('--my', `${y.toFixed(1)}%`);
        card.style.setProperty('--gx', `${((50 - x) / 6).toFixed(1)}px`);
        card.style.setProperty('--gy', `${((50 - y) / 6).toFixed(1)}px`);
        card.style.setProperty('--holo', '1');
      });
      card.addEventListener('pointerleave', () => card.style.setProperty('--holo', '0'));
    }
  }

  window.KoiCardFoil = Object.freeze({ arm });
  arm();
})();
