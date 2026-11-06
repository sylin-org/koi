import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('../assets/card-effect.js', import.meta.url), 'utf8');

test('card foil clones the Sylin pointer geometry and arms only once', () => {
  const listeners = new Map();
  const properties = new Map();
  const card = {
    dataset: {},
    style: { setProperty: (name, value) => properties.set(name, value) },
    addEventListener(name, listener) {
      assert.equal(listeners.has(name), false, `${name} should be armed once`);
      listeners.set(name, listener);
    },
    getBoundingClientRect: () => ({ left: 10, top: 20, width: 300, height: 478 }),
  };
  const document = { querySelectorAll: selector => selector === '.tcg' ? [card] : [] };
  const window = {};

  vm.runInNewContext(source, { document, window });
  assert.equal(card.dataset.foilArmed, 'true');
  assert.deepEqual([...listeners.keys()].sort(), ['pointerleave', 'pointermove']);

  listeners.get('pointermove')({ clientX: 85, clientY: 378.5 });
  assert.equal(properties.get('--mx'), '25.0%');
  assert.equal(properties.get('--my'), '75.0%');
  assert.equal(properties.get('--gx'), '4.2px');
  assert.equal(properties.get('--gy'), '-4.2px');
  assert.equal(properties.get('--holo'), '1');

  window.KoiCardFoil.arm(document);
  listeners.get('pointerleave')();
  assert.equal(properties.get('--holo'), '0');
});
