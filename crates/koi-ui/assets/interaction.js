// Shared interaction semantics. The browser and desktop each provide one
// bounded `KoiOperator.perform(action, payload)` adapter.
(() => {
  const root = document;

  function statusNode(control) {
    return control.closest('main')?.querySelector('.operation-status');
  }

  function payload(form) {
    const result = Object.fromEntries(new FormData(form).entries());
    for (const key of ['ttl', 'ttl_mins']) {
      if (result[key] === '') delete result[key];
      else if (key in result) result[key] = Number(result[key]);
    }
    if ('enabled' in result) result.enabled = result.enabled === 'true';
    return result;
  }

  async function perform(control, action, values = {}) {
    const bridge = window.KoiOperator;
    const output = statusNode(control);
    if (!bridge?.perform) {
      if (output) output.textContent = 'This action is unavailable from the current connection.';
      return;
    }
    const button = control.matches('button') ? control : control.querySelector('button[type="submit"]');
    if (button?.disabled) return;
    if (control.dataset.confirm && !window.confirm(control.dataset.confirm)) return;
    const required = control.dataset.requireValue;
    if (required && values.confirmation !== required) {
      if (output) output.textContent = `Type ${required} exactly to continue.`;
      return;
    }
    if (button) button.disabled = true;
    if (output) {
      output.removeAttribute('data-error');
      output.textContent = 'Applying change…';
    }
    try {
      const result = await bridge.perform(action, values);
      if (output) output.textContent = result?.message || 'Change applied.';
      await bridge.refresh?.();
    } catch (error) {
      if (output) {
        output.dataset.error = 'true';
        output.textContent = typeof error === 'string' ? error : error?.message || 'The change could not be applied.';
      }
    } finally {
      if (button?.isConnected) button.disabled = false;
    }
  }

  root.addEventListener('click', event => {
    const favorite = event.target.closest('button[data-ui-favorite]');
    if (favorite && window.KoiOperator?.kind === 'native') {
      event.preventDefault();
      perform(favorite, 'ui_set_favorite', {
        service_id: favorite.dataset.serviceId,
        favorite: favorite.dataset.uiFavorite === 'true',
      });
      return;
    }
    const button = event.target.closest('button[data-operator-action]');
    if (!button) return;
    event.preventDefault();
    perform(button, button.dataset.operatorAction,
      button.dataset.operatorUrl ? { url: button.dataset.operatorUrl } : {});
  });

  root.addEventListener('click', event => {
    const button = event.target.closest('button[data-ui-copy]');
    if (!button || window.KoiOperator?.kind !== 'native') return;
    event.preventDefault();
    navigator.clipboard.writeText(button.dataset.uiCopy).then(() => {
      button.textContent = 'Copied';
    }).catch(() => {
      const output = statusNode(button);
      if (output) {
        output.dataset.error = 'true';
        output.textContent = 'Clipboard access was refused. Select the address and copy it manually.';
      }
    });
  });

  root.addEventListener('submit', event => {
    const alias = event.target.closest('form[data-ui-alias-form]');
    if (alias && window.KoiOperator?.kind === 'native') {
      event.preventDefault();
      perform(alias, 'ui_set_alias', {
        service_id: alias.dataset.serviceId,
        friendly_alias: alias.querySelector('[data-ui-alias]')?.value.trim() || null,
      });
      return;
    }
    const form = event.target.closest('form[data-operator-action]');
    if (!form) return;
    event.preventDefault();
    perform(form, form.dataset.operatorAction, payload(form));
  });
})();
