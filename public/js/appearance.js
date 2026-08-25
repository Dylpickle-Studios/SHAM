'use strict';

function copyTheme(theme) {
  return { name: theme.name, mode: theme.mode || 'system', custom: { ...theme.custom } };
}

function populateThemeDialog() {
  state.themeDraft = copyTheme(window.SHAM_THEME.get());
  const custom = state.themeDraft.custom;
  $('#theme-accent').value = custom.accent;
  $('#theme-accent-secondary').value = custom.accentSecondary;
  $('#theme-background').value = custom.background;
  $('#theme-panel').value = custom.panel;
  $('#theme-text').value = custom.text;
  $('#theme-radius').value = String(custom.radius);
  $('#theme-radius-value').textContent = String(custom.radius);
  updateThemePicker();
}

function updateThemePicker() {
  $$('.theme-preset').forEach((button) => {
    const active = button.dataset.themePreset === state.themeDraft.name;
    button.classList.toggle('active', active);
    button.setAttribute('aria-checked', String(active));
    button.setAttribute('role', 'radio');
    button.tabIndex = active ? 0 : -1;
  });
  $$('.theme-mode-option').forEach((button) => {
    const active = button.dataset.themeMode === state.themeDraft.mode;
    button.classList.toggle('active', active);
    button.setAttribute('aria-checked', String(active));
    button.tabIndex = active ? 0 : -1;
  });
  $('#custom-theme-fields').hidden = state.themeDraft.name !== 'custom';
  updateThemeValidation();
}

$('.theme-mode-toggle').addEventListener('click', (event) => {
  const button = event.target.closest('[data-theme-mode]');
  if (!button) return;
  state.themeDraft.mode = button.dataset.themeMode;
  updateThemePicker();
});

$('.theme-mode-toggle').addEventListener('keydown', (event) => {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
  const buttons = $$('.theme-mode-option');
  const current = Math.max(0, buttons.indexOf(document.activeElement));
  let next;
  if (event.key === 'Home') next = 0;
  else if (event.key === 'End') next = buttons.length - 1;
  else next = (current + (event.key === 'ArrowRight' ? 1 : -1) + buttons.length) % buttons.length;
  event.preventDefault();
  state.themeDraft.mode = buttons[next].dataset.themeMode;
  updateThemePicker();
  buttons[next].focus();
});

$('.theme-presets').addEventListener('click', (event) => {
  const button = event.target.closest('[data-theme-preset]');
  if (!button) return;
  state.themeDraft.name = button.dataset.themePreset;
  updateThemePicker();
});

$('.theme-presets').addEventListener('keydown', (event) => {
  if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
  const buttons = $$('.theme-preset');
  const current = Math.max(0, buttons.indexOf(document.activeElement));
  let next;
  if (event.key === 'Home') next = 0;
  else if (event.key === 'End') next = buttons.length - 1;
  else next = (current + (['ArrowRight', 'ArrowDown'].includes(event.key) ? 1 : -1) + buttons.length) % buttons.length;
  event.preventDefault();
  state.themeDraft.name = buttons[next].dataset.themePreset;
  updateThemePicker();
  buttons[next].focus();
});

function readCustomTheme() {
  return {
    accent: $('#theme-accent').value,
    accentSecondary: $('#theme-accent-secondary').value,
    background: $('#theme-background').value,
    panel: $('#theme-panel').value,
    text: $('#theme-text').value,
    radius: Number($('#theme-radius').value)
  };
}

function updateThemeValidation() {
  const error = $('#theme-form-error');
  if (!error || state.themeDraft?.name !== 'custom') {
    if (error) error.textContent = '';
    return true;
  }
  const result = window.SHAM_THEME.validateCustom(readCustomTheme());
  error.textContent = result.valid ? `Contrast check passed (${result.minimum.toFixed(1)}:1 minimum).` : result.message;
  error.classList.toggle('success-text', result.valid);
  return result.valid;
}

$$('#custom-theme-fields input').forEach((input) => input.addEventListener('input', () => {
  if (input.id === 'theme-radius') $('#theme-radius-value').textContent = input.value;
  updateThemeValidation();
}));
$('#theme-form').addEventListener('submit', (event) => {
  event.preventDefault();
  state.themeDraft.custom = readCustomTheme();
  if (!updateThemeValidation()) return;
  const persisted = window.SHAM_THEME.save(state.themeDraft);
  const label = state.themeDraft.name === 'custom' ? 'Custom' : state.themeDraft.name[0].toUpperCase() + state.themeDraft.name.slice(1);
  const modeLabel = state.themeDraft.mode[0].toUpperCase() + state.themeDraft.mode.slice(1);
  toast(persisted ? `${label} · ${modeLabel} applied.` : `${label} · ${modeLabel} applied for this session; browser storage is unavailable.`, persisted ? 'success' : 'warning');
});
$('#theme-reset').addEventListener('click', () => {
  const persisted = window.SHAM_THEME.reset();
  populateThemeDialog();
  toast(persisted ? 'Theme reset to Purple · System.' : 'Theme reset for this session; browser storage is unavailable.', persisted ? 'success' : 'warning');
});

$('#operations-tab-appearance')?.addEventListener('click', populateThemeDialog);
populateThemeDialog();
