'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

// Render the shipped markup and CSS in isolation to cover every settings panel
// without depending on configured external services or administrator credentials.
test.beforeEach(async ({ page }) => {
  const root = path.resolve(__dirname, '../../public');
  const html = await fs.readFile(path.join(root, 'index.html'), 'utf8');
  await page.setContent(html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ''));
  await page.addStyleTag({ path: path.join(root, 'styles.css') });
  await page.evaluate(() => {
    globalThis.document.querySelector('#auth-view').hidden = true;
    globalThis.document.querySelector('#dashboard-view').hidden = false;
  });
});

for (const width of [320, 390, 768, 1280]) {
  test(`dashboard and settings content fit at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    const sections = await page.locator('.view-section').evaluateAll(elements => elements.map(element => element.id));
    for (const id of sections) {
      await page.evaluate(id => {
        globalThis.document.querySelectorAll('.view-section').forEach(element => { element.hidden = element.id !== id; });
        globalThis.document.querySelectorAll(`#${id} [role="tabpanel"]`).forEach(element => { element.hidden = false; });
      }, id);
      const overflow = await page.locator(`#${id}`).evaluate(section => {
        const bounds = section.getBoundingClientRect();
        return [...section.querySelectorAll('.panel, .page-header, form, .download-row, .table-wrap')]
          .filter(element => element.clientWidth > 0)
          .filter(element => {
            const rect = element.getBoundingClientRect();
            return rect.left < bounds.left - 1 || rect.right > bounds.right + 1
              || (globalThis.getComputedStyle(element).overflowX === 'visible' && element.scrollWidth > element.clientWidth + 2);
          }).map(element => element.id || element.className);
      });
      expect(overflow, id).toEqual([]);
    }
  });
}

for (const height of [844, 667, 400]) {
  test(`phone file editor and save action remain reachable at ${height}px height`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height });
    await page.evaluate(() => globalThis.document.querySelector('#files-dialog').showModal());
    const dialog = await page.locator('#files-dialog').boundingBox();
    expect(dialog.x).toBe(0);
    expect(dialog.width).toBe(390);
    expect(dialog.height).toBeLessThanOrEqual(height);
    const editor = page.locator('#document-editor');
    expect((await editor.boundingBox()).height).toBeGreaterThanOrEqual(90);
    await page.locator('#save-file').scrollIntoViewIfNeeded();
    await expect(page.locator('#save-file')).toBeInViewport();
    await page.locator('#file-search').scrollIntoViewIfNeeded();
    await expect(page.locator('#file-search')).toBeInViewport();
  });
}

for (const width of [320, 390, 768, 1280]) {
  test(`all dialogs contain expanded content and spaced controls at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    const dialogs = await page.locator('dialog').evaluateAll(elements => elements.map(element => element.id));
    for (const id of dialogs) {
      await page.evaluate(id => {
        const dialog = globalThis.document.getElementById(id);
        dialog.querySelectorAll('details').forEach(element => { element.open = true; });
        dialog.showModal();
      }, id);
      const overflow = await page.locator(`#${id}`).evaluate(dialog => [...dialog.querySelectorAll('*')]
        .filter(element => element.checkVisibility() && element.clientWidth > 0)
        .filter(element => globalThis.getComputedStyle(element).overflowX === 'visible' && element.scrollWidth > element.clientWidth + 2)
        .map(element => element.id || element.className));
      expect(overflow, id).toEqual([]);
      const touching = await page.locator(`#${id} .modal-body`).evaluateAll(bodies => bodies.flatMap(body => {
        const bounds = body.getBoundingClientRect();
        const children = [...body.children].filter(element => element.checkVisibility() && element.getBoundingClientRect().height > 0);
        return children.flatMap((element, index) => {
          const rect = element.getBoundingClientRect();
          const previous = children[index - 1]?.getBoundingClientRect();
          return rect.left < bounds.left + 10 || rect.right > bounds.right - 10 || (previous && rect.top - previous.bottom < 8)
            ? [element.id || element.className] : [];
        });
      }));
      expect(touching, id).toEqual([]);
      await page.evaluate(id => globalThis.document.getElementById(id).close(), id);
    }
  });
}

for (const width of [390, 1024]) {
  test(`long confirmation and sign-in forms remain reachable at ${width}x400`, async ({ page }) => {
    await page.setViewportSize({ width, height: 400 });
    await page.evaluate(() => {
      globalThis.document.querySelector('#action-message').textContent = 'Confirm the operation for this project. '.repeat(80);
      globalThis.document.querySelector('#action-input-wrap').hidden = false;
      globalThis.document.querySelector('#action-dialog').showModal();
    });
    // A real wheel gesture verifies scrolling is available to users, including
    // the confirmation body that previously used overflow: hidden.
    await page.locator('#action-message').hover();
    await page.mouse.wheel(0, 5000);
    await expect(page.locator('#action-input')).toBeInViewport();
    await expect(page.locator('#action-confirm')).toBeInViewport();
    await page.evaluate(() => {
      globalThis.document.querySelector('#action-dialog').close();
      globalThis.document.querySelector('#dashboard-view').hidden = true;
      globalThis.document.querySelector('#auth-view').hidden = false;
      for (const id of ['auth-oidc', 'auth-switch']) globalThis.document.getElementById(id).hidden = false;
      globalThis.document.querySelector('#auth-error').textContent = 'Sign-in failed. Please check your username and password. '.repeat(8);
    });
    await page.locator('#auth-username').scrollIntoViewIfNeeded();
    await expect(page.locator('#auth-username')).toBeInViewport();
    await page.locator('.auth-panel').hover();
    await page.mouse.wheel(0, 5000);
    await expect(page.locator('#auth-switch')).toBeInViewport();
  });
}

for (const mode of ['light', 'dark']) {
  test(`theme colors apply to auth, native controls, and feedback in ${mode} mode`, async ({ page }) => {
    await page.addScriptTag({ path: path.resolve(__dirname, '../../public/theme-init.js') });
    for (const name of ['purple', 'midnight', 'emerald', 'custom']) {
      await page.evaluate(({ name, mode }) => {
        globalThis.SHAM_THEME.apply({ ...globalThis.SHAM_THEME.get(), name, mode });
        globalThis.document.querySelector('#toast-region').innerHTML = '<div class="toast error">Failed</div><div class="toast success">Saved</div>';
      }, { name, mode });
      const colors = await page.evaluate(() => {
        const root = globalThis.getComputedStyle(globalThis.document.documentElement);
        const color = selector => globalThis.getComputedStyle(globalThis.document.querySelector(selector)).color;
        const resolved = token => {
          const probe = globalThis.document.createElement('span');
          probe.style.color = `var(${token})`;
          globalThis.document.body.append(probe);
          const result = globalThis.getComputedStyle(probe).color;
          probe.remove();
          return result;
        };
        return {
          error: color('#auth-error'), expectedError: resolved('--danger-text'),
          toastError: color('.toast.error'), toastSuccess: color('.toast.success'), expectedSuccess: resolved('--success-text'),
          fileButton: globalThis.getComputedStyle(globalThis.document.querySelector('#plugin-file'), '::file-selector-button').color,
          text: resolved('--text'),
          authBackground: globalThis.getComputedStyle(globalThis.document.querySelector('#auth-view')).backgroundImage,
          background: root.getPropertyValue('--bg').trim()
        };
      });
      expect(colors.error, name).toBe(colors.expectedError);
      expect(colors.toastError, name).toBe(colors.expectedError);
      expect(colors.toastSuccess, name).toBe(colors.expectedSuccess);
      expect(colors.fileButton, name).toBe(colors.text);
      // The chosen background must be part of the sign-in gradient.
      const rgb = colors.background.slice(1).match(/../g).map(channel => parseInt(channel, 16)).join(', ');
      expect(colors.authBackground, name).toContain(`rgb(${rgb})`);
    }
  });
}
