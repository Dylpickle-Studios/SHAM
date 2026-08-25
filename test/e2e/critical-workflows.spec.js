'use strict';

const { test, expect } = require('@playwright/test');
const { ShamHarness } = require('../integration/harness');

let sham;
const username = 'browser-admin';
const password = 'browser-integration-password-123!';

test.beforeAll(async () => { sham = await new ShamHarness().start({ register: false }); });
test.afterAll(async () => { await sham?.close(); });

async function login(page) {
  await page.goto(sham.baseUrl);
  await page.locator('#auth-username').fill(username);
  await page.locator('#auth-password').fill(password);
  await page.locator('#auth-submit').click();
  await expect(page.locator('#auth-view')).toBeHidden();
}

test('first-run setup creates an administrator and opens the dashboard', async ({ page }) => {
  await page.goto(sham.baseUrl);
  await expect(page.locator('#auth-title')).toHaveText('Create administrator');
  await page.locator('#auth-username').fill(username);
  await page.locator('#auth-password').fill(password);
  await page.locator('#auth-submit').click();
  await expect(page.locator('#auth-view')).toBeHidden();
  await expect(page.locator('body')).toContainText(/Dashboard|Sites/i);
});

test('authenticated dashboard renders a real deployed site and its runtime logs', async ({ page }) => {
  await sham.request('/api/auth/login', { method: 'POST', body: { username, password } });
  const site = await sham.createNodeSite({ name: 'browser-site', domain: 'browser.integration.test' });
  await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_1');
  await login(page);
  await expect(page.locator('body')).toContainText('browser-site');
  await expect(page.locator('body')).toContainText(/runtime|logs/i);
});
