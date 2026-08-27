'use strict';

const { test, expect } = require('@playwright/test');
const { ShamHarness } = require('../integration/harness');

let sham;
const username = 'browser-admin';
const password = 'browser-integration-password-123!';
const siteName = 'browser-site';
const siteDomain = 'browser.integration.test';

test.describe.configure({ mode: 'serial' });
test.beforeAll(async () => { sham = await new ShamHarness().start({ register: false }); });
test.afterAll(async () => { await sham?.close(); });

async function login(page) {
  await page.goto(sham.baseUrl);
  await page.locator('#auth-username').fill(username);
  await page.locator('#auth-password').fill(password);
  await page.locator('#auth-submit').click();
  await expect(page.locator('#auth-view')).toBeHidden();
  if (await page.locator('#setup-dialog').isVisible()) {
    await page.getByRole('button', { name: 'Mark setup complete' }).click();
  }
}

async function openWorkspace(page) {
  await page.getByRole('button', { name: 'Sites' }).click();
  const card = page.locator('.site-card').filter({ hasText: siteName });
  await expect(card).toBeVisible();
  await card.getByRole('button', { name: siteName }).click();
  await expect(page.locator('#section-site-workspace')).toBeVisible();
}

test('unauthenticated visitors see the first-run access gate, not a dashboard', async ({ page }) => {
  await page.goto(sham.baseUrl);
  await expect(page.locator('#auth-title')).toHaveText('Create administrator');
  await expect(page.locator('#dashboard-view')).toBeHidden();
});

test('first-run setup creates an administrator and opens the dashboard', async ({ page }) => {
  await page.goto(sham.baseUrl);
  await expect(page.locator('#auth-title')).toHaveText('Create administrator');
  await page.locator('#auth-username').fill(username);
  await page.locator('#auth-password').fill(password);
  await page.locator('#auth-submit').click();
  await expect(page.locator('#auth-view')).toBeHidden();
  await expect(page.locator('#setup-dialog')).toBeVisible();
  await page.getByRole('button', { name: 'Mark setup complete' }).click();
  await expect(page.locator('body')).toContainText(/Dashboard|Sites/i);
});

test('invalid credentials show a controlled error and do not open the dashboard', async ({ page }) => {
  await page.goto(sham.baseUrl);
  await page.locator('#auth-username').fill(username);
  await page.locator('#auth-password').fill('not-the-browser-test-password');
  await page.locator('#auth-submit').click();
  await expect(page.locator('#auth-error')).not.toBeEmpty();
  await expect(page.locator('#dashboard-view')).toBeHidden();
});

test('a real login session survives a browser refresh', async ({ page }) => {
  await login(page);
  await page.reload();
  await expect(page.locator('#auth-view')).toBeHidden();
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
});

test('an administrator creates and deploys a Git-backed Node site through the UI', async ({ page }) => {
  await login(page);
  await page.getByRole('button', { name: 'Sites' }).click();
  await page.getByRole('button', { name: /New site/i }).click();
  await page.getByRole('radio', { name: /Git/i }).click();
  await page.getByRole('radio', { name: /Node \/ Express/i }).click();
  await page.locator('#site-create-git-url').fill(sham.gitUrl);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.locator('#site-name').fill(siteName);
  await page.locator('#site-domain').fill(siteDomain);
  // The Node preset correctly defaults to `npm ci`. This fixture has no
  // dependencies or package manifest, so exercise the UI's explicit
  // no-install configuration rather than requiring a registry in CI.
  await page.locator('#site-install-command').fill('');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.locator('#runtime-safety-options').click();
  await page.locator('#site-edge').check();
  await page.locator('#delivery-options').click();
  await page.locator('#site-release-mode').check();
  await page.getByRole('button', { name: 'Deploy site' }).click();
  await expect(page.locator('#site-dialog')).toBeHidden({ timeout: 30_000 });
  await expect(page.locator('.site-card').filter({ hasText: siteName })).toBeVisible();
  await sham.waitForEdge(siteDomain, 'SHAM_TEST_VERSION_1');
});

test('runtime logs are visible in the site workspace', async ({ page }) => {
  await login(page);
  await sham.edgeText(siteDomain);
  await openWorkspace(page);
  await page.getByRole('tab', { name: 'Logs' }).click();
  await expect(page.locator('#workspace-log-list')).toContainText('fixture SHAM_TEST_VERSION_1');
});

test('site stop, start, and restart controls recover a managed runtime', async ({ page }) => {
  await login(page);
  await page.getByRole('button', { name: 'Sites' }).click();
  const card = page.locator('.site-card').filter({ hasText: siteName });
  await card.getByRole('button', { name: 'Stop' }).click();
  await expect(card.getByRole('button', { name: 'Start' })).toBeVisible();
  await card.getByRole('button', { name: 'Start' }).click();
  await sham.waitForEdge(siteDomain, 'SHAM_TEST_VERSION_1');
  await expect(card.getByRole('button', { name: 'Restart' })).toBeVisible();
  await card.getByRole('button', { name: 'Restart' }).click();
  await sham.waitForEdge(siteDomain, 'SHAM_TEST_VERSION_1');
});

test('a workspace deployment switches traffic to version 2 and rollback restores version 1', async ({ page }) => {
  await sham.publishFixture('node-v2', 'browser version 2');
  await login(page);
  await openWorkspace(page);
  await page.getByRole('tab', { name: 'Deployments' }).click();
  await page.getByRole('button', { name: 'Deploy Git' }).click();
  await sham.waitForEdge(siteDomain, 'SHAM_TEST_VERSION_2');
  await expect(page.locator('#workspace-deployment-list')).toContainText(/Active|browser version 2/i);
  await page.getByRole('button', { name: 'Roll back' }).last().click();
  await sham.waitForEdge(siteDomain, 'SHAM_TEST_VERSION_1');
});

test('a failed UI deployment keeps the previously healthy release serving', async ({ page }) => {
  await sham.publishFixture('node-broken', 'browser broken candidate');
  await login(page);
  await openWorkspace(page);
  await page.getByRole('tab', { name: 'Deployments' }).click();
  await page.getByRole('button', { name: 'Deploy Git' }).click();
  await expect(page.locator('body')).toContainText(/failed|readiness|deployment/i, { timeout: 30_000 });
  await sham.waitForEdge(siteDomain, 'SHAM_TEST_VERSION_1');
});
