import { expect, test } from '@playwright/test';
import { serviceUrl } from '../../../utils/stack-urls';

test('Onboarding start page is reachable without an existing stack session', async ({ page }) => {
  test.setTimeout(60000);

  const response = await page.goto(serviceUrl('onboarding', '/start'), {
    waitUntil: 'domcontentloaded',
    timeout: 30000,
  });

  expect(response?.status()).toBe(200);
  await expect(page.getByRole('heading', { name: /start account onboarding/i })).toBeVisible({ timeout: 15000 });
  await expect(page.locator('body')).toContainText(/Invite code/i);
  await expect(page).not.toHaveURL(/keycloak-auth|protocol\/openid-connect/i);
});
