import { expect, test } from '@playwright/test';
import { authenticatedSessionState, testUser } from '../shared/forward-auth';
import { serviceUrl, stackDomain } from '../../../utils/stack-urls';

test.use({ storageState: authenticatedSessionState });

test('Onboarding confirms admin-managed membership for existing users', async ({ page }) => {
  test.setTimeout(90000);

  await page.goto(serviceUrl('onboarding'), { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});

  await expect(page.getByRole('heading', { name: /account setup complete/i })).toBeVisible({ timeout: 15000 });
  await expect(page.locator('body')).toContainText(testUser.username, { timeout: 15000 });
  await expect(page.locator('body')).toContainText(/Access is admin-managed/i);
  await expect(page.locator('body')).toContainText(/This page does not create accounts/i);
  await expect(page.locator('body')).not.toContainText(/Update the temporary password in Keycloak/i);
  await expect(page.locator('body')).not.toContainText(/Enroll OTP\/MFA/i);

  const accountLink = page.getByRole('link', { name: /return to homepage/i });
  await expect(accountLink).toHaveAttribute(
    'href',
    `https://homepage.${stackDomain}/`,
  );

  const apiResult = await page.evaluate(async () => {
    const response = await fetch('/api/setup', { method: 'POST' });
    return {
      status: response.status,
      body: await response.json(),
    };
  });
  expect(apiResult.status).toBe(410);
  expect(apiResult.body).toMatchObject({
    ok: false,
    accountUrl: `https://keycloak.${stackDomain}/realms/webservices/account/`,
  });
});
