import { expect, test } from '@playwright/test';
import { authenticatedSessionState, testUser } from '../shared/forward-auth';
import { serviceUrl, stackDomain } from '../../../utils/stack-urls';

test.use({ storageState: authenticatedSessionState });

test('Onboarding points users to Keycloak required actions', async ({ page }) => {
  test.setTimeout(90000);

  await page.goto(serviceUrl('onboarding'), { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});

  await expect(page.getByRole('heading', { name: /finish account setup in keycloak/i })).toBeVisible({ timeout: 15000 });
  await expect(page.locator('body')).toContainText(testUser.username, { timeout: 15000 });
  await expect(page.locator('body')).toContainText(/Update the temporary password in Keycloak/i);
  await expect(page.locator('body')).toContainText(/Enroll OTP\/MFA/i);

  const accountLink = page.getByRole('link', { name: /open keycloak account console/i });
  await expect(accountLink).toHaveAttribute(
    'href',
    `https://keycloak.${stackDomain}/realms/webservices/account/`,
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
