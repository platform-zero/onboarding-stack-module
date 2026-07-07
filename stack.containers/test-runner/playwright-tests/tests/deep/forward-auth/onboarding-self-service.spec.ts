import { expect, test } from '@playwright/test';
import { serviceUrl, stackDomain } from '../../../utils/stack-urls';

test('Onboarding does not expose a public entrypoint without an existing stack session', async ({ page }) => {
  test.setTimeout(60000);

  const response = await page.goto(serviceUrl('onboarding', '/start'), {
    waitUntil: 'domcontentloaded',
    timeout: 30000,
  });

  expect(response?.ok()).toBeTruthy();
  const currentUrl = new URL(page.url());
  const currentLocation = `${currentUrl.hostname}${currentUrl.pathname}`;

  if (
    /keycloak-auth\.[^/]+\/oauth2\/start|keycloak\.[^/]+\/realms\/[^/]+\/protocol\/openid-connect\/auth/.test(
      currentLocation,
    )
  ) {
    return;
  }

  expect(currentLocation).toBe(`onboarding.${stackDomain}/start`);
  await expect(page.locator('body')).toContainText(/Start account onboarding/i);
  await expect(page.locator('body')).toContainText(/Self-service onboarding is not enabled for this stack/i);
  await expect(page.getByRole('button', { name: /create account/i })).toBeDisabled();
  await expect(page.locator('input[name="code"]')).toBeDisabled();
  await expect(page.locator('input[name="username"]')).toBeDisabled();
  await expect(page.locator('input[name="email"]')).toBeDisabled();
});
