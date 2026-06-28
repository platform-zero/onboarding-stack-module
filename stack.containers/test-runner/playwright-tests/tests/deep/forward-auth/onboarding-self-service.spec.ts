import { expect, test } from '@playwright/test';
import { serviceUrl } from '../../../utils/stack-urls';

test('Onboarding does not expose a public entrypoint without an existing stack session', async ({ page }) => {
  test.setTimeout(60000);

  const response = await page.goto(serviceUrl('onboarding', '/start'), {
    waitUntil: 'domcontentloaded',
    timeout: 30000,
  });

  expect(response?.ok()).toBeTruthy();
  const currentUrl = new URL(page.url());
  expect(`${currentUrl.hostname}${currentUrl.pathname}`).toMatch(
    /keycloak-auth\.[^/]+\/oauth2\/start|keycloak\.[^/]+\/realms\/[^/]+\/protocol\/openid-connect\/auth/,
  );
});
