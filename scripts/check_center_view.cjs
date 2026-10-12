// Inspect the actual self-contained center/observer timeline in Chromium.
const assert = require('node:assert/strict');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {chromium} = require(process.env.ORIENTATION_PLAYWRIGHT_MODULE);

(async () => {
  const browser = await chromium.launch({executablePath: process.env.ORIENTATION_CHROME,
    headless: true, args: ['--no-sandbox']});
  try {
    const page = await browser.newPage({viewport: {width: 1250, height: 1000}});
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(pathToFileURL(path.resolve(process.argv[2])).href);
    const step = async value => page.locator('#step').evaluate((el, next) => {
      el.value = next; el.dispatchEvent(new Event('input'));
    }, String(value));
    assert.equal(await page.locator('#effects').textContent(), '0');
    await page.locator('#next').click();
    assert.equal(await page.locator('#effects').textContent(), '0');
    assert.equal(await page.locator('#events tr').count(), 1);
    await step(2);
    assert.equal(await page.locator('#ringVerdict').textContent(), 'OBSERVER_RING_ROLE_REQUIRED');
    await step(6);
    assert.equal(await page.locator('#activeCenter').textContent(), 'B');
    assert.equal(await page.locator('#actualPosition').textContent(), 'work');
    assert.equal(await page.locator('#effects').textContent(), '1');
    await page.screenshot({path: path.join(process.argv[3], 'center-desktop.png'), fullPage: true});
    await page.setViewportSize({width: 390, height: 844});
    await step(9);
    assert.equal(await page.locator('#diagnosis').textContent(), 'CENTER_STAGNATION_HOLD');
    assert.equal(await page.locator('#effects').textContent(), '2');
    await page.screenshot({path: path.join(process.argv[3], 'center-mobile.png'), fullPage: true});
    const layout = await page.evaluate(() => ({
      viewport: innerWidth, width: document.documentElement.scrollWidth,
      labelPixels: [...document.querySelectorAll('#orbit text')].map(el =>
        parseFloat(getComputedStyle(el).fontSize) * el.getScreenCTM().a)
    }));
    assert.ok(layout.width <= layout.viewport, JSON.stringify(layout));
    assert.ok(Math.min(...layout.labelPixels) >= 10, JSON.stringify(layout));
    await page.locator('#next').click();
    assert.equal(await page.locator('#authority').textContent(), 'STOPPED');
    assert.equal(await page.locator('#next').isDisabled(), true);
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({status: 'PASS', chromium: browser.version(), page_errors: errors,
      desktop: [1250,1000], mobile: [390,844], minimum_graph_label_pixels: Math.min(...layout.labelPixels),
      interactions: ['idea_is_not_fact', 'missing_observer_role', 'center_change_without_teleport', 'stagnation_hold', 'STOP']}));
  } finally {await browser.close();}
})().catch(error => {console.error(error); process.exitCode = 1;});
