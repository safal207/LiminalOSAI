// Real-browser check of the self-contained, read-only orientation artifact.
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
    await page.locator('#step').evaluate(el => {el.value = '3'; el.dispatchEvent(new Event('input'));});
    assert.equal(await page.locator('#counter').textContent(), '4 / 9');
    assert.equal(await page.locator('#pending').textContent(), '1');
    assert.match(await page.locator('#positions').innerText(), /beta:send/);
    const pending = await page.locator('#positions').innerText();
    await page.locator('#next').click();
    assert.equal(await page.locator('#positions').innerText(), pending);
    await page.screenshot({path: path.join(process.argv[3], 'orientation-desktop.png'), fullPage: true});
    await page.setViewportSize({width: 390, height: 844});
    await page.locator('#step').evaluate(el => {el.value = el.max; el.dispatchEvent(new Event('input'));});
    assert.equal(await page.locator('#session').textContent(), 'STOPPED');
    assert.equal(await page.locator('#budget').textContent(), '4 / 10');
    assert.equal(await page.locator('#pending').textContent(), '0');
    assert.equal(await page.locator('#next').isDisabled(), true);
    await page.screenshot({path: path.join(process.argv[3], 'orientation-mobile.png'), fullPage: true});
    const overflow = await page.evaluate(() => ({
      width: document.documentElement.scrollWidth,
      viewport: innerWidth,
      elements: [...document.querySelectorAll('main *')].filter(el => {
        const rect = el.getBoundingClientRect();
        return !el.closest('.tablewrap') && (rect.right > innerWidth || rect.left < 0);
      }).map(el => ({tag: el.tagName, id: el.id, className: String(el.className)}))
    }));
    assert.ok(overflow.width <= overflow.viewport, JSON.stringify(overflow));
    const graphLabelPixels = await page.locator('#graph text').evaluateAll(labels =>
      labels.map(el => parseFloat(getComputedStyle(el).fontSize) * el.getScreenCTM().a));
    assert.ok(graphLabelPixels.length > 0 && Math.min(...graphLabelPixels) >= 10,
      'Mobile graph labels must remain readable: ' + JSON.stringify(graphLabelPixels));
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({status: 'PASS', chromium: browser.version(), page_errors: errors,
      desktop: [1250,1000], mobile: [390,844], minimum_graph_label_pixels: Math.min(...graphLabelPixels), interactions: ['pending','claim_does_not_move','STOP']}));
  } finally {await browser.close();}
})().catch(error => {console.error(error); process.exitCode = 1;});
