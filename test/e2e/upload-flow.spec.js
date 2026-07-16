const path = require("node:path");
const { test, expect } = require("@playwright/test");
const jsQR = require("jsqr");
const { PNG } = require("pngjs");

const FIXTURE = path.join(__dirname, "fixtures", "sample.txt");

test("upload, QR hidden until clicked, decodes to the exact share URL", async ({ page }) => {
    await page.goto("/");
    await page.setInputFiles("#fileInput", FIXTURE);
    await page.click("#uploadBtn");
    await page.waitForSelector("#successState:not(.hidden)");

    const link = await page.inputValue("#linkInput");
    expect(link).toMatch(/^http:\/\/localhost:\d+\/f\/[\w-]+$/);

    await expect(page.locator("#qrContainer")).toHaveClass(/hidden/);
    await expect(page.locator("#qrCode svg")).toHaveCount(0);

    await page.click("#qrToggleBtn");
    await expect(page.locator("#qrContainer")).not.toHaveClass(/hidden/);
    await expect(page.locator("#qrToggleBtn")).toHaveText("Masquer le QR Code");

    const svgBuffer = await page.locator("#qrCode svg").screenshot();
    const png = PNG.sync.read(svgBuffer);
    const decoded = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
    expect(decoded && decoded.data).toBe(link);

    await page.click("#qrToggleBtn");
    await expect(page.locator("#qrContainer")).toHaveClass(/hidden/);
});

test("password + download limit: wrong password rejected, correct password downloads and updates the counter", async ({ page }) => {
    await page.goto("/");
    await page.setInputFiles("#fileInput", FIXTURE);
    await page.fill("#passwordInput", "e2e-secret");
    await page.click('.segmented__option[data-value="5"]');
    await page.click("#uploadBtn");
    await page.waitForSelector("#successState:not(.hidden)");
    const link = await page.inputValue("#linkInput");

    await page.goto(link);
    await page.waitForSelector("#statePassword:not(.hidden)");
    await expect(page.locator("#filePwDownloads")).toHaveText("0 / 5");

    await page.fill("#passwordInput", "wrong-password");
    await page.click("#passwordSubmitBtn");
    await expect(page.locator("#passwordError")).toHaveText("Mot de passe invalide.");

    await page.fill("#passwordInput", "e2e-secret");
    const downloadPromise = page.waitForEvent("download");
    await page.click("#passwordSubmitBtn");
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe("sample.txt");
    await download.path(); // wait for the download to fully finish writing

    // Check the resulting counter via the API rather than re-navigating this
    // page: browser navigations right after a window.location.href download
    // can hang here (Chromium/sandbox quirk unrelated to the app), while the
    // download itself was genuinely triggered through the real UI above.
    const id = new URL(link).pathname.split("/").pop();
    const info = await (await page.request.get(`/api/file-info/${id}`)).json();
    expect(info.downloadCount).toBe(1);
});

test("unlimited share shows the infinity symbol on the download page", async ({ page }) => {
    await page.goto("/");
    await page.setInputFiles("#fileInput", FIXTURE);
    await page.click("#uploadBtn");
    await page.waitForSelector("#successState:not(.hidden)");
    const link = await page.inputValue("#linkInput");

    await page.goto(link);
    await page.waitForSelector("#stateReady:not(.hidden)");
    await expect(page.locator("#downloads")).toHaveText("∞");
});
