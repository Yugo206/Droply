const fs = require("fs");
const path = require("path");

// Extensions that can execute code on the recipient's machine when opened.
// Based on the set Gmail blocks for attachments.
const DANGEROUS_EXTENSIONS = new Set([
    "exe", "dll", "com", "bat", "cmd", "msi", "msp", "msix", "msixbundle",
    "appx", "appxbundle", "scr", "ps1", "psc1", "psm1", "vb", "vbe", "vbs",
    "js", "jse", "wsf", "wsh", "hta", "cpl", "msc", "jar", "apk",
    "sh", "bash", "bin", "run", "out", "action", "workflow",
    "reg", "scf", "sct", "shb", "shs", "lnk", "pif", "vxd", "sys", "iso", "img"
]);

// Magic-byte signatures of executable/script formats, used to catch files
// that were renamed to hide their real type (e.g. malware.exe -> photo.jpg).
const EXECUTABLE_SIGNATURES = [
    { name: "Windows PE executable (.exe/.dll)", bytes: [0x4d, 0x5a] },
    { name: "ELF executable", bytes: [0x7f, 0x45, 0x4c, 0x46] },
    { name: "Mach-O executable", bytes: [0xfe, 0xed, 0xfa, 0xce] },
    { name: "Mach-O executable", bytes: [0xfe, 0xed, 0xfa, 0xcf] },
    { name: "Mach-O executable", bytes: [0xce, 0xfa, 0xed, 0xfe] },
    { name: "Mach-O executable", bytes: [0xcf, 0xfa, 0xed, 0xfe] },
    { name: "Mach-O universal binary / Java class", bytes: [0xca, 0xfe, 0xba, 0xbe] },
    { name: "shell script (shebang)", bytes: [0x23, 0x21] }
];

function matchesSignature(buffer, bytes) {
    if (buffer.length < bytes.length) return false;
    return bytes.every((byte, i) => buffer[i] === byte);
}

function detectExecutableSignature(buffer) {
    return EXECUTABLE_SIGNATURES.find((sig) => matchesSignature(buffer, sig.bytes)) || null;
}

function validateFile(filePath, originalname) {
    const ext = path.extname(originalname).slice(1).toLowerCase();

    if (DANGEROUS_EXTENSIONS.has(ext)) {
        return { valid: false, reason: `Files of type ".${ext}" are not allowed.` };
    }

    const header = Buffer.alloc(4);
    const fd = fs.openSync(filePath, "r");
    const bytesRead = fs.readSync(fd, header, 0, 4, 0);
    fs.closeSync(fd);

    const signature = detectExecutableSignature(header.subarray(0, bytesRead));
    if (signature) {
        return {
            valid: false,
            reason: `File content was identified as a ${signature.name}, which is not allowed.`
        };
    }

    return { valid: true };
}

module.exports = { validateFile, DANGEROUS_EXTENSIONS };
