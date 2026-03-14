const crypto = require("crypto");

function pbkdf2HashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const iterations = 210000;
  const digest = "sha512";
  const keylen = 64;
  const hash = crypto
    .pbkdf2Sync(password, salt, iterations, keylen, digest)
    .toString("hex");
  return `pbkdf2$${digest}$${iterations}$${salt}$${hash}`;
}

const password = process.argv.slice(2).join(" ");
if (!password) {
  console.error("Usage: npm run hash:admin -- \"your-admin-password\"");
  process.exit(1);
}

console.log(pbkdf2HashPassword(password));
