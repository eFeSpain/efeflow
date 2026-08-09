/* Run the Linux smoke check on a machine that has a graphical session.
 *
 *   npm run e2e:linux -- efe@192.168.1.10
 *   npm run e2e:linux -- efe@host --deb dist/efeflow_0.9.10_amd64.deb
 *
 * The .deb is what people download and nothing automated touches it: the
 * end-to-end run drives WebView2's debugging protocol and WebKitGTK does not
 * speak it. This is the cheap half of the answer — it cannot click anything,
 * so it makes no claim about the interface, but it does check the failure that
 * is both likeliest and most expensive: the application not starting, or
 * starting without a webview.
 *
 * It goes over the machine's own ssh, so keys and ~/.ssh/config apply.
 */
import { execFileSync } from "node:child_process";
import { dirname, join, basename } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const host = args.find((a) => !a.startsWith("--"));
const deb = args[args.indexOf("--deb") + 1] && args.includes("--deb")
  ? args[args.indexOf("--deb") + 1] : null;

if (!host) {
  console.error(`
  usage: npm run e2e:linux -- <user@host> [--deb <path>]

  The machine needs a desktop session logged in — polkit and the webview both
  want one, and a check run from a bare ssh login would be checking something
  nobody uses.
`);
  process.exit(2);
}

const ssh = (cmd, opts = {}) =>
  execFileSync("ssh", ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host, cmd],
               { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], ...opts });

try {
  console.log(`\n  ${host}: ${ssh("uname -sr; . /etc/os-release && echo $PRETTY_NAME").trim().replace(/\n/g, " · ")}`);
} catch (e) {
  console.error(`\n  cannot reach ${host} over ssh:\n    ${String(e.stderr || e.message).trim().split("\n")[0]}\n`);
  process.exit(1);
}

/* the script, and the package if one was named */
execFileSync("scp", ["-q", join(here, "linux-smoke.sh"), `${host}:/tmp/efeflow-smoke.sh`]);
let remoteDeb = "";
if (deb) {
  remoteDeb = `/tmp/${basename(deb)}`;
  execFileSync("scp", ["-q", deb, `${host}:${remoteDeb}`]);
  console.log(`  shipped ${basename(deb)}`);
}

let out = "", failed = false;
try {
  out = ssh(`sh /tmp/efeflow-smoke.sh ${remoteDeb}`);
} catch (e) {
  out = String(e.stdout || "") + String(e.stderr || "");
  failed = true;
}
process.stdout.write(out);

try { ssh("rm -f /tmp/efeflow-smoke.sh /tmp/efeflow-smoke.log"); } catch { /* leaving it is not a failure */ }
process.exit(failed ? 1 : 0);
