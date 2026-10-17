/**
 * Builds the YOUPI SMS Gateway APK from source (apps/android-observer-app, Java sources).
 *
 * SECURITY: the repository no longer ships prebuilt APK or JAR binaries, because nobody can
 * verify that a committed binary matches the source. Build it yourself with this script
 * (or the "Android APK" GitHub Actions workflow) and install the result on your phone.
 *
 * Requirements:
 *   - JDK 17 (JAVA_HOME set, or javac/keytool on PATH)
 *   - Android SDK with build-tools 34.0.0 and platforms;android-34
 *     (ANDROID_HOME or ANDROID_SDK_ROOT set)
 *
 * Optional environment:
 *   ANDROID_BUILD_TOOLS_VERSION  default 34.0.0
 *   ANDROID_PLATFORM             default android-34
 *   ANDROID_KEYSTORE_PATH        keystore used to sign (default: data/android-release.keystore, created once)
 *   ANDROID_KEYSTORE_PASSWORD    keystore + key password (default: random, saved next to the keystore)
 *   ANDROID_KEY_ALIAS            default youpi_gateway
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const isWindows = process.platform === 'win32';

const ZXING_VERSION = '3.5.3';
const ZXING_URL = `https://repo1.maven.org/maven2/com/google/zxing/core/${ZXING_VERSION}/core-${ZXING_VERSION}.jar`;

function fail(message) {
  console.error(`\n❌ ${message}`);
  process.exit(1);
}

function resolveTool(dir, name, winExt) {
  const candidate = path.join(dir, isWindows ? `${name}${winExt}` : name);
  return fs.existsSync(candidate) ? candidate : null;
}

function javaTool(name) {
  const javaHome = process.env.JAVA_HOME;
  if (javaHome) {
    const p = path.join(javaHome, 'bin', isWindows ? `${name}.exe` : name);
    if (fs.existsSync(p)) return p;
  }
  return name; // fall back to PATH
}

// Runs a tool without a shell. Windows .bat wrappers need cmd.exe, invoked with an argument list.
function run(tool, args, options = {}) {
  if (isWindows && /\.bat$/i.test(tool)) {
    return execFileSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', tool, ...args], { stdio: 'inherit', ...options });
  }
  return execFileSync(tool, args, { stdio: 'inherit', ...options });
}

async function download(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Download failed (${res.status}): ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

async function ensureZxingJar(libsDir) {
  const jarPath = path.join(libsDir, `core-${ZXING_VERSION}.jar`);
  // Always verify against the checksum Maven Central publishes for this artifact.
  const expectedSha1 = (await download(`${ZXING_URL}.sha1`)).toString('utf8').trim().split(/\s+/)[0].toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(expectedSha1)) throw new Error('Unexpected checksum format from Maven Central.');

  let jar = fs.existsSync(jarPath) ? fs.readFileSync(jarPath) : null;
  if (!jar || crypto.createHash('sha1').update(jar).digest('hex') !== expectedSha1) {
    console.log(`   ⬇️  Downloading ZXing core ${ZXING_VERSION} from Maven Central...`);
    jar = await download(ZXING_URL);
  }
  const actual = crypto.createHash('sha1').update(jar).digest('hex');
  if (actual !== expectedSha1) throw new Error(`ZXing checksum mismatch: expected ${expectedSha1}, got ${actual}`);
  fs.mkdirSync(libsDir, { recursive: true });
  fs.writeFileSync(jarPath, jar);
  console.log(`   ✅ ZXing core verified (sha1 ${actual}).`);
  return jarPath;
}

function ensureKeystore(keytool) {
  const alias = process.env.ANDROID_KEY_ALIAS || 'youpi_gateway';
  const keystorePath = path.resolve(REPO_ROOT, process.env.ANDROID_KEYSTORE_PATH || 'data/android-release.keystore');
  const passFile = `${keystorePath}.password`;
  let password = process.env.ANDROID_KEYSTORE_PASSWORD;

  if (!fs.existsSync(keystorePath)) {
    password = password || crypto.randomBytes(24).toString('base64url');
    fs.mkdirSync(path.dirname(keystorePath), { recursive: true });
    run(keytool, [
      '-genkeypair', '-keystore', keystorePath, '-alias', alias, '-keyalg', 'RSA', '-keysize', '3072',
      '-validity', '10000', '-storepass', password, '-keypass', password,
      '-dname', 'CN=YouPI SMS Gateway, O=Self-hosted, C=IN'
    ], { stdio: 'pipe' });
    if (!process.env.ANDROID_KEYSTORE_PASSWORD) {
      fs.writeFileSync(passFile, password, { mode: 0o600 });
    }
    console.log(`   🔑 Created signing keystore at ${keystorePath} (keep it private and backed up; app updates must use the same key).`);
  }
  if (!password) {
    if (!fs.existsSync(passFile)) fail(`Keystore exists at ${keystorePath} but no password: set ANDROID_KEYSTORE_PASSWORD.`);
    password = fs.readFileSync(passFile, 'utf8').trim();
  }
  return { keystorePath, password, alias };
}

async function main() {
  console.log('🚀 Building YouPI SMS Gateway APK from source...');

  const sdk = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT;
  if (!sdk) fail('Set ANDROID_HOME (or ANDROID_SDK_ROOT) to your Android SDK.');
  const buildToolsDir = path.join(sdk, 'build-tools', process.env.ANDROID_BUILD_TOOLS_VERSION || '34.0.0');
  const androidJar = path.join(sdk, 'platforms', process.env.ANDROID_PLATFORM || 'android-34', 'android.jar');
  const AAPT = resolveTool(buildToolsDir, 'aapt', '.exe');
  const D8 = resolveTool(buildToolsDir, 'd8', '.bat');
  const ZIPALIGN = resolveTool(buildToolsDir, 'zipalign', '.exe');
  const APKSIGNER = resolveTool(buildToolsDir, 'apksigner', '.bat');
  if (!AAPT || !D8 || !ZIPALIGN || !APKSIGNER) fail(`Android build-tools not found in ${buildToolsDir}.`);
  if (!fs.existsSync(androidJar)) fail(`android.jar not found at ${androidJar}.`);
  const JAVAC = javaTool('javac');
  const KEYTOOL = javaTool('keytool');

  const APP_DIR = path.resolve(REPO_ROOT, 'apps/android-observer-app/app');
  const MANIFEST = path.join(APP_DIR, 'src/main/AndroidManifest.xml');
  const RES_DIR = path.join(APP_DIR, 'src/main/res');
  const JAVA_DIR = path.join(APP_DIR, 'src/main/java/com/youpi/observer');
  const LIBS_DIR = path.join(APP_DIR, 'libs');

  const WORK_DIR = path.resolve(REPO_ROOT, '.tmp_apk_build');
  fs.rmSync(WORK_DIR, { recursive: true, force: true });
  const BIN_DIR = path.join(WORK_DIR, 'bin');
  fs.mkdirSync(BIN_DIR, { recursive: true });

  try {
    console.log('📦 [1/6] Fetching and verifying dependencies...');
    const zxingJar = await ensureZxingJar(LIBS_DIR);

    console.log('📦 [2/6] Compiling Java sources...');
    const javaFiles = fs.readdirSync(JAVA_DIR).filter(f => f.endsWith('.java')).map(f => path.join(JAVA_DIR, f));
    const classpath = [androidJar, zxingJar].join(path.delimiter);
    run(JAVAC, ['-encoding', 'UTF-8', '--release', '17', '-cp', classpath, '-d', BIN_DIR, ...javaFiles]);

    console.log('⚡ [3/6] Converting bytecode to classes.dex...');
    const classFiles = [];
    (function collect(dir) {
      for (const item of fs.readdirSync(dir)) {
        const p = path.join(dir, item);
        if (fs.statSync(p).isDirectory()) collect(p);
        else if (p.endsWith('.class')) classFiles.push(p);
      }
    })(BIN_DIR);
    run(D8, ['--release', '--min-api', '26', '--lib', androidJar, '--output', WORK_DIR, ...classFiles, zxingJar]);
    const dexPath = path.join(WORK_DIR, 'classes.dex');
    if (!fs.existsSync(dexPath)) throw new Error('D8 did not produce classes.dex');

    console.log('📜 [4/6] Packaging resources and manifest...');
    const unalignedApk = path.join(WORK_DIR, 'unaligned.apk');
    run(AAPT, ['package', '-f', '-M', MANIFEST, '-S', RES_DIR, '-I', androidJar, '-F', unalignedApk]);
    run(AAPT, ['add', unalignedApk, 'classes.dex'], { cwd: WORK_DIR, stdio: 'pipe' });

    console.log('📐 [5/6] Aligning and signing...');
    const alignedApk = path.join(WORK_DIR, 'aligned.apk');
    run(ZIPALIGN, ['-f', '4', unalignedApk, alignedApk], { stdio: 'pipe' });
    const { keystorePath, password, alias } = ensureKeystore(KEYTOOL);
    const signedApk = path.join(WORK_DIR, 'signed.apk');
    run(APKSIGNER, ['sign', '--ks', keystorePath, '--ks-pass', `pass:${password}`, '--key-pass', `pass:${password}`, '--ks-key-alias', alias, '--out', signedApk, alignedApk]);
    run(APKSIGNER, ['verify', signedApk]);

    console.log('🚚 [6/6] Writing APK...');
    const apk = fs.readFileSync(signedApk);
    const outDir = path.resolve(REPO_ROOT, 'apps/android-observer-app/app/build/outputs/apk/release');
    fs.mkdirSync(outDir, { recursive: true });
    const outPath = path.join(outDir, 'youpi-sms-gateway.apk');
    fs.writeFileSync(outPath, apk);
    const sha256 = crypto.createHash('sha256').update(apk).digest('hex');
    fs.writeFileSync(`${outPath}.sha256`, `${sha256}  youpi-sms-gateway.apk\n`);
    console.log(`\n✨ Built ${outPath}\n   SHA-256: ${sha256}`);
    console.log('   The Payment API serves this file at /youpi-sms-gateway.apk.');
  } finally {
    fs.rmSync(WORK_DIR, { recursive: true, force: true });
  }
}

main().catch(err => fail(err.message));
