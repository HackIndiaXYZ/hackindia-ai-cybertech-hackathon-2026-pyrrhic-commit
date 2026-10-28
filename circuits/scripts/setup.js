const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const crypto = require('crypto');

const ROOT_DIR = path.resolve(__dirname, '../..');
const CIRCUITS_DIR = path.join(ROOT_DIR, 'circuits');
const BUILD_DIR = path.join(CIRCUITS_DIR, 'build');
const ARTIFACTS_DIR = path.join(CIRCUITS_DIR, 'artifacts');

function sha256File(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function runSetup() {
  console.log('=== Starting VeriRespond ZK Setup Ceremony (Demo/Test) ===');

  if (!fs.existsSync(BUILD_DIR)) {
    fs.mkdirSync(BUILD_DIR, { recursive: true });
  }
  if (!fs.existsSync(ARTIFACTS_DIR)) {
    fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
  }

  const userLocalCircom = path.join(process.env.HOME || '', '.local/bin/circom');
  const circomPath = process.env.CIRCOM_PATH ||
    (fs.existsSync(userLocalCircom) ? userLocalCircom :
    (fs.existsSync('c:\\Users\\chira\\bin\\circom.exe') ? 'c:\\Users\\chira\\bin\\circom.exe' : 'circom'));
  const circuitSrc = path.join(CIRCUITS_DIR, 'fsm_v1.circom');
  const r1csPath = path.join(BUILD_DIR, 'fsm_v1.r1cs');
  const wasmPath = path.join(BUILD_DIR, 'fsm_v1_js', 'fsm_v1.wasm');

  // Verify circom compiler availability
  try {
    execSync(`"${circomPath}" --version`, { stdio: 'ignore' });
  } catch {
    console.error(`\n[BLOCKED] Circom compiler binary ('${circomPath}') not found in environment.`);
    console.error('Please install Circom 2 (https://docs.circom.io/getting-started/installation/) or provide precompiled fsm_v1.wasm and fsm_v1_final.zkey.\n');
    process.exit(1);
  }

  // 1. Compile circuit if not already compiled
  console.log('[1/5] Compiling fsm_v1.circom...');
  execSync(`"${circomPath}" "${circuitSrc}" --r1cs --wasm --sym -o "${BUILD_DIR}"`, { stdio: 'inherit' });

  const snarkjsLocal = path.join(ROOT_DIR, 'node_modules', '.bin', process.platform === 'win32' ? 'snarkjs.cmd' : 'snarkjs');
  const snarkjsCmd = fs.existsSync(snarkjsLocal) ? snarkjsLocal : 'snarkjs';

  const ptau0 = path.join(ARTIFACTS_DIR, 'pot10_0000.ptau');
  const ptau1 = path.join(ARTIFACTS_DIR, 'pot10_contrib.ptau');
  const ptauFinal = path.join(ARTIFACTS_DIR, 'pot10_final.ptau');
  const zkey0 = path.join(ARTIFACTS_DIR, 'fsm_v1_0000.zkey');
  const zkeyFinal = path.join(ARTIFACTS_DIR, 'fsm_v1_final.zkey');
  const vkeyPath = path.join(ARTIFACTS_DIR, 'fsm_v1.vkey.json');
  const manifestPath = path.join(ARTIFACTS_DIR, 'manifest.json');

  // 2. Powers of Tau Phase 1 (pot10)
  if (!fs.existsSync(ptauFinal)) {
    console.log('[2/5] Running Powers of Tau (power 10)...');
    execSync(`"${snarkjsCmd}" powersoftau new bn128 10 "${ptau0}" -v`, { stdio: 'ignore' });
    execSync(`"${snarkjsCmd}" powersoftau contribute "${ptau0}" "${ptau1}" --name="VeriRespondContrib1" -v -e="verirespond_entropy_1"`, { stdio: 'ignore' });
    execSync(`"${snarkjsCmd}" powersoftau prepare phase2 "${ptau1}" "${ptauFinal}" -v`, { stdio: 'ignore' });
    if (fs.existsSync(ptau0)) fs.unlinkSync(ptau0);
    if (fs.existsSync(ptau1)) fs.unlinkSync(ptau1);
  } else {
    console.log('[2/5] Found existing pot10_final.ptau.');
  }

  // 3. Groth16 Phase 2 setup
  console.log('[3/5] Setting up Groth16 zkey...');
  execSync(`"${snarkjsCmd}" groth16 setup "${r1csPath}" "${ptauFinal}" "${zkey0}"`, { stdio: 'ignore' });
  execSync(`"${snarkjsCmd}" zkey contribute "${zkey0}" "${zkeyFinal}" --name="VeriRespondZKeyContrib" -v -e="verirespond_zkey_entropy"`, { stdio: 'ignore' });
  if (fs.existsSync(zkey0)) fs.unlinkSync(zkey0);

  // 4. Export verification key
  console.log('[4/5] Exporting verification key...');
  execSync(`"${snarkjsCmd}" zkey export verificationkey "${zkeyFinal}" "${vkeyPath}"`, { stdio: 'ignore' });

  // 5. Generate Manifest with cryptographic hashes
  console.log('[5/5] Generating verification artifact manifest...');
  const manifest = {
    schema_version: '1',
    policy_version: 'fsm-v1',
    description: 'VeriRespond FSM v1 Groth16 Setup Manifest',
    toolchain: {
      circom: '2.2.3',
      snarkjs: '0.7.5',
      circomlib: '2.0.5',
      circomlibjs: '0.1.7'
    },
    artifacts: {
      circuit_source: {
        path: 'circuits/fsm_v1.circom',
        sha256: sha256File(circuitSrc)
      },
      r1cs: {
        path: 'circuits/build/fsm_v1.r1cs',
        sha256: sha256File(r1csPath)
      },
      wasm: {
        path: 'circuits/build/fsm_v1_js/fsm_v1.wasm',
        sha256: sha256File(wasmPath)
      },
      verification_key: {
        path: 'circuits/artifacts/fsm_v1.vkey.json',
        sha256: sha256File(vkeyPath)
      },
      zkey_final: {
        path: 'circuits/artifacts/fsm_v1_final.zkey',
        sha256: sha256File(zkeyFinal)
      }
    },
    timestamp: new Date().toISOString(),
    demo_notice: 'Generated for HackIndia 2026 hackathon demo/testing. Not a production trusted ceremony.'
  };

  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
  console.log('✓ ZK Setup completed successfully!');
  console.log(`Verification Key: ${vkeyPath}`);
  console.log(`Manifest: ${manifestPath}`);
  console.log(`VKey SHA-256: ${manifest.artifacts.verification_key.sha256}`);
}

if (require.main === module) {
  runSetup();
}

module.exports = { runSetup };
