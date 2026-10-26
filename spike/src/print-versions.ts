/**
 * Print all installed package versions for the spike report.
 */

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgPath = join(__dirname, '..', 'package.json');
const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));

console.log('═'.repeat(50));
console.log('  Installed Package Versions');
console.log('═'.repeat(50));
console.log(`Node.js: ${process.version}`);
console.log('');

const allDeps = {
  ...pkg.dependencies,
  ...pkg.devDependencies,
};

for (const [name, version] of Object.entries(allDeps).sort()) {
  // Try to read the actual installed version from node_modules
  try {
    const modPkgPath = join(__dirname, '..', 'node_modules', name, 'package.json');
    const modPkg = JSON.parse(readFileSync(modPkgPath, 'utf-8'));
    console.log(`  ${name}: ${modPkg.version} (requested: ${version})`);
  } catch {
    // Scoped packages may be nested
    try {
      const parts = (name as string).split('/');
      const modPkgPath = join(__dirname, '..', 'node_modules', ...parts, 'package.json');
      const modPkg = JSON.parse(readFileSync(modPkgPath, 'utf-8'));
      console.log(`  ${name}: ${modPkg.version} (requested: ${version})`);
    } catch {
      console.log(`  ${name}: ${version} (not resolved)`);
    }
  }
}
