// Declaration inventory, not a claim that a declaration has behavioral coverage.
import path from 'node:path';
import { createRequire } from 'node:module';
const require = createRequire(path.resolve(process.argv[3], 'package.json'));
const ts = require('typescript');
const root = path.resolve(process.argv[2]);
const sourceRoot = path.join(root, 'src');
const entry = path.join(sourceRoot, 'index.ts');
const program = ts.createProgram([entry], {
  target: ts.ScriptTarget.Latest,
  module: ts.ModuleKind.NodeNext,
  moduleResolution: ts.ModuleResolutionKind.NodeNext,
  noEmit: true,
  skipLibCheck: true,
});
const checker = program.getTypeChecker();
const tree = program.getSourceFile(entry);
if (!tree) throw Error(`Missing TypeScript public entry point: ${entry}`);
const module = checker.getSymbolAtLocation(tree);
if (!module) throw Error(`Not a TypeScript module: ${entry}`);
const rows = [];
const seen = new Set();
const emit = (symbol, kind, node) => {
  const source = node.getSourceFile();
  const relative = path.relative(sourceRoot, source.fileName);
  // Native and dependency re-exports are not declarations in this wrapper
  // source tree. Keep the inventory's existing external-expansion boundary.
  if (relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) return;
  const row = {symbol, kind, file: `sdk/node-ts/src/${relative.split(path.sep).join('/')}`, line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1};
  const key = JSON.stringify(row);
  if (!seen.has(key)) { seen.add(key); rows.push(row); }
};

function visitMembers(name, node, ancestors = new Set()) {
  if (ancestors.has(node)) return;
  const visiting = new Set(ancestors).add(node);
  if (ts.isTypeAliasDeclaration(node) && ts.isTypeReferenceNode(node.type)) {
    // Public type/value pairs use aliases such as `Rule = _Types.Rule`.
    // Follow direct references to local declarations without expanding arbitrary
    // unions, mapped types or external native/dependency interfaces.
    let target = checker.getSymbolAtLocation(node.type.typeName);
    if (target?.flags & ts.SymbolFlags.Alias) target = checker.getAliasedSymbol(target);
    for (const declaration of target?.declarations ?? []) visitMembers(name, declaration, visiting);
    return;
  }
  if (!ts.isClassDeclaration(node) && !ts.isInterfaceDeclaration(node)) return;
  for (const member of node.members) {
    if (member.modifiers?.some(m => [ts.SyntaxKind.PrivateKeyword, ts.SyntaxKind.ProtectedKeyword].includes(m.kind))) continue;
    const method = ts.isConstructorDeclaration(member) ? 'constructor' : member.name?.getText();
    if (!method || method.startsWith('#')) continue;
    emit(`${name}.${method}`, ts.isPropertyDeclaration(member) || ts.isPropertySignature(member) ? 'property' : 'callable', member);
  }
}

function visitExports(module, prefix = '', ancestors = new Set()) {
  if (ancestors.has(module)) return;
  const visiting = new Set(ancestors).add(module);
  // The checker follows named, aliased and export-star chains, including
  // cyclic barrels. Scanning directories would include private implementation
  // exports and still miss the public names of aliased declarations.
  for (const exported of checker.getExportsOfModule(module)) {
    const symbol = exported.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(exported) : exported;
    const name = prefix + exported.getName();
    if (symbol.flags & ts.SymbolFlags.Module) visitExports(symbol, `${name}.`, visiting);
    for (const node of symbol.declarations ?? []) {
      if (ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node)) {
        emit(name, 'type', node);
        visitMembers(name, node);
      } else if (ts.isFunctionDeclaration(node)) emit(name, 'callable', node);
      else if (ts.isTypeAliasDeclaration(node) || ts.isEnumDeclaration(node)) {
        emit(name, 'type', node);
        visitMembers(name, node);
      }
      else if (ts.isVariableDeclaration(node)) emit(name, 'exported_value', node);
    }
  }
}
visitExports(module);
rows.sort((a, b) => a.symbol.localeCompare(b.symbol) || a.file.localeCompare(b.file) || a.line - b.line || a.kind.localeCompare(b.kind));
process.stdout.write(JSON.stringify(rows));
