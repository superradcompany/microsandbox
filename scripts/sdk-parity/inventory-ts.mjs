// Declaration inventory, not a claim that a declaration has behavioral coverage.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
const require = createRequire(path.resolve(process.argv[3], 'package.json'));
const ts = require('typescript');
const root = path.resolve(process.argv[2]);
const rows = [];
for (const name of fs.readdirSync(path.join(root, 'src'))) {
  if (!name.endsWith('.ts')) continue;
  const file = path.join(root, 'src', name);
  const tree = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
  const emit = (symbol, kind, node) => rows.push({symbol, kind, file: `sdk/node-ts/src/${name}`, line: tree.getLineAndCharacterOfPosition(node.getStart(tree)).line + 1});
  for (const node of tree.statements) {
    if (!node.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword)) continue;
    if (ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node)) {
      const owner = node.name?.text;
      if (!owner) continue;
      emit(owner, 'type', node);
      for (const member of node.members) {
        if (member.modifiers?.some(m => [ts.SyntaxKind.PrivateKeyword, ts.SyntaxKind.ProtectedKeyword].includes(m.kind))) continue;
        const method = ts.isConstructorDeclaration(member) ? 'constructor' : member.name?.getText(tree);
        if (!method || method.startsWith('#')) continue;
        emit(`${owner}.${method}`, ts.isPropertyDeclaration(member) || ts.isPropertySignature(member) ? 'property' : 'callable', member);
      }
    } else if (ts.isFunctionDeclaration(node) && node.name) emit(node.name.text, 'callable', node);
    else if ((ts.isTypeAliasDeclaration(node) || ts.isEnumDeclaration(node)) && node.name) emit(node.name.text, 'type', node);
    else if (ts.isVariableStatement(node)) for (const declaration of node.declarationList.declarations) emit(declaration.name.getText(tree), 'exported_value', declaration);
  }
}
process.stdout.write(JSON.stringify(rows));
