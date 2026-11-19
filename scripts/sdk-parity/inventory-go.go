// Standalone standard-library parser; invoke with go run, outside an SDK package.
package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

type row struct {
	Symbol string `json:"symbol"`
	Kind   string `json:"kind"`
	File   string `json:"file"`
	Line   int    `json:"line"`
}

func main() {
	root := os.Args[1]
	fset := token.NewFileSet()
	var rows []row
	files, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		panic(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		tree, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			panic(err)
		}
		emit := func(name, kind string, pos token.Pos) {
			rows = append(rows, row{name, kind, "sdk/go/" + filepath.Base(file), fset.Position(pos).Line})
		}
		for _, declaration := range tree.Decls {
			switch node := declaration.(type) {
			case *ast.FuncDecl:
				if !ast.IsExported(node.Name.Name) {
					continue
				}
				name := node.Name.Name
				if node.Recv != nil {
					receiver := node.Recv.List[0].Type
					if pointer, ok := receiver.(*ast.StarExpr); ok {
						receiver = pointer.X
					}
					if id, ok := receiver.(*ast.Ident); ok {
						name = id.Name + "." + name
					}
				}
				emit(name, "callable", node.Pos())
			case *ast.GenDecl:
				for _, spec := range node.Specs {
					if typ, ok := spec.(*ast.TypeSpec); ok && ast.IsExported(typ.Name.Name) {
						emit(typ.Name.Name, "type", typ.Pos())
						if data, ok := typ.Type.(*ast.StructType); ok {
							for _, field := range data.Fields.List {
								for _, name := range field.Names {
									if ast.IsExported(name.Name) {
										emit(typ.Name.Name+"."+name.Name, "property", field.Pos())
									}
								}
							}
						}
						if face, ok := typ.Type.(*ast.InterfaceType); ok {
							for _, field := range face.Methods.List {
								for _, name := range field.Names {
									if ast.IsExported(name.Name) {
										emit(typ.Name.Name+"."+name.Name, "callable", field.Pos())
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(rows); err != nil {
		panic(err)
	}
}
