package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type JSONSchemaProperty struct {
	Type        string              `json:"type,omitempty"`
	Description string              `json:"description,omitempty"`
	Enum        []string            `json:"enum,omitempty"`
	Items       *JSONSchemaProperty `json:"items,omitempty"`
	Default     interface{}         `json:"default,omitempty"`
}

type JSONSchema struct {
	Schema     string                         `json:"$schema"`
	Title      string                         `json:"title"`
	Type       string                         `json:"type"`
	Properties map[string]*JSONSchemaProperty `json:"properties"`
	Required   []string                       `json:"required"`
}

func main() {
	root, err := findProjectRoot()
	if err != nil {
		fmt.Printf("Error finding project root: %v\n", err)
		os.Exit(1)
	}

	srcFile := filepath.Join(root, "internal/config/config.go")
	destFile := filepath.Join(root, "docs/config.schema.json")

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, srcFile, nil, parser.ParseComments)
	if err != nil {
		fmt.Printf("Error parsing Go source file %s: %v\n", srcFile, err)
		os.Exit(1)
	}

	properties := make(map[string]*JSONSchemaProperty)
	var requiredFields []string

	ast.Inspect(node, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Config" {
			return true
		}

		structType, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}

		for _, field := range structType.Fields.List {
			if len(field.Names) == 0 {
				continue
			}

			// Extract yaml tag name
			var yamlTag string
			if field.Tag != nil {
				tagValue := field.Tag.Value
				re := regexp.MustCompile(`yaml:"([^"]+)"`)
				matches := re.FindStringSubmatch(tagValue)
				if len(matches) > 1 {
					yamlTag = matches[1]
				}
			}

			if yamlTag == "" || yamlTag == "-" {
				continue
			}

			// Determine json schema type
			prop := &JSONSchemaProperty{}
			switch t := field.Type.(type) {
			case *ast.Ident:
				switch t.Name {
				case "string":
					prop.Type = "string"
				case "int":
					prop.Type = "integer"
				case "bool":
					prop.Type = "boolean"
				}
			case *ast.ArrayType:
				if ident, ok := t.Elt.(*ast.Ident); ok && ident.Name == "string" {
					prop.Type = "array"
					prop.Items = &JSONSchemaProperty{Type: "string"}
				}
			}

			// Extract doc comments or inline comments
			var commentText string
			if field.Comment != nil {
				commentText = strings.TrimSpace(field.Comment.Text())
			} else if field.Doc != nil {
				commentText = strings.TrimSpace(field.Doc.Text())
			}

			// Clean comment text and detect enums
			commentText = strings.ReplaceAll(commentText, "\n", " ")
			prop.Description = commentText

			if strings.Contains(yamlTag, "webhook_format") {
				prop.Enum = []string{"generic", "slack", "telegram"}
			} else if strings.Contains(yamlTag, "storage_backend") {
				prop.Enum = []string{"sqlite", "duckdb"}
			}

			properties[yamlTag] = prop

			// Mark standard configurations as required fields
			if yamlTag != "webhook_url" && yamlTag != "webhook_format" && yamlTag != "suricata_eve_path" {
				requiredFields = append(requiredFields, yamlTag)
			}
		}
		return false
	})

	schema := JSONSchema{
		Schema:     "http://json-schema.org/draft-07/schema#",
		Title:      "FlowGuard Lite Configuration Schema",
		Type:       "object",
		Properties: properties,
		Required:   requiredFields,
	}

	jsonData, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		fmt.Printf("Error marshalling json schema: %v\n", err)
		os.Exit(1)
	}

	// Create directory if not exists
	err = os.MkdirAll(filepath.Dir(destFile), 0755)
	if err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(destFile, jsonData, 0644)
	if err != nil {
		fmt.Printf("Error writing schema file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully generated JSON schema file: %s\n", destFile)
}

func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found starting from %s", dir)
		}
		dir = parent
	}
}
