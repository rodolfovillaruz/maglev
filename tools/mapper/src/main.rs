use std::fs;
use std::path::Path;
use syn::visit::Visit;
use syn::{ItemEnum, ItemFn, ItemImpl, ItemStruct, ItemTrait};
use walkdir::WalkDir;

/// Holds the mapped data for a single file
#[derive(Default, Debug)]
struct FileMap {
    structs: Vec<String>,
    enums: Vec<String>,
    traits: Vec<String>,
    functions: Vec<String>,
    methods: Vec<String>, // Stored as "StructName::method_name"
}

/// A visitor that walks the Rust Abstract Syntax Tree (AST)
struct MapVisitor {
    map: FileMap,
    current_impl_target: Option<String>,
}

impl MapVisitor {
    fn new() -> Self {
        Self {
            map: FileMap::default(),
            current_impl_target: None,
        }
    }
}

// Implement the Syn Visitor trait to extract specific items
impl<'ast> Visit<'ast> for MapVisitor {
    fn visit_item_struct(&mut self, i: &'ast ItemStruct) {
        self.map.structs.push(i.ident.to_string());
        syn::visit::visit_item_struct(self, i);
    }

    fn visit_item_enum(&mut self, i: &'ast ItemEnum) {
        self.map.enums.push(i.ident.to_string());
        syn::visit::visit_item_enum(self, i);
    }

    fn visit_item_trait(&mut self, i: &'ast ItemTrait) {
        self.map.traits.push(i.ident.to_string());
        syn::visit::visit_item_trait(self, i);
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        self.map.functions.push(i.sig.ident.to_string());
        syn::visit::visit_item_fn(self, i);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        // Track the name of the Struct/Enum being implemented
        if let syn::Type::Path(type_path) = &*i.self_ty {
            if let Some(segment) = type_path.path.segments.last() {
                self.current_impl_target = Some(segment.ident.to_string());
            }
        }
        syn::visit::visit_item_impl(self, i);
        self.current_impl_target = None;
    }

    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        // Tie the method to its parent Struct/Enum
        if let Some(impl_name) = &self.current_impl_target {
            self.map
                .methods
                .push(format!("{}::{}", impl_name, i.sig.ident));
        }
        syn::visit::visit_impl_item_fn(self, i);
    }
}

fn process_file(path: &Path) -> Option<FileMap> {
    let content = fs::read_to_string(path).ok()?;

    // Parse the file content into an AST
    let syntax_tree = syn::parse_file(&content).ok()?;

    let mut visitor = MapVisitor::new();
    visitor.visit_file(&syntax_tree);

    Some(visitor.map)
}

fn print_map(path: &Path, map: FileMap) {
    // Skip empty files
    if map.structs.is_empty()
        && map.enums.is_empty()
        && map.traits.is_empty()
        && map.functions.is_empty()
        && map.methods.is_empty()
    {
        return;
    }

    println!("\n📄 {}", path.display());

    if !map.structs.is_empty() {
        println!("  📦 Structs:");
        for s in map.structs {
            println!("     - {}", s);
        }
    }
    if !map.enums.is_empty() {
        println!("  🎲 Enums:");
        for e in map.enums {
            println!("     - {}", e);
        }
    }
    if !map.traits.is_empty() {
        println!("  📜 Traits:");
        for t in map.traits {
            println!("     - {}", t);
        }
    }
    if !map.functions.is_empty() {
        println!("  ⚡ Free Functions:");
        for f in map.functions {
            println!("     - {}", f);
        }
    }
    if !map.methods.is_empty() {
        println!("  🔧 Impl Methods:");
        for m in map.methods {
            println!("     - {}", m);
        }
    }
}

fn main() {
    // CHANGE THIS PATH to point to the `src` directory of the project you want to map
    let target_dir = Path::new("src");

    if !target_dir.exists() {
        eprintln!("Error: Directory '{}' not found.", target_dir.display());
        return;
    }

    println!("🗺️  Generating code map for: {}", target_dir.display());

    for entry in WalkDir::new(target_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();

        // Only process .rs files
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("rs") {
            if let Some(map) = process_file(path) {
                print_map(path, map);
            }
        }
    }
}
