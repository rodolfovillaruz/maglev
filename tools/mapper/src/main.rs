use std::fs;
use std::path::Path;
use syn::visit::Visit;
use syn::{ItemEnum, ItemFn, ItemImpl, ItemStruct, ItemTrait, ItemUse};
use walkdir::WalkDir;

/// Holds the mapped data for a single function or method
#[derive(Default, Debug, Clone)]
struct FuncMap {
    name: String,
    dependencies: Vec<String>,
}

/// Holds the mapped data for a single file
#[derive(Default, Debug)]
struct FileMap {
    imports: Vec<String>,
    structs: Vec<String>,
    enums: Vec<String>,
    traits: Vec<String>,
    functions: Vec<FuncMap>,
    methods: Vec<FuncMap>,
}

/// A visitor that walks the Rust Abstract Syntax Tree (AST)
struct MapVisitor {
    map: FileMap,
    current_impl_target: Option<String>,
    // Stack to handle potential nested functions
    current_functions: Vec<FuncMap>,
}

impl MapVisitor {
    fn new() -> Self {
        Self {
            map: FileMap::default(),
            current_impl_target: None,
            current_functions: Vec::new(),
        }
    }

    /// Extends the dependency list for the active function from a syn::Path
    fn add_dependency(&mut self, path: &syn::Path) {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        if segments.is_empty() {
            return;
        }
        let dep = segments.join("::");

        // Ignore common built-ins to reduce noise
        if Self::is_primitive_or_common(&dep) {
            return;
        }

        self.add_dependency_string(dep);
    }

    /// Adds a string dependency to the currently active function context
    fn add_dependency_string(&mut self, dep: String) {
        if let Some(func) = self.current_functions.last_mut() {
            if !func.dependencies.contains(&dep) {
                func.dependencies.push(dep);
            }
        }
    }

    /// Filters out standard library primitives and extremely common wrappers
    fn is_primitive_or_common(name: &str) -> bool {
        matches!(
            name,
            "String"
                | "Vec"
                | "Option"
                | "Result"
                | "Box"
                | "Rc"
                | "Arc"
                | "bool"
                | "char"
                | "str"
                | "Self"
                | "u8"
                | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "usize"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "i128"
                | "isize"
                | "f32"
                | "f64"
        )
    }
}

// Implement the Syn Visitor trait to extract specific items
fn format_vis(vis: &syn::Visibility) -> String {
    match vis {
        syn::Visibility::Public(_) => "pub ".to_string(),
        syn::Visibility::Restricted(r) => {
            let path_segments: Vec<String> = r
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            let path_str = path_segments.join("::");
            let in_str = if r.in_token.is_some() { "in " } else { "" };
            format!("pub({}{}) ", in_str, path_str)
        }
        syn::Visibility::Inherited => "".to_string(),
    }
}

fn format_use_tree(tree: &syn::UseTree) -> String {
    match tree {
        syn::UseTree::Path(p) => format!("{}::{}", p.ident, format_use_tree(&p.tree)),
        syn::UseTree::Name(n) => n.ident.to_string(),
        syn::UseTree::Rename(r) => format!("{} as {}", r.ident, r.rename),
        syn::UseTree::Glob(_) => "*".to_string(),
        syn::UseTree::Group(g) => {
            let items: Vec<String> = g.items.iter().map(format_use_tree).collect();
            format!("{{{}}}", items.join(", "))
        }
    }
}

// Implement the Syn Visitor trait to extract specific items
impl<'ast> Visit<'ast> for MapVisitor {
    fn visit_item_use(&mut self, i: &'ast ItemUse) {
        let vis_str = format_vis(&i.vis);
        let prefix = if i.leading_colon.is_some() { "::" } else { "" };
        let tree_str = format_use_tree(&i.tree);
        self.map
            .imports
            .push(format!("{}use {}{};", vis_str, prefix, tree_str));
        syn::visit::visit_item_use(self, i);
    }

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
        let name = i.sig.ident.to_string();
        self.current_functions.push(FuncMap {
            name,
            dependencies: Vec::new(),
        });

        // Visit children (arguments, return types, body) to extract dependencies
        syn::visit::visit_item_fn(self, i);

        if let Some(func) = self.current_functions.pop() {
            self.map.functions.push(func);
        }
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        if let syn::Type::Path(type_path) = &*i.self_ty {
            if let Some(segment) = type_path.path.segments.last() {
                self.current_impl_target = Some(segment.ident.to_string());
            }
        }
        syn::visit::visit_item_impl(self, i);
        self.current_impl_target = None;
    }

    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        let name = if let Some(impl_name) = &self.current_impl_target {
            format!("{}::{}", impl_name, i.sig.ident)
        } else {
            i.sig.ident.to_string()
        };

        self.current_functions.push(FuncMap {
            name,
            dependencies: Vec::new(),
        });

        // Visit children (arguments, return types, body) to extract dependencies
        syn::visit::visit_impl_item_fn(self, i);

        if let Some(func) = self.current_functions.pop() {
            self.map.methods.push(func);
        }
    }

    // --- Dependency Extraction Hooks ---

    /// Extracts direct function calls: `my_function()`
    fn visit_expr_call(&mut self, i: &'ast syn::ExprCall) {
        if let syn::Expr::Path(expr_path) = &*i.func {
            self.add_dependency(&expr_path.path);
        }
        syn::visit::visit_expr_call(self, i);
    }

    /// Extracts method calls: `my_object.my_method()`
    fn visit_expr_method_call(&mut self, i: &'ast syn::ExprMethodCall) {
        self.add_dependency_string(i.method.to_string());
        syn::visit::visit_expr_method_call(self, i);
    }

    /// Extracts struct instantiations: `MyStruct { field: 1 }`
    fn visit_expr_struct(&mut self, i: &'ast syn::ExprStruct) {
        self.add_dependency(&i.path);
        syn::visit::visit_expr_struct(self, i);
    }

    /// Extracts explicit types: Variable assignments, Function signatures, Generics
    fn visit_type_path(&mut self, i: &'ast syn::TypePath) {
        self.add_dependency(&i.path);
        syn::visit::visit_type_path(self, i);
    }

    /// Extracts macro invocations: `my_macro!()`
    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        self.add_dependency(&i.path);
        syn::visit::visit_macro(self, i);
    }
}

fn process_file(path: &Path) -> Option<FileMap> {
    let content = fs::read_to_string(path).ok()?;
    let syntax_tree = syn::parse_file(&content).ok()?;

    let mut visitor = MapVisitor::new();
    visitor.visit_file(&syntax_tree);

    Some(visitor.map)
}

fn print_map(path: &Path, map: FileMap) {
    if map.imports.is_empty()
        && map.structs.is_empty()
        && map.enums.is_empty()
        && map.traits.is_empty()
        && map.functions.is_empty()
        && map.methods.is_empty()
    {
        return;
    }

    println!("\n📄 {}", path.display());

    if !map.imports.is_empty() {
        println!("  📥 Imports:");
        for i in map.imports {
            println!("     - {}", i);
        }
    }
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
            println!("     - {}", f.name);
            if !f.dependencies.is_empty() {
                println!("       └─ Dependencies: {}", f.dependencies.join(", "));
            }
        }
    }
    if !map.methods.is_empty() {
        println!("  🔧 Impl Methods:");
        for m in map.methods {
            println!("     - {}", m.name);
            if !m.dependencies.is_empty() {
                println!("       └─ Dependencies: {}", m.dependencies.join(", "));
            }
        }
    }
}

fn main() {
    let target_dir = Path::new("src");

    if !target_dir.exists() {
        eprintln!("Error: Directory '{}' not found.", target_dir.display());
        return;
    }

    println!("🗺️  Generating code map for: {}", target_dir.display());

    for entry in WalkDir::new(target_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();

        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("rs") {
            if let Some(map) = process_file(path) {
                print_map(path, map);
            }
        }
    }
}
