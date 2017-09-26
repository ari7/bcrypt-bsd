// Bring in a dependency on an externally maintained `gcc` package which manages
// invoking the C compiler.
extern crate gcc;

fn main() {
    let names: Vec<String> = vec![
        "crypt_blowfish.c",
        "crypt_gensalt.c",
        "wrapper.c",
        "rust-interface.c"
    ].into_iter().map(|n| "src/c/".to_owned() + n).collect();

    gcc::Build::new()
        .files(names)
        .compile("bcrypt-bsd");
}
