// Bring in a dependency on an externally maintained `gcc` package which manages
// invoking the C compiler.
extern crate gcc;

fn main() {
    gcc::Build::new()
        .files(&["c/crypt_blowfish.c",
                 "c/crypt_gensalt.c",
                 "c/wrapper.c",
                 "c/rust-interface.c"])
        .compile("bcrypt-bsd");
}
