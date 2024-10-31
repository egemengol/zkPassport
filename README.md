To test:

```sh
# deno test -A
deno test -A --filter "DG1 TD3"
```

To build the documentation:

1. Install `cargo` using `rustup`
2. Install Java
3. Install `plantuml`
4. Run `cargo install mdbook mdbook-plantuml`
5. Run `cd docs && mdbook serve --open`

The (somewhat stale) documentation is live [here](https://zkpassportdocs.netlify.app/)
