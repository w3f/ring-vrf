# ring-vrf

Ring VRF implementation using zkSNARKs.

## Building the Specification document

The specification is built by means of [Cargo spec](https://crates.io/crates/cargo-spec) crate. To build the specification document, one can simply invoke:
```
$ cargo spec build
```
[`specification.md`](./specification.md) then shall contain the newly built specification. The specification could be easily converted to HTML by the help of `pandoc` if desired:
```
$ pandoc -f commonmark specification.md --standalone  --output specification.html 
```
The specification contais mathematical formula which needs to be converted to LaTeX format in order to be displayed as intended using:
```
$ pandoc -f commonmark specification.md --to=latex --standalone  --output specification.tex 
```
Alternatively you could simply run:
```
$ make spec-build
```
and get the specification in `./spec/specification.pdf`

Or run:
```
$ make spec-build-html
```
and get the specification in `./spec/specification.html`
