all: deriv.js

clean:
	rm -f deriv.js deriv.bc deriv.cm*

deriv.bc: deriv.ml
	ocamlfind c -package js_of_ocaml -linkpkg -unsafe -o $@ $^

deriv.js: deriv.bc
	js_of_ocaml $^

.PHONY: all clean
