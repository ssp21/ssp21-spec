
DOT_GEN_FILES = dot/master_handshake_states.png
MSC_GEN_FILES = msc/handshake_success.png msc/handshake_error1.png msc/handshake_error2.png
ALL_GEN_FILES = ${DOT_GEN_FILES} ${MSC_GEN_FILES}

default: ssp21.html ssp21.pdf

msc/%.png: msc/%.msc Makefile
	mscgen -T png -i $< -o $@

dot/%.png: dot/%.dot Makefile
	dot -Tpng -o $@ $<
	
ssp21.html: ssp21.md template_pandoc.html spec_markdown.css Makefile $(ALL_GEN_FILES)
	pandoc ssp21.md -s --toc --toc-depth=5 --number-sections \
	        -f markdown+yaml_metadata_block+startnum \
		--filter pandoc-fignos \
		--template template_pandoc.html \
		--css=spec_markdown.css \
		-o ssp21.html

ssp21.pdf: ssp21.md template_pandoc.latex Makefile $(ALL_GEN_FILES)
	pandoc ssp21.md -s --toc --toc-depth=5 --number-sections \
	        -f markdown+yaml_metadata_block+startnum \
		--filter pandoc-fignos \
		--template template_pandoc.latex \
		-V colorlinks \
		-o ssp21.pdf

clean:
	rm msc/*.png
	rm dot/*.png
	rm ssp21.html ssp21.pdf
