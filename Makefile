
default: ssp21.html ssp21.pdf

ssp21.html: ssp21.md template_pandoc.html spec_markdown.css Makefile
	pandoc ssp21.md -s --toc --number-sections \
	        -f markdown+yaml_metadata_block+startnum \
		--filter pandoc-fignos \
		--template template_pandoc.html \
		--css=spec_markdown.css \
		-o ssp21.html

ssp21.pdf: ssp21.md template_pandoc.latex Makefile
	pandoc ssp21.md -s --toc --number-sections \
	        -f markdown+yaml_metadata_block+startnum \
		--filter pandoc-fignos \
		--template template_pandoc.latex \
		-V colorlinks \
		-o ssp21.pdf

clean:
	rm ssp21.html ssp21.pdf
