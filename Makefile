
#### Generated image files ####

DOT_GEN_FILES = $(patsubst %.dot, %.png, $(wildcard dot/*.dot))
SVG_GEN_FILES = $(patsubst %.svg, %.png, $(wildcard svg/*.svg))
MSC_GEN_FILES = $(patsubst %.msc, %.png, $(wildcard msc/*.msc))
ALL_GEN_FILES = ${DOT_GEN_FILES} ${SVG_GEN_FILES} ${MSC_GEN_FILES}

#### Primary targets ####

TARGETS = ssp21.html ssp21.pdf

default: $(TARGETS)

clean:
	rm $(TARGETS) $(ALL_GEN_FILES)

wrap:
	fold -w 120 -s ssp21.md > ssp21_folded.md
	mv ssp21_folded.md ssp21.md

#### Use pandoc to create PDF and HTML ####

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

#### Wildcard rules for generating PNGs from source formats ####

dot/%.png: dot/%.dot Makefile
	dot -Tpng -o $@ $<

msc/%.png: msc/%.msc Makefile
	mscgen -T png -i $< -o $@

svg/%.png: svg/%.svg Makefile
	convert $< $@



