MSC_GEN_FILES = $(patsubst %.msc,%.png,$(wildcard msc/*.msc))
TARGETS:=ssp21.html ssp21.pdf trust-model.pdf trust-model.html

default: $(TARGETS)

%.html: %.md template_pandoc.html spec_markdown.css Makefile $(MSC_GEN_FILES)
	pandoc $< \
		-s \
		--toc --toc-depth=5 \
		--number-sections \
		-f markdown+yaml_metadata_block+startnum \
		--filter pandoc-fignos \
		--template template_pandoc.html \
		--css=spec_markdown.css \
		-o $@

%.pdf: %.md template_pandoc.latex Makefile $(MSC_GEN_FILES)
	pandoc $< \
		-s \
		--toc --toc-depth=5 \
		--number-sections \
		-f markdown+yaml_metadata_block+startnum \
		--filter pandoc-fignos \
		--template template_pandoc.latex \
		-V colorlinks \
		-o $@

msc/%.png: msc/%.msc Makefile
	mscgen -T png -i $< -o $@

clean:
	rm $(TARGETS) $(MSC_GEN_FILES)

