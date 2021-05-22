XML2RFC_TARGETS = draft-bottomley-tpm2-keys.txt \
		draft-bottomley-tpm2-keys.html

if HAVE_XML2RFC
all: $(XML2RFC_TARGETS)

clean-local:
	rm -fr $(XML2RFC_TARGETS)
endif

$(builddir)/%.txt: $(srcdir)/%.xml
	$(XML2RFC) --text -o $@ $<

$(builddir)/%.html: $(srcdir)/%.xml
	$(XML2RFC) --html -o $@ $<
