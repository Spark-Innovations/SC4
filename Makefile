# Makefile for building a completely self-contained version of SC4 that
# can be run from a file: URL

TARGET=sc4_genlocal.html

${TARGET}: jquery.js nacl-fast.min.js sc4.js sc4.css sc4.html
	echo '<!-- This is a self-contained version of SC4 -->' > $(TARGET)
	echo '<!-- See https://sc4.us/ for more information -->' >> $(TARGET)
	echo '<style>' >> ${TARGET}
	cat sc4.css >> ${TARGET}
	echo '</style>' >> ${TARGET}
	echo '<script>' >> ${TARGET}
	cat jquery.js nacl-fast.min.js sc4.js >> ${TARGET}
	echo '</script>' >> ${TARGET}
	tail -n +8 sc4.html >> ${TARGET}

clean:
	rm $(TARGET)
