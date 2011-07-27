all:
	pdflatex main.tex
	pdflatex main.tex
	bibtex main
	pdflatex main.tex
	pdflatex main.tex
	gcc -Wall -O2 -o server server.c
	gcc -Wall -O2 -o client client.c

clean:
	rm *.o server client *.aux *.bbl *.blg *.log *.out
