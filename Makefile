default: out

out : 
	g++ wiretap.cpp -o wiretap -lpcap

clean:
	rm wiretap 

