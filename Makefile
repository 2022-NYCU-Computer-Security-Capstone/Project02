.SILENT: all clean

all: MITM/MITM.py
	echo "#!/usr/local/bin/python3" > mitm_attack
	cat MITM/MITM.py >> mitm_attack
	chmod a+x mitm_attack

clean:
	rm mitm_attack
