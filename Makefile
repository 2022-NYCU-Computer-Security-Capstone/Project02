.SILENT: all clean

all: MITM/MITM.py DNS-Spoofing/DNS-Spoofing.py
	echo "#!/usr/bin/python3" > mitm_attack
	cat MITM/MITM.py >> mitm_attack

	echo "#!/usr/bin/python3" > pharm_attack
	cat DNS-Spoofing/DNS-Spoofing.py >> pharm_attack
	
	chmod a+x mitm_attack pharm_attack

clean:
	rm mitm_attack
	rm pharm_attack
