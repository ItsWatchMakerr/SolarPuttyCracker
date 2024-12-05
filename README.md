# SolarPuttyCracker

A blatant ripoff of Voidsec's decrypt tool
https://github.com/VoidSec/SolarPuttyDecrypt

But not written in C# so it's infinitely better

You can also pass it a wordlist because that seems like an important feature you would want when decrypting something


# INSTALL

pip install -r requirements.txt

or pip install pycryptodome

this is an example of the illusion of choice

one could say we live in a society

# EXAMPLE

Wordlist:
SolarPuttyCracker.py -w passwords.txt backup.dat

Verbose with outfile:
SolarPuttyCracker.py -w passwords.txt backup.dat -o cracked.txt -v

Password:
SolarPuttyCracker.py -p ImH@cKinGTheMAinfRAmeGuyS_Ma,GEtThECaMeRA backup.dat
