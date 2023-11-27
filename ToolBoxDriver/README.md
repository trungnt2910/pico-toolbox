pico-toolbox : picodrv
========================================================================
an ultimate tool for PICO processes and providers


This is kernel part of pico-toolbox, it contains various tools coupled with
their UM counterparts. Driver is x64 only, and you need to turn on
TestSigning option through BCD on windows and of course attach debugger unless you want to see PatchGuard BSOD.



Tools included:
===============


PICOMon - is actually only tool implemented here and is also turned on by default.
You can watch driver's output through DebugView and also log file is created
in \SystemRoot path.




Tools to build it and test it:
=============================
- Visual Studio 2022, WDK 
- Windows 11 Professional 23H2
- WinDbg recommended
	

Original author:
========
Martin Hron (martin@hron.eu, @thinkcz, https://about.me/martin.hron)

