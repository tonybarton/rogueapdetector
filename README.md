# rogueapdetector
Tool for actively monitoring and detecting rouge access points and evil twins


# How to use
	
scan

	scan is used to learn what access points it can trust. Scan will pick up on all access points in the area.
		
		whitelist any access point that is yours or a known neighbors
		
		blacklist any access point that you are not sure of and would like to investigate more
		
monitor
	
	monitor is used after the initial scan. This is what will monitor access points at all times. If a rouge access point is detected it will appear in the console. After a rouge ap or evil twin is discovered you will get a chance to whitelist or blacklist that access point.
		
		whitelist any access point that is yours or a known neighbors
		
		blacklist any access point that you are not sure of and would like to investigate more

show whitelist

	shows a list of currently whitelisted access points
	
show blacklist

	shows a list of currently blacklisted access points

clear
	
	clears the screen
		
help
	
	help will display a list of commands
	
exit

	exits the console
