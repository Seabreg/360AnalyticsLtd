# 360AnalyticsLtd

   ________   _______________           ________________      _____ __________ 
   \_____  \ /  _____/\   _  \          \_   _____/  _  \    /  _  \\______   \
     _(__  </   __  \ /  /_\  \   ______ |    __)/  /_\  \  /  /_\  \|       _/
    /       \  |__\  \\  \_/   \ /_____/ |     \/    |    \/    |    \    |   \
   /______  /\_____  / \_____  /         \___  /\____|__  /\____|__  /____|_  /
          \/       \/        \/              \/         \/         \/       \/ 


The latest version of this code can be found at http://sourceforge.net/projects/faar/ 
---------------------------------------------------------------------------------------------------

360-FAAR is an open source firewall analysis, policy rebuild and configuration tool.  It is intended to 
provide a toolkit for firewall engineers and analysts to use to plan, analyse and implement complex network 
changes in enterprise brown field environments and to provide the detailed analysis to be confident in the 
integrety of the security changes generated.

360-FAAR (Firewall Analysis Audit and Repair) is an offline, command line, Perl firewall policy manipulation 
tool to filter, compare to logs, merge, translate and output firewall commands for new policies, 
in Checkpoint dbedit, Cisco PIX/ASA or ScreenOS commands, and its one file!

Read Policy and Logs for:

Checkpoint FW1 (in odumper.csv / logexport format),
Netscreen ScreenOS (in get config / syslog format),
Cisco ASA (show run / syslog format),

360-FAAR uses both inclusive and exclusive CIDR and text filters, permitting you to split large policies 
into smaller ones for virutalisation at the same time as removing unused connectivity.

360-FAAR supports, policy to log association, object translation, rulebase reordering and simplification, 
rule moves and duplicate matching automatically. Allowing you to seamlessly move rules to where you need them.

TRY: 'print' mode. One command, and spreadsheet for your audit needs!


Features
---------------------------------------------------------------------------------------------------

    * WRITTEN IN SIMPLE Perl - NEEDS ONLY STANDARD MODULES - IS ONE FILE
    * 
    * Build new rulebases from scratch with a single 'any' rule and log files.
    * Reverse lookup Names for IP's and /27 blocks and use these in the policies built.
    * Read many logfiles by specifying the directory and an optional regex to match names.
    * Switch the processing into DROPS mode and process drop log entries for further analysis.
    * Output pre processed logs in JSON and read later and process more logs into the same config.
    * Easy to Edit Menu Driven Text Interface
    * Capable of manipulating tens of thousands of rules, objects and groups
    * Handles infinitely deep groups
    * Capable of CIDR filtering connectivity in/out of policy rulebases.
    * Capable of merging rulebases.
    * Identifies existing connectivity in rulebases and policies
    * Automatically performs cleanup if a log file is provided.
    * Keeps DR connecitvity via any text or IP tag
    * Encryption rules can be added during policy moves to remove the "merge from" rules for traffic that would be encrypted by the time it reached the firewall on which the "merge to" policy is to be installed - sounds complicated but its not in practice - apropriate ike and esp rules should be added manually
    * Runs consistency checks on its own objects and rule definitions
    * Extendable via a simple elsif in the user interaction loop section.
    * 
    * EASY TO EXECUTE:
    * ./360-faar.pl od=|ns=|cs=configfile[,logfile,natsfile] [logparse=normal|drops] [json=in|out]
    *
    * CONFIG TYPES: - cisco soon!
    * od = logexported logs, object dumper format config, fwdoc format nat rules csv
    * ns = syslog format logs, screenos6 format config, nats are included in policy but not processed fuly yet, fwdoc format nats can be used though
    * cs = cisco asa syslog file, cisco ASA format config, - not ready yet
    * 
    * OUTPUT TYPES:
    * od = output an odumper/ofiller format config to file, and print the dbedit for the rulebase creation to screen
    * ns = outputs netscreen screenos6 objects and policies (requires a netscreen config or zone info)
    * cs = cisco asa format config - running and almost ready...
    * 
    * JSON OPTIONS:
    * in  = read logjson.txt and more logs, output logjson.txt
    * out = output logjson.txt
    *
    * LOG PARSE OPTIONS:
    * normal = process in ACCEPT mode, profile and group ACCEPT LOG PROFILES
    * drops  = process in DROP mode, profile and build DROP LOG PROFILES (with 'res' and 'ures' and 'name'  modes)
    *
    * By default 360-FAAR accepts as many configs as you enter the command line.
    * Make an empty file called "fake" and and use this as the file name for logfiles if you want to process a config with NATS but no logfile.
    * Log file headders in fw1 logexported logs are found automatically so many files can be cated together
    * 
    * FUTHER PROCESSING AND MANUAL EDITING:
    * Output odumper/ofiller format files and make them more readable (watchout for spaces in names) using the numberrules helper script
    * Edit these csv's in Openoffice or Excell using any of the object or group definitions from the three loaded configs.
    * You can then use this file as a template to translate to many different firewalls using the 'bldobjs' mode
    * Further resolve IP networks to names with the helper scripts and DNS / whois.


# 360-FAAR (Firewall Analysis, Audit, and Repair)

# The purpose of this script is to provide detailed analysis of a firewalls configuration by combining logs and config
#---------------------------------------------------------------------------------------------------

# Currently supported input amd output firewall config types are:
#---------------------------------------------------------------------------------------------------
#                - Cisco ASA: show run
#                - Netscreen ScreenOS 6: get config
#                - Checkpoint Firewall-1: odumper/ofiller csv format in, fwdoc nats in, dbedit out
#                - Many similar typed configs can be "cat'ed" together for comparison via 'print' modes or duplicates Data::Dumper prints

# Currently supported input firewall log types are:
#---------------------------------------------------------------------------------------------------
#                - Cisco ASA: syslog text log
#                - Netscreen ScreenOS 6: syslog text log
#                - Checkpoint Firewall-1: logexport utility format, 
#                - Many log files can be "cat'ed" together, in line log headers and prefixes are accounted for

# This script is hopefully written in a way that will make its workings understandable to firewall and network engineers
#---------------------------------------------------------------------------------------------------

# The latest version of this code can be found at http://sourceforge.net/projects/faar/ 
#---------------------------------------------------------------------------------------------------

# Version v0.6.3 - This release updates the config pasers to permit you to specify the default service
#   25/08/2017     set used to scan rules and service objects, for example to permit a checkpoint csv 
#                  to be parsed using Cisco ASA config default service definitions.
#                - This release also add's close statements for all files opened while parsing logs.

# Version v0.6.2 - This release fixes the bug in the cisco asa drop log parser that missed %ASA-6-106100 
#   13/04/2017     logs and also mutes the SOMETHINGELSE print in droplog processing mode.
#                - The is_ip and is_netmask subs regex has been updated to more exclusively match ips.
#                - The cisco log parser for ASA-6-110003 has been updated to correctly isolate the ip.
#                - The checkpoint log parsers now parse icmp type codes and 'other' and ip protos.

# Version v0.6.1 - This release fixes the bug in the output stage of 'bldobj' mode that was causing faar
#   26/03/2017     to explode... every procedural programming pit fall needs heads to fall in it.
#                - The Cisco log parsers have been updated to capture the hit count of message repeated logs
#                - Also updated (thank to feedback from OE) is the dbedit service output sub:
#                  The "protocol" line is removed, the 'exp dport=X' is now just 'port X'.
#                - The Cisco ASA output sub has been updated so that unknown objects are output as
#                  'object $src_or_dst' so that the syntax at least is correct.
#                - In drops rr mode 'hitcount' is the now the default output style.

# Version v0.6.0 - This release hacks backwards some more of the functionality in SuperFAAR. Some of it
#   25/09/2016     is nasty but it works for the most part. If you require better handling of large port 
#                  ranges, IPv4 and IPv6 capabilities, better simplificaiton, better output stages, better
#                  handling of rule comments & section headers, object interfaces and rule actions, better
#                  translation between firewall vendors configs, many more rulebase processing options for 
#                  securing your policiees, seperation of input policies connectivity and maintaining 
#                  policy order with no need to swap between drops and normal modes - you need SuperFAAR.
#                  Contact dan@360-faar.pl or +447960028070 for details.
#                - This release allows 360-FAAR to be switched into DROP log processing mode.
#                - This release updates the log parsers to parse drop and reject logs. To allow the profiles
#                  of drop connectivity to be compared the policies are output as accept rules with the 
#                  prefix on rulebases and filenames of "DROPS-".
#                - This release also allows you to output the preprocessed logs in json format, which can
#                  be used to roll log connectivity together or many other types of processing.
#                - This release also includes many performance enhancements in the rule build stages.

# Version v0.5.8 - This release updates the log parsers so less supurious and source ports are resolved.
#   05/09/2016   - This release updates the log parsers for Cisco ASA syslogs, Netscreen ScreenOS6
#                  and FW1 logexport format so that virtual connectons logged for known port UDP replies
#                  are reversed. The temporary known ports are taken from a large part centos /etc/services
#                - This release also updates the log to policy filter so that connections are matched
#                  to only the most speciffic proto and port match for all IP matches. Firewall rulebases
#                  or rulegroups are now processed in the order in which they are entered.
#                - This release also adds the new 'names' filter type.  This new default set permits
#                  IPs that could not be matched to existing firewall objects to be checked for theirs 
#                  name via DNS reverse name lookup (and whois if you uncomment the lines).
#                - The rashed rules output now indicates source, dest, port and original rule more clearly.
#                - Two new helper scripts have been added: 
#                . resolvenames.pl searches 'od' style CSV's for nets called Log_Net_<ip>-<nm> created
#                  with res mode, reverse looks up names and outputs report.txt, it reads this file at
#                  startup skips the ip blocks already resolved writes newly resolved names back to report.txt
#                . makehostcsv.csv converts the report.txt to 'od' style CSV format names.  These names
#                  can be used in 'rr' or 'bldobj' mode to translate any unknown ip's from configs output
#                  in res mode.
#                - Fixed bug in name <ip> reader - removed or incorrect name statements are warned about
#                  during the policy read subs.

# Version v0.5.7 - This release updates the predefined FW1, ASA and ScreenOSdefault service objects.
#   02/03/2016   - Port group processing during rule group building is now significantly faster.
#                - Also includes many fixes for policy readers and service object processing.

# Version v0.5.6 - This release updates the bloobj mode to fix the bug introduced "for names with spaces"
#   08/02/2016   - Bldobj mode will now output rulebases correctly.

# Version v0.5.5 - This release updates the internal logic to handle names with spaces correctly.
#   31/01/2016   - The semicolon character is no longer valid for object and group names.
#                - This release changes the WARNING status of some common messages to INFO status.
#                - Many log files can now be read by specifying the directory and an optional search string.
#                - This release also add further circular group checking to the build routines but currently full
#                  circular group checking has not been backported due to the different datastrures.
#                - MERGE-TO and FILTER counts are no longer printed if they are not used.

# Version v0.5.4 - This release updates the 'loose' and 'loosen' filters so that 'include' filters
#   24/01/2016     work the same as 'exclude' filters did.  
#                  This release also updates the Netscreen Parser so that it reads lines with spaces
#                  at the beginning.

# Version v0.5.3 - This release adds the Cisco ASA default service 'ntp'.
#   14/01/2016     This service will now be properly recognised in rules and groups.

# Version v0.5.2 - This release adds a vital omision, missing from the last release:
#   10/01/2016     now reads Cisco ASA configs with spaces at the start of lines.
#                  ...the best laid plans of mice.
#                  This release also backports Cisco ASA log parser snipets from SuperFAAR:
#                  ASA-6-106100 log entries are now parsed and fixups for icmp directionality have been added
#                  to the ASA-6-302020 and ASA-6-302021 parsers.

# Version v0.5.1 - This release back ports the "create new objects" option from SuperFAAR.
#   01/12/2015     It also changes the default options for 'res' mode to make them more useable and include this option.
#                  The 'res' option will now generate new /27 netobjects called 'Log_Net_<SubnettedIP>-255.255.255.224' for 
#                  log connectivity matching an IP 'any' object in a rulebase, and uses these new objects in the rules generated.
#                  This allows you to build completely new rulebases and: 
#                   generate new /27 objects from the logs with the rule:  anyip to anyip on any service
#                  Alternately you could build only the internal network: 
#                                                          with the rule: net 10/8 to anyip on any service
#                  The second will only generate new objects for the matching networks from the logs and rules that were destinations
#                  outside of the ten net (it will need to be added to the config bundle for the rule to parse, so will match for 
#                  source 10/8 and longer in the logs).
#                  The reason this has not been back ported before is because it "polutes" the network objects tree with objects
#                  that do not exist in original config.  Its a one time change once the objects are added they can be removed
#                  without reloading the configs. SuperFAAR can delete a config from memory and reload from the database if required.
#                  However this might be a good thing if your starting with a log file an no objects.
#                  If you want to change the mask length of the new objects search '00000' and change the values to what you require.
#                  SuperFAAR has several options for this and also options to make a rulebase more specific when required.
#                  Also SuperFAAR contains newly generated object rules from 'any' rule matches, within the rulebase section 
#                  in which they have been generated.  This combined with maintaing rulebase section headers and rule type specificity
#                  builds rulebases that are faar more recognisable.

# Version v0.5.0 - This release back ports the config parsers from the Enterprise Edition SuperFAAR. These parsers are greatly
#		   improved from the last release.  This release only back ports the config parsers for the existing config parsers.
#		   new config parsers (for other firewall manafacturers) are only be available in the Enterprise Releases: 
#			* 360-FAARen and 
#			* SuperFAAR.
#		 - This release ONLY back ports the conifg parsers. 
#		 - None of the following has been backported: 
#			* improved config bundle building algorithms, 
#			* complex rulebase processing in rr mode, 
#			* new subnetted object creation for the expanding out of 'any' rules for unknown ips from logs.
#			* dynamic group creation for output Cisco configs to reduce access-list statements.
#			* improved object translation (algorithms and user output), 
#			* improved object matching between differing config types,
#			* most speciffic or all possible policy matching to log connectivity information.
#			* greatly improved usability, 
#			* significntly improved print, filterprint, bldobj modes.
#			* a lot more colour, 
#			* and very much improved and more flexible output config writers, 
#			* as well as many algorithmig optimizations anda great deal of code cleanup.  
#			* many many bug fixes.
#			* faar better memory usage and the ability to parse many binary logs sequentially to save memory.
#			* batch mode processing for adding config bundles to the database back end.
#			* The internal subroutines retain their original names but most have been completely reworked
#			* Database storage and multiple client access (either read or write access).
#			* The ablilty to store and compare / merge many configs and copy / merge many logs over time.
#			* The ability to read directories of log files and generate binary logs from 50 or 1000 at a time.
#		 - This release also updates the output config writer subs to their latest version before the integrated output and 
#		   translation subs were dropped in favour of cleaner seperated translation and output subs as in SuperFAAR and 
#		   360-FAARen, these new subs also handle rulebase structure and output sections and headers (not supported in this version).
#		 - The following bug fix has also been added, which is to correct the processing of default service ranges added
#		   to the ordered ports list from the parsers.  This should greatly improve the quality of the ports hash
#		   this bug fix is unnecessary in SuperFAAR and 360-FAARen as the process has been simplified and the code the bug
#		   existed in removed.
#		 - The default Cisco objects have been updated to include the 'any4' net object, to be able to parse ASA9.3+ IPv4 configs.
#		 - This release uses more modern modules, thanks to AJH.
#		 - The reason the parsers have been back ported is so that the open source algorithms can be used with more modern
#		   configurations, (eg: Cisco ASA 9.3+) and also to provide better warnings while parsing configs.
#		 - The algorithms already opensourced herin are sufficient for most small to medium firewall configuration situations,
#		   and can be used for IP translation (bldobj mode), rulebase simplification (rr mode) and object ananlysis (print modes). 
#		   For use with the open source version configurations can be split into rulebase sections and processed seperatily, 
#		   new groups can be added to input configs to create differently built rulebases, which can then be added together,
#		   either in sections (by cuting and pasting output files) or by merging them in rr mode.
#		 - The enterprise editions handle all these tasks for you.
#		 
#   IMPORTANT    - If you require Enterprise firewall analysis please consider looking at SuperFAAR, its probably not as much as you think!
#		 - If you require demo version please contact dan@360-faar.com, we will need to sign mutual NDA's after which I can provide
#		   demo software (the current version of SuperFAAR without the output config writers or database back end).
#		 - If you require support during the demo period its free for the period fo the demo - currently we have no outstanding
#		   bugs, this is not because there are none, but that every bug found has been resolved to our customers satisfaction.
#		 - The turn around for bug fixes is 24 hours, and for feature requests we average a week turnaroud.
#		 - Also, if you are using this for production use you should note the BETA status of the project, that status is justified
#		   which is why the algorithms have been rewritten for the Enterprise Releases SuperFAAR and 360-FAARen.
#		   You have been warned!!
#

# Version v0.4.6 - This release correctly translates output netscreen group names in comment lines and comments are output last.
#		 - Empty groups are not matched in build_rules subs - should be irrevelavant, but just incase.
#		 - Rule comments are output in 'set name' statements in policy id mode for netscreen rulebases.
#		 - Netscreen rules 'name' strings are added with rule descriptions and net ranges are translated as ranges.
#		 - Netscreen and checkpoint default services have been updated with a few new services definitions.
#		 - 'rr' mode 'nat' defaults added - the same as 'yes' defaults with CIDR filter NAT translations switched on.
# Version v0.4.5 - This release fixes rulebase output bugs when using the 'cl' option in 'rr' mode.
#		 - Netscreen rulebase numbers now otput usable rule numbers in 'cl' rulebases.
#		 - Also, hopefully the ctrl-c panic when reading logs is fixed.
#		 - 'rr' mode 'log' defaults now switch off 'Any' rule to object and service object resolution. 
#		 - 'rr' mode 'res' defaults now switch on most resolution and matching options.
# Version v0.4.4 - This release adds the "resolve services from 'Any' objects" option to the 'rr' mode.
#		   This new 'rr' mode option requires that a log file is loaded and that the output policy is filtered using it.
#		   When connectivity is found in the logs that matches a policy instance with the 'Any' service specified, the 
#		   proto and port from the logs are used in the output policy and resolved objects are not added to the source 
#		   config bundles but are reported during the rule build stages and should be added manually.
#		 - Unknown service definitions are not output but are used in rules - cisco output uses unknown-proto in rules.
#		 - Also, this release adds the "resolve 'Any' network objects to known nets" option to thr 'rr' mode.
#		   This new 'rr' mode 'log' default resolves binary objects from the logs using all existing network objects
#		   from the "merge from" config bundle, and uses them in the new policy.
# Version v0.4.3 - This release adds the 'hc' option to build rules in 'rr' mode and arrange the most hit new rules at the top.
#		   BEWARE: Hit count rules are not 100% reliable at present!!! Hit counts can be multiplied for multi IP objects.
#		 - 'cl' mode rules now use the original global rule number instead of incrementing it by 1.
#		 - The defaults for 'rr' mode rule builds have been changed - say no to ALL DEFAULTS to see new default options.
#		 - Added 'log' defaults to 'rr' mode, this selects the same new defaults but chooses 'yes' in filter with logs.
#		 - Nat rule dots printing is more frequent to give better visual output.
#		 - Less dots are printed for log to rule matches in 'rr' mode.
#		 - 'load' mode now doesnt try to load logs and nats from '.' when you skip loading these files
#		 - Rules that are not logged with a rule number in checkpoint are now listed as rule 0 which hopefully resolves
#		   the non numeric sort errors in 'rr' mode.
# Version v0.4.2 - This release adds the 'cl' option to clean/filter original rules, in 'rr' mode, and allows output of service. 
#		   priority rules as well as the original dst src priority rule build.
#		 - The 'rr' mode menu has been simplified further
#		 - Starting the script without any options now starts load mode to add at least one config.
#		 - This release fixes a bug in the 'any' object matching, any will now be matched from logs.
#		 - The rashfilter hash tree format has been changed to match the order of the other rule 
#		   processing hashes: mergebase, filterbase and rulegroups, this should reduce memory use slightly.
# Version v0.4.1 - This release adds the 'mergelog' mode.  This mode allows you to add binary log entries from one
#		   config with another, this does not update the information output by 'print' mode but does update
#		   the binary log information used by 'rr' mode.
#		 - This release also significantly updates the user interface.  You can now choose options using an
#		   option number instead of the text value.
#		 - Help is no longer printed if you start the script without any options.  This allows all configs to 
#		   be loaded from the 'load' menu instead of specifying them on the command line.
#		 - Added 'verbose' switches to 'print' and 'rr' modes so that screen output can be switches off.
#		 - The netscreen output stage now uses a default zone if none are specified.
#		 - Also, all 'end.' key words have been changed to simply '.' to reduce the number of keystrokes needed
#		   for each rationalization. Entering '0' now adds all options and '.' chooses the default if availble.
# Version v0.4.0 - This release changes the command line options and permits you to process as many configs as you choose
#		 - Some MIP functionality was fixed in the Netscreen Reader sections.
#		 - All config reading and processing has been refactored into subroutines.
#		 - Three new modes have been added:
#		   'load' mode allows you to load new config bundles into an already running instance of 360-FAAR
#		   'copylog' mode associates a log file from one config with another loaded or new config.
#		   'help' mode prints info about all of the other modes
#		   Undefined warnings have been resolved when using CTRL-C to exit the user loop.
# Version v0.3.9 - release permits you to to choose they types of rules and which rule actions to include in the 
#		   rule rationalization mode.  Both the 'merge from' and 'filter' rulebases rule types can be chosen.
#		 - The 'rr' mode rule unwrap code has been optimized.
# Version v0.3.8 - This release adds Cisco ASA 8.3+ object NAT to the cisco reader section for static and dynamic NAT.
#		   Network objects, ranges and IPs are translated - groups are not presently translated.
#		 - Runnig the script with '--help' or '-h' or 'h' in the first arguement now prints the simple help screen.
#		 - Two new options have been added to the 'rr' mode filters, to allow encryption rules from the merge from and to
#		   rulebases to be used to mask later rules in the merge from rulebase.
#		 - Matches output during 'rr' mode filtering are now listed using the source config bundle object names instead of 
#		 - the binary CIDR IP's.
# Version v0.3.7 - This release fixes many of the bugs in the cisco reader and writer sections, 
#		   so that cisco configs can now be processed written, read processed and written again cyclicly
#		 - Access lists using proto groups, specifying only protocol details or using 'any' services are now handled.
#		 - Protocol group-objects are written and used in rules for service groups with different protocols specified within them.
#		 - port-object's are read in service objects, service groups and protocol groups alike.
#		 - The cisco 'echo' default service has been updated to remove tcp and udp from its listed ports.
# Version v0.3.6 - This release resolves many of the problems with the filter sections, many of the undefined warnings are resolved.
#		 - Both the speciffic and the subnet 'rr' mode filter sections have been upgraded to fix many of the issues related to 
#		   combining various filter mode types, and the filters behaviour should be much more predictable.
#		 - The Cisco and od outut section definitions now print service defs for all defined proto types
# Version v0.3.5 - This release introduces three new sub routines that are used to run much stronger consistency checks against the 
#		   internal network and service object, group and rule definitions after each round of processing.  These new tests 
#		   provide much greater visibility of incomplete objects and rules and give details of any missing object elements.
#		 - The netscreen reader now reads "interface dip" and rule "dip-id" statements and adds appropriate objects 
#		   and nat translation rules.
#		 - Warnings are printed for unknown cisco object group-objects found in policies during the config read.
#		 - NAT SRC DST translations in 'rr' mode now support range objects using the range start address only and network 
#		   objects are now translated to their network CIDR rather than the full binary IP.
#		 - Various other updates to resolve "undefined" warnings
# Version v0.3.4 - This release resolves Cisco ICMP default services with out printing stringified hash references in the cs output
#		 - Also Cisco network and range objects are listed as such in object-groups instead of as hosts
#		 - The cisco output writer uses 'object' in access-lists instead of IP NM, as well as listing range objects using 'range' 
#		   in access-lists as well as groups.  I should probably just use 'object' but the key word is easily changed and 
#		   IMHO it makes the polices more readable
#		 - The NAT translation now supports SRC NAT translation for known network objects in rr mode filters
# Version v0.3.3 - This release adds Cisco ASA static nat statements to the nats table for IP IP NM and access-list nats.
#		 - The < and > range identifiers used in ports are now striped before printing out Netscreen policies in rr mode.
#		 - Some of the undefined warnings have been resolved
# Version v0.3.2 - This release reads Netscreen interface vip statements and adds them to the NATs table
#		 - The Cisco internal rule object type definitions that are added to rulebases built from ASA or PIX configs
#		   have been corrected - these definitions are not used for anything yet.
#		 - Further consistency checks have been added to the policy build sections to more easily identify problem objects.
#		 - The NEW helper script htmlprintcsv.pl converts the 'print' mode output CSV file to HTML, run the script for info.
# Version v0.3.1 - This release cleans up the output in the new columns, so that speciffic VPN and negation usage is easier to see.
#		   The Cisco ASA/PIX reader has been upgraded so that it prints more user friendly info during the config read
#		   and handles rules using protocol groups far better than before.  
#		 - The cisco config reader now also correctly reads negated source and dest services.
# Version v0.3.0 - This release further updates the 'print' and 'fltprint' mode spreadsheets to include VPN tunnel usage info
#		   and source / destination negation from the policy as well as "install on" info.
#		   'print' modes now include most all of the "important" details pulled from the configs and logs.
# Version v0.2.9 - This release further upgrades the NAT analysis capabilities, more NAT details are listed in 'print' mode
# Version v0.2.8 - This release adds new columns to the 'print' mode spreadsheets to list the policy and log NAT translations.
#		   The NAT rule processing is further updated to include log and policy information in the network objects.
# Version v0.2.7 - This release completely dropps the previous NAT methodology and integrates NATs into the rule processing subs 
#		   and also sports a rewrite of the NAT structures and nat rule processing, this new method is much more robust
#		 - Negated rules are now identified in Netscreen and excluded from rr mode rulebases
# Version v0.2.6 - Corrected MIP interface NAT ANY service name and added nat dst ip statements to NATs tables
#		 - Correctly reads disabled rules in netscreen and adds further checks to the rr mode rulebase builters
#		 - Netscreen reader now reads tunnel vpn rules
# Version v0.2.5 - Added 'end.' comments to rr mode "enter search INC EX string" instructions
#		 - Added 'exit' to menu and tried to resolve looping issue when using CTRL-c ...did it work?
#		 - This release also resolves netscreen MIP(ipaddr) objects from interface mip statements and adds them to the NATs
#		 - Issues resolved: incorrect protocol definitions (used when merging between checkpoint - netscreen) are skipped,
#		   and unknown rule types are skipped and reported - e.g. netscreen tunnel rules
# Version v0.2.4 - Further updates the cisco policy writer and resolves issues with service group access lists
#		 - This release also resolves a few cisco reader bugs that printed undefined warnings
# Version v0.2.3 - Further updates to dbedit output - od mode now outputs object and service groups
#		 - Dbedit output is also now printed straight to file 
# Version v0.2.2 - Added object output to dbedit text in od mode, and NOTE: statements to the policy reader sections.
#		 - net and service_builder subs now catch and report circular groups and sub groups
#		 - fixed several bugs in cisco object, group and rule readers and writers
#		 - changed proto port and toZone fromZone divider character from . to ~
# Version v0.2.1 - Removed default service definitions that were not recognised in FW-1 r75.10 and caused dbedit policy build to fail.
# Version v0.2.0 - Changed project status to BETA - feedback needed!!!
#		 - Signigicantly upgraded the cisco object readers and writers and added more object checks to the netscreen and odumper
#		   readers, plus fixed the policy src print field and many other bugs
# Version v0.1.9 - Log to binary log conversion now writes log and rule usage hits to netobjects and 'print' mode prints this info
#		 - The log object resolution matches to the most specific CIDR range, to properly match traffic to rules use 'rr' mode
#		 - Print mode also now lists src and dst service associations from rules for each object
# Version 0.1.8.1- Updated netscreen obj reader to flag DNS names in set address cmd's and capture service timeout cmd's
#		 - Thanks to M.T. for flagging these issues so concicely!! Let me know if you want your name here if you read this.
# Version v0.1.8 - Added cisco policy output subroutine and sub groups to cisco reader
# Version 0.1.7.1- Fixed underfined warning in checkpoint log file reader for logs without service_id field.
# Version v0.1.7 - Fixed autovivication problem in bin log zone check, rule comments on original filtered rules, netscreen
#		   Any object name fixed, cisco apen protocol rules improved, add_srvc protocol issue fixed and log reader added.
# Version v0.1.6 - Bug Fixed and improved 'print' mode, fixed duplicate issue in cs mode, and many more bugs fixed in 
#		   in the cisco asa rule reading, as well as fixing misses in the binary log translation service matches.
#		 - the improved print mode gives object duplicates, supernets, subnets, hosts on nets, rule obj usage etc.
#		 - Added the 'fltprint mode', that filters the object analysis spreadsheet as its output
# Version v0.1.5 - ASA/PIX reader working well, new 'print' mode working, better named and organised subs
#		 - print mode is a little noisy (warnings) but the warnings are for window dressing that is missing
# Version v0.1.3 - better bldobj mode and notes and zone mappings sorted in netscreen out, and groups translated
#                - service groups translated and odumper service group field spelling corrected.

# This program was writen by Dan Martin of 360 Analytics Ltd. 
#---------------------------------------------------------------------------------------------------
# www.360-faar.com dan@360-faar.com +44 7960 028 070 <- no one has ever called me on this number
