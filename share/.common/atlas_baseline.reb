Description: Atlas system baseline - the facts every Windows installation states about itself
Author: Atlas
Version: 1.0
Id: 5c1c1b2e-3f0a-4c1e-9a6d-atlasbaseline1
Keys:
#
# One targeted batch per hive: the values the baseline reads, nothing else.
# Values under every control set are collected; the baseline keeps the one
# Select\Current names. Plugins registered with RECmd (user accounts, time
# zone, profile list, USBSTOR, network list, uninstall) format their keys.
#
# ---- SYSTEM ----
    -
        Description: Current control set
        HiveType: SYSTEM
        Category: Baseline
        KeyPath: Select
        ValueName: Current
        Recursive: false
        Comment: "Which ControlSet00N is current"
    -
        Description: Computer name
        HiveType: SYSTEM
        Category: Baseline
        KeyPath: ControlSet00*\Control\ComputerName\ComputerName
        ValueName: ComputerName
        Recursive: false
        Comment: "The machine's own name"
    -
        Description: Time zone
        HiveType: SYSTEM
        Category: Baseline
        KeyPath: ControlSet00*\Control\TimeZoneInformation
        Recursive: false
        Comment: "TimeZoneKeyName (Vista and later) or StandardName (XP), Bias, DaylightBias, ActiveTimeBias"
    -
        Description: Last shutdown
        HiveType: SYSTEM
        Category: Baseline
        KeyPath: ControlSet00*\Control\Windows
        ValueName: ShutdownTime
        Recursive: false
        Comment: "FILETIME of the last clean shutdown"
    -
        Description: TCP/IP parameters
        HiveType: SYSTEM
        Category: Baseline
        KeyPath: ControlSet00*\Services\Tcpip\Parameters
        Recursive: false
        Comment: "Hostname, Domain (DNS suffix only), DhcpDomain"
    -
        Description: Interfaces
        HiveType: SYSTEM
        Category: Baseline
        KeyPath: ControlSet00*\Services\Tcpip\Parameters\Interfaces
        Recursive: true
        Comment: "Per-adapter IPAddress, DhcpIPAddress, SubnetMask, DefaultGateway, DhcpServer, LeaseObtainedTime, LeaseTerminatesTime"
    -
        Description: USB storage devices
        HiveType: SYSTEM
        Category: Baseline
        KeyPath: ControlSet00*\Enum\USBSTOR
        Recursive: true
        Comment: "Vendor, product, serial, first and last connect"
    -
        Description: Mounted devices
        HiveType: SYSTEM
        Category: Baseline
        KeyPath: MountedDevices
        Recursive: false
        Comment: "Volume names for removable devices"
    -
        Description: Prefetcher
        HiveType: SYSTEM
        Category: Baseline
        KeyPath: ControlSet00*\Control\Session Manager\Memory Management\PrefetchParameters
        ValueName: EnablePrefetcher
        Recursive: false
        Comment: "What an absence of Prefetch means"
    -
        Description: Last access updates
        HiveType: SYSTEM
        Category: Baseline
        KeyPath: ControlSet00*\Control\FileSystem
        ValueName: NtfsDisableLastAccessUpdate
        Recursive: false
        Comment: "What a last-access time means"
    -
        Description: Event log channels
        HiveType: SYSTEM
        Category: Baseline
        KeyPath: ControlSet00*\Services\EventLog
        Recursive: true
        Comment: "MaxSize and Retention per channel"
    -
        Description: Volume shadow copies
        HiveType: SYSTEM
        Category: Baseline
        KeyPath: ControlSet00*\Services\VSS
        Recursive: false
        Comment: "Start value of the shadow copy service"
    -
        Description: Audit policy (XP and later, LSA)
        HiveType: SYSTEM
        Category: Baseline
        KeyPath: ControlSet00*\Control\Lsa
        Recursive: false
        Comment: "LSA settings beside the audit policy"
# ---- SOFTWARE ----
    -
        Description: Windows version
        HiveType: SOFTWARE
        Category: Baseline
        KeyPath: Microsoft\Windows NT\CurrentVersion
        Recursive: false
        Comment: "ProductName, CurrentBuild, CurrentVersion, CSDVersion, EditionID, InstallDate, RegisteredOwner, RegisteredOrganization"
    -
        Description: Profile list
        HiveType: SOFTWARE
        Category: Baseline
        KeyPath: Microsoft\Windows NT\CurrentVersion\ProfileList
        Recursive: true
        Comment: "Profile paths per SID; domain users appear here, not in SAM"
    -
        Description: Installed software (64-bit view)
        HiveType: SOFTWARE
        Category: Baseline
        KeyPath: Microsoft\Windows\CurrentVersion\Uninstall
        Recursive: true
        Comment: "DisplayName, DisplayVersion, InstallDate"
    -
        Description: Installed software (32-bit view)
        HiveType: SOFTWARE
        Category: Baseline
        KeyPath: WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
        Recursive: true
        Comment: "DisplayName, DisplayVersion, InstallDate"
    -
        Description: Network profiles
        HiveType: SOFTWARE
        Category: Baseline
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
        Recursive: true
        Comment: "ProfileName, DateCreated, DateLastConnected"
    -
        Description: Network signatures
        HiveType: SOFTWARE
        Category: Baseline
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures
        Recursive: true
        Comment: "DefaultGatewayMac (the gateway's, never the host's), DnsSuffix"
# ---- SAM ----
    -
        Description: Local accounts
        HiveType: SAM
        Category: Baseline
        KeyPath: SAM\Domains\Account\Users
        Recursive: true
        Comment: "Local accounts only: RID, created, last logon, logon count, flags"
# ---- SECURITY ----
    -
        Description: Primary domain name (raw)
        HiveType: SECURITY
        Category: Baseline
        KeyPath: Policy\PolPrDmN
        Recursive: false
        Comment: "UTF-16 name after the LSA string header; decoded by the baseline"
    -
        Description: Primary domain SID (raw)
        HiveType: SECURITY
        Category: Baseline
        KeyPath: Policy\PolPrDmS
        Recursive: false
        Comment: "Binary SID, empty on a workgroup machine; decoded by the baseline"
    -
        Description: Audit policy (raw)
        HiveType: SECURITY
        Category: Baseline
        KeyPath: Policy\PolAdtEv
        Recursive: false
        Comment: "Audit categories; read through rip.pl auditpol"
