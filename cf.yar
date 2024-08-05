import "pe"
import "dotnet"
import "console"

private global rule IsDotNetExe {
	condition:
		dotnet.is_dotnet
}

rule ConfuserEx_Watermark {
	meta:
		description = "Detects ConfuserEx watermark in .NET binaries. Most of the time this is removed, but here for completeness"

	strings:
		$s1 = "ConfuserEx v"
		$s2 = "ConfusedByAttribute"
	
	condition:
		$s1 or $s2
}

rule SuppressIldasm {
	meta:
		description = "Detects SuppressIldasm attribute in .NET binaries, not specific to ConfuserEx"

	strings:
		$s1 = "SuppressIldasmAttribute"
	
	condition:
		$s1
}

global rule ConfuserEx_General {
	meta:
		description = "Detect unicode naming pattern used by ConfuserEx when any code protection is enabled. This is present even if the user chooses to use a different renamer"

	strings:
		$name_pattern = { E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 8? ?? E2 80 AE } // I have seen 40-41 repititions

	condition:
		$name_pattern
}

private rule VirtualProtect {
	strings:
		$s1 = "kernel32.dll"
		$s2 = "VirtualProtect"

	condition:
		$s1 and $s2
}

rule ConfuserEx_AntiTamper_Normal {
	strings:
		$s1 = "GetFunctionPointerForDelegate"

	condition:
		VirtualProtect
		and not $s1
		and pe.sections[0].characteristics == 0xE0000040
		and pe.sections[pe.number_of_sections - 1].characteristics == 0x60000020
		and pe.sections[pe.number_of_sections - 1].name == ""

		// TODO detect mkaring version that does insert before .reloc
}

rule ConfuserEx_AntiTamper_JIT {
	strings:
		$s1 = "GetFunctionPointerForDelegate"

	condition:
		VirtualProtect
		and $s1
		and for any section in pe.sections : (
			section.characteristics == 0x60000020
			and section.name == ""
		)
		and for any section in pe.sections : (
			section.characteristics == 0xE0000040
		)
}

rule ConfuserEx_Constants {
	meta:
		description = "ConfuserEx constants protection which may include string protection, primitives, etc."

	strings:
		$s1 = "CreateInstance"
		$s2 = "GetElementType"
		$s3 = "BlockCopy"
		$s4 = "GetString"
		$shift = { 11 08 11 06 }

	condition:
		$s1 and $s2 and $s3 and $s4 and $shift 
}


rule ConfuserEx_ControlFlow_Switch {
	strings:
		$switch = { 20 [4] 61 25 0A ?? 5E 45 }

	condition:
		$switch
}

rule ConfuserEx_AntiDump {
	strings:
		$h1 = { 08 1F 3C D3 58 0D 08 09 4B 58 0D }
		$h2 = { 61 25 13 2C } // w/ ref proxy
		$h3 = { 11 1A 20 [4] 5A 20 [4] 61 }
		$h4 = { 11 06 1A D3 18 5A 58 20 [4] 53 }
		$s1 = "GetTypeFromHandle"
		$s2 = "op_Explicit"
		$s3 = "GetHINSTANCE"

	condition:
		VirtualProtect
		and (
			$h1 or $h2 or $h3 or $h4
		)
		and $s1
		and $s2
		and $s3
}

rule ConfuserEx_AntiDebug_Win32 {
	meta:
		description = "ConfuserEx anti-debugging protection in \"win32\" mode"

	strings:
		$s1 = "CloseHandle"
		$s2 = "IsDebuggerPresent"
		$s3 = "OutputDebugString"
		$s4 = "ParameterizedThreadStart"

	condition:
		$s1 and $s2 and $s3 and $s4
}

rule ConfuserEx_AntiDebug_Safe {
	meta:
		description = "ConfuserEx anti-debugging protection in \"safe\" mode"

	strings:
		$s1 = "get_IsAttached"
		$s2 = "IsLogging"
		$s3 = "FailFast"

	condition:
		$s1 and $s2 and $s3 and not ConfuserEx_AntiDebug_Win32
}

rule ConfuserEx_AntiDebug_Antinet {
	meta:
		description = "ConfuserEx anti-debugging protection in \"antinet\" mode"

	strings:
		$s1 = "kernel32"
		$s2 = "GetCurrentProcessId"
		$s3 = "CreateNamedPipe"
		$s4 = "CreateFile"

	condition:
		$s1 and $s2 and $s3 and $s4
}

rule ConfuserEx_InvalidMetadata {
	strings:
		$s1 = "#Strings"
		$s2 = "#GUID"
		$s3 = "#Blob"
		$h1 = { FF 7F FF 7F FF 7F }

	condition:
		#s1 > 1
		and #s2 > 1
		and #s3 > 1
		and $h1
}

rule ConfuserEx_RefProxy_Strong {
	strings:
		$s1 = "GetFieldFromHandle"
		$s2 = "ResolveSignature"
		$s3 = "GetOptionalCustomModifiers"
		$s4 = "SetLocalSignature"

	condition:
		$s1
		and $s2
		and $s3
		and $s4
}

rule ConfuserEx_Resources_Protection {
	strings:
		$s1 = "get_CurrentDomain"
		$s2 = "add_AssemblyResolve"

	condition:
		$s1
		and $s2
}

rule ConfuserEx_Packer {
	meta:
		description = "ConfuserEx packer/compressor mode"

	strings:
		$s1 = "GCHandle"
		$s2 = "Free"
		$s3 = "GetExecutingAssembly"
		$s4 = "GetEntryAssembly"
		$s5 = "GetManifestResourceStream"
		$s6 = "LoadModule"

	condition:
		$s1
		and $s2
		and $s3
		and $s4
		and $s5
		and $s6
}
