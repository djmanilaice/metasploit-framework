require 'msf/core'
require 'msf/core/payload/windows/exec'


###
#
# Extends the Exec payload to run Scientific calc.
#
###
module Metasploit3
    
	include Msf::Payload::Windows::Exec
    
	def initialize(info = {})
		super(update_info(info,
                          'Name'          => 'Windows Execute calc.exe with Scientific layout',
                          'Description'   => %q{
                          Run Scientific calc.exe
                          },
                          'Author'        => ['DJ Manila Ice - @manils'],
                          'License'       => MSF_LICENSE,
                          'Platform'      => 'win',
                          'Arch'          => ARCH_X86,
                          'Privileged'    => true))
        
		# Register command execution options
		register_options(
                         [
                         OptString.new('NUM', [ false, "Number of calcs to launch", "1"]),
                         OptString.new('DISPLAYNUM', [ false, "Numeric number to display","31337"]),
                         ], self.class)
        
		# Hide the CMD option...this is kinda ugly
		deregister_options('CMD')
	end
    
	#
	# Override the exec command string - this is super ghetto and I'm gonna do this in asm with c0relanc0der instead.
	#
	def command_string
		reg_edit = 'reg add "HKCU\Software\Microsoft\Calc" /f /v layout /t REG_DWORD /d 0'
		loop_count = datastore["NUM"]
		display_num = datastore["DISPLAYNUM"]
		message = 'echo var sh = WScript.CreateObject("WScript.Shell"); > calc.js && ' +
        'echo sh.AppActivate("Calculator"); >> calc.js &&' +
        'echo sh.SendKeys("^V"); >> calc.js'
		return "cmd.exe /c #{reg_edit} && echo #{display_num} | clip && #{message} && FOR /L %i IN (1,1,#{loop_count}) DO start /b calc.exe & timeout 1 & cscript calc.js & timeout 1"
	end
end

