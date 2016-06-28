Global Const $fc_nooverwrite = 0
Global Const $fc_overwrite = 1
Global Const $fc_createpath = 8
Global Const $ft_modified = 0
Global Const $ft_created = 1
Global Const $ft_accessed = 2
Global Const $fo_read = 0
Global Const $fo_append = 1
Global Const $fo_overwrite = 2
Global Const $fo_createpath = 8
Global Const $fo_binary = 16
Global Const $fo_unicode = 32
Global Const $fo_utf16_le = 32
Global Const $fo_utf16_be = 64
Global Const $fo_utf8 = 128
Global Const $fo_utf8_nobom = 256
Global Const $fo_utf8_full = 16384
Global Const $eof = -1
Global Const $fd_filemustexist = 1
Global Const $fd_pathmustexist = 2
Global Const $fd_multiselect = 4
Global Const $fd_promptcreatenew = 8
Global Const $fd_promptoverwrite = 16
Global Const $create_new = 1
Global Const $create_always = 2
Global Const $open_existing = 3
Global Const $open_always = 4
Global Const $truncate_existing = 5
Global Const $invalid_set_file_pointer = -1
Global Const $file_begin = 0
Global Const $file_current = 1
Global Const $file_end = 2
Global Const $file_attribute_readonly = 1
Global Const $file_attribute_hidden = 2
Global Const $file_attribute_system = 4
Global Const $file_attribute_directory = 16
Global Const $file_attribute_archive = 32
Global Const $file_attribute_device = 64
Global Const $file_attribute_normal = 128
Global Const $file_attribute_temporary = 256
Global Const $file_attribute_sparse_file = 512
Global Const $file_attribute_reparse_point = 1024
Global Const $file_attribute_compressed = 2048
Global Const $file_attribute_offline = 4096
Global Const $file_attribute_not_content_indexed = 8192
Global Const $file_attribute_encrypted = 16384
Global Const $file_share_read = 1
Global Const $file_share_write = 2
Global Const $file_share_delete = 4
Global Const $file_share_readwrite = BitOR($file_share_read, $file_share_write)
Global Const $file_share_any = BitOR($file_share_read, $file_share_write, $file_share_delete)
Global Const $generic_all = 268435456
Global Const $generic_execute = 536870912
Global Const $generic_write = 1073741824
Global Const $generic_read = -2147483648
Global Const $generic_readwrite = BitOR($generic_read, $generic_write)
Global Const $frta_nocount = 0
Global Const $frta_count = 1
Global Const $frta_intarrays = 2
Global Const $frta_entiresplit = 4
Global Const $flta_filesfolders = 0
Global Const $flta_files = 1
Global Const $flta_folders = 2
Global Const $fltar_filesfolders = 0
Global Const $fltar_files = 1
Global Const $fltar_folders = 2
Global Const $fltar_nohidden = 4
Global Const $fltar_nosystem = 8
Global Const $fltar_nolink = 16
Global Const $fltar_norecur = 0
Global Const $fltar_recur = 1
Global Const $fltar_nosort = 0
Global Const $fltar_sort = 1
Global Const $fltar_fastsort = 2
Global Const $fltar_nopath = 0
Global Const $fltar_relpath = 1
Global Const $fltar_fullpath = 2
Global Const $prov_rsa_full = 1
Global Const $prov_rsa_aes = 24
Global Const $crypt_verifycontext = -268435456
Global Const $hp_hashsize = 4
Global Const $hp_hashval = 2
Global Const $crypt_exportable = 1
Global Const $crypt_userdata = 1
Global Const $calg_md2 = 32769
Global Const $calg_md4 = 32770
Global Const $calg_md5 = 32771
Global Const $calg_sha1 = 32772
Global Const $calg_3des = 26115
Global Const $calg_aes_128 = 26126
Global Const $calg_aes_192 = 26127
Global Const $calg_aes_256 = 26128
Global Const $calg_des = 26113
Global Const $calg_rc2 = 26114
Global Const $calg_rc4 = 26625
Global Const $calg_userkey = 0
Global $__g_acryptinternaldata[3]

Func _crypt_startup()
	If __crypt_refcount() = 0 Then
		Local $hadvapi32 = DllOpen("Advapi32.dll")
		If $hadvapi32 = -1 Then Return SetError(1, 0, False)
		__crypt_dllhandleset($hadvapi32)
		Local $iproviderid = $prov_rsa_aes
		Local $aret = DllCall(__crypt_dllhandle(), "bool", "CryptAcquireContext", "handle*", 0, "ptr", 0, "ptr", 0, "dword", $iproviderid, "dword", $crypt_verifycontext)
		If @error OR NOT $aret[0] Then
			Local $ierror = @error + 10, $iextended = @extended
			DllClose(__crypt_dllhandle())
			Return SetError($ierror, $iextended, False)
		Else
			__crypt_contextset($aret[1])
		EndIf
	EndIf
	__crypt_refcountinc()
	Return True
EndFunc

Func _crypt_shutdown()
	__crypt_refcountdec()
	If __crypt_refcount() = 0 Then
		DllCall(__crypt_dllhandle(), "bool", "CryptReleaseContext", "handle", __crypt_context(), "dword", 0)
		DllClose(__crypt_dllhandle())
	EndIf
EndFunc

Func _crypt_derivekey($vpassword, $ialg_id, $ihash_alg_id = $calg_md5)
	Local $aret = 0, $hbuff = 0, $hcrypthash = 0, $ierror = 0, $iextended = 0, $vreturn = 0
	_crypt_startup()
	Do
		$aret = DllCall(__crypt_dllhandle(), "bool", "CryptCreateHash", "handle", __crypt_context(), "uint", $ihash_alg_id, "ptr", 0, "dword", 0, "handle*", 0)
		If @error OR NOT $aret[0] Then
			$ierror = @error + 10
			$iextended = @extended
			$vreturn = -1
			ExitLoop
		EndIf
		$hcrypthash = $aret[5]
		$hbuff = DllStructCreate("byte[" & BinaryLen($vpassword) & "]")
		DllStructSetData($hbuff, 1, $vpassword)
		$aret = DllCall(__crypt_dllhandle(), "bool", "CryptHashData", "handle", $hcrypthash, "struct*", $hbuff, "dword", DllStructGetSize($hbuff), "dword", $crypt_userdata)
		If @error OR NOT $aret[0] Then
			$ierror = @error + 20
			$iextended = @extended
			$vreturn = -1
			ExitLoop
		EndIf
		$aret = DllCall(__crypt_dllhandle(), "bool", "CryptDeriveKey", "handle", __crypt_context(), "uint", $ialg_id, "handle", $hcrypthash, "dword", $crypt_exportable, "handle*", 0)
		If @error OR NOT $aret[0] Then
			$ierror = @error + 30
			$iextended = @extended
			$vreturn = -1
			ExitLoop
		EndIf
		$vreturn = $aret[5]
	Until True
	If $hcrypthash <> 0 Then DllCall(__crypt_dllhandle(), "bool", "CryptDestroyHash", "handle", $hcrypthash)
	Return SetError($ierror, $iextended, $vreturn)
EndFunc

Func _crypt_destroykey($hcryptkey)
	Local $aret = DllCall(__crypt_dllhandle(), "bool", "CryptDestroyKey", "handle", $hcryptkey)
	Local $ierror = @error, $iextended = @extended
	_crypt_shutdown()
	If $ierror OR NOT $aret[0] Then
		Return SetError($ierror + 10, $iextended, False)
	Else
		Return True
	EndIf
EndFunc

Func _crypt_encryptdata($vdata, $vcryptkey, $ialg_id, $bfinal = True)
	Local $ireqbuffsize = 0, $aret = 0, $hbuff = 0, $ierror = 0, $iextended = 0, $vreturn = 0
	_crypt_startup()
	Do
		If $ialg_id <> $calg_userkey Then
			$vcryptkey = _crypt_derivekey($vcryptkey, $ialg_id)
			If @error Then
				$ierror = @error + 100
				$iextended = @extended
				$vreturn = -1
				ExitLoop
			EndIf
		EndIf
		$aret = DllCall(__crypt_dllhandle(), "bool", "CryptEncrypt", "handle", $vcryptkey, "handle", 0, "bool", $bfinal, "dword", 0, "ptr", 0, "dword*", BinaryLen($vdata), "dword", 0)
		If @error OR NOT $aret[0] Then
			$ierror = @error + 20
			$iextended = @extended
			$vreturn = -1
			ExitLoop
		EndIf
		$ireqbuffsize = $aret[6]
		$hbuff = DllStructCreate("byte[" & $ireqbuffsize & "]")
		DllStructSetData($hbuff, 1, $vdata)
		$aret = DllCall(__crypt_dllhandle(), "bool", "CryptEncrypt", "handle", $vcryptkey, "handle", 0, "bool", $bfinal, "dword", 0, "struct*", $hbuff, "dword*", BinaryLen($vdata), "dword", DllStructGetSize($hbuff))
		If @error OR NOT $aret[0] Then
			$ierror = @error + 30
			$iextended = @extended
			$vreturn = -1
			ExitLoop
		EndIf
		$vreturn = DllStructGetData($hbuff, 1)
	Until True
	If $ialg_id <> $calg_userkey Then _crypt_destroykey($vcryptkey)
	_crypt_shutdown()
	Return SetError($ierror, $iextended, $vreturn)
EndFunc

Func _crypt_decryptdata($vdata, $vcryptkey, $ialg_id, $bfinal = True)
	Local $aret = 0, $hbuff = 0, $htempstruct = 0, $ierror = 0, $iextended = 0, $iplaintextsize = 0, $vreturn = 0
	_crypt_startup()
	Do
		If $ialg_id <> $calg_userkey Then
			$vcryptkey = _crypt_derivekey($vcryptkey, $ialg_id)
			If @error Then
				$ierror = @error + 100
				$iextended = @extended
				$vreturn = -1
				ExitLoop
			EndIf
		EndIf
		$hbuff = DllStructCreate("byte[" & BinaryLen($vdata) + 1000 & "]")
		DllStructSetData($hbuff, 1, $vdata)
		$aret = DllCall(__crypt_dllhandle(), "bool", "CryptDecrypt", "handle", $vcryptkey, "handle", 0, "bool", $bfinal, "dword", 0, "struct*", $hbuff, "dword*", BinaryLen($vdata))
		If @error OR NOT $aret[0] Then
			$ierror = @error + 20
			$iextended = @extended
			$vreturn = -1
			ExitLoop
		EndIf
		$iplaintextsize = $aret[6]
		$htempstruct = DllStructCreate("byte[" & $iplaintextsize & "]", DllStructGetPtr($hbuff))
		$vreturn = DllStructGetData($htempstruct, 1)
	Until True
	If $ialg_id <> $calg_userkey Then _crypt_destroykey($vcryptkey)
	_crypt_shutdown()
	Return SetError($ierror, $iextended, $vreturn)
EndFunc

Func _crypt_hashdata($vdata, $ialg_id, $bfinal = True, $hcrypthash = 0)
	Local $aret = 0, $hbuff = 0, $ierror = 0, $iextended = 0, $ihashsize = 0, $vreturn = 0
	_crypt_startup()
	Do
		If $hcrypthash = 0 Then
			$aret = DllCall(__crypt_dllhandle(), "bool", "CryptCreateHash", "handle", __crypt_context(), "uint", $ialg_id, "ptr", 0, "dword", 0, "handle*", 0)
			If @error OR NOT $aret[0] Then
				$ierror = @error + 10
				$iextended = @extended
				$vreturn = -1
				ExitLoop
			EndIf
			$hcrypthash = $aret[5]
		EndIf
		$hbuff = DllStructCreate("byte[" & BinaryLen($vdata) & "]")
		DllStructSetData($hbuff, 1, $vdata)
		$aret = DllCall(__crypt_dllhandle(), "bool", "CryptHashData", "handle", $hcrypthash, "struct*", $hbuff, "dword", DllStructGetSize($hbuff), "dword", $crypt_userdata)
		If @error OR NOT $aret[0] Then
			$ierror = @error + 20
			$iextended = @extended
			$vreturn = -1
			ExitLoop
		EndIf
		If $bfinal Then
			$aret = DllCall(__crypt_dllhandle(), "bool", "CryptGetHashParam", "handle", $hcrypthash, "dword", $hp_hashsize, "dword*", 0, "dword*", 4, "dword", 0)
			If @error OR NOT $aret[0] Then
				$ierror = @error + 30
				$iextended = @extended
				$vreturn = -1
				ExitLoop
			EndIf
			$ihashsize = $aret[3]
			$hbuff = DllStructCreate("byte[" & $ihashsize & "]")
			$aret = DllCall(__crypt_dllhandle(), "bool", "CryptGetHashParam", "handle", $hcrypthash, "dword", $hp_hashval, "struct*", $hbuff, "dword*", DllStructGetSize($hbuff), "dword", 0)
			If @error OR NOT $aret[0] Then
				$ierror = @error + 40
				$iextended = @extended
				$vreturn = -1
				ExitLoop
			EndIf
			$vreturn = DllStructGetData($hbuff, 1)
		Else
			$vreturn = $hcrypthash
		EndIf
	Until True
	If $hcrypthash <> 0 AND $bfinal Then DllCall(__crypt_dllhandle(), "bool", "CryptDestroyHash", "handle", $hcrypthash)
	_crypt_shutdown()
	Return SetError($ierror, $iextended, $vreturn)
EndFunc

Func _crypt_hashfile($sfile, $ialg_id)
	Local $btempdata = 0, $hfile = 0, $hhashobject = 0, $ierror = 0, $iextended = 0, $vreturn = 0
	_crypt_startup()
	Do
		$hfile = FileOpen($sfile, $fo_binary)
		If $hfile = -1 Then
			$ierror = 1
			$vreturn = -1
			ExitLoop
		EndIf
		Do
			$btempdata = FileRead($hfile, 512 * 1024)
			If @error Then
				$vreturn = _crypt_hashdata($btempdata, $ialg_id, True, $hhashobject)
				If @error Then
					$ierror = @error
					$iextended = @extended
					$vreturn = -1
					ExitLoop 2
				EndIf
				ExitLoop 2
			Else
				$hhashobject = _crypt_hashdata($btempdata, $ialg_id, False, $hhashobject)
				If @error Then
					$ierror = @error + 100
					$iextended = @extended
					$vreturn = -1
					ExitLoop 2
				EndIf
			EndIf
		Until False
	Until True
	_crypt_shutdown()
	If $hfile <> -1 Then FileClose($hfile)
	Return SetError($ierror, $iextended, $vreturn)
EndFunc

Func _crypt_encryptfile($ssourcefile, $sdestinationfile, $vcryptkey, $ialg_id)
	Local $btempdata = 0, $hinfile = 0, $houtfile = 0, $ierror = 0, $iextended = 0, $ifilesize = FileGetSize($ssourcefile), $iread = 0, $breturn = True
	_crypt_startup()
	Do
		If $ialg_id <> $calg_userkey Then
			$vcryptkey = _crypt_derivekey($vcryptkey, $ialg_id)
			If @error Then
				$ierror = @error
				$iextended = @extended
				$breturn = False
				ExitLoop
			EndIf
		EndIf
		$hinfile = FileOpen($ssourcefile, $fo_binary)
		If @error Then
			$ierror = 2
			$breturn = False
			ExitLoop
		EndIf
		$houtfile = FileOpen($sdestinationfile, $fo_overwrite + $fo_createpath + $fo_binary)
		If @error Then
			$ierror = 3
			$breturn = False
			ExitLoop
		EndIf
		Do
			$btempdata = FileRead($hinfile, 1024 * 1024)
			$iread += BinaryLen($btempdata)
			If $iread = $ifilesize Then
				$btempdata = _crypt_encryptdata($btempdata, $vcryptkey, $calg_userkey, True)
				If @error Then
					$ierror = @error + 400
					$iextended = @extended
					$breturn = False
				EndIf
				FileWrite($houtfile, $btempdata)
				ExitLoop 2
			Else
				$btempdata = _crypt_encryptdata($btempdata, $vcryptkey, $calg_userkey, False)
				If @error Then
					$ierror = @error + 500
					$iextended = @extended
					$breturn = False
					ExitLoop 2
				EndIf
				FileWrite($houtfile, $btempdata)
			EndIf
		Until False
	Until True
	If $ialg_id <> $calg_userkey Then _crypt_destroykey($vcryptkey)
	_crypt_shutdown()
	If $hinfile <> -1 Then FileClose($hinfile)
	If $houtfile <> -1 Then FileClose($houtfile)
	Return SetError($ierror, $iextended, $breturn)
EndFunc

Func _crypt_decryptfile($ssourcefile, $sdestinationfile, $vcryptkey, $ialg_id)
	Local $btempdata = 0, $hinfile = 0, $houtfile = 0, $ierror = 0, $iextended = 0, $ifilesize = FileGetSize($ssourcefile), $iread = 0, $breturn = True
	_crypt_startup()
	Do
		If $ialg_id <> $calg_userkey Then
			$vcryptkey = _crypt_derivekey($vcryptkey, $ialg_id)
			If @error Then
				$ierror = @error
				$iextended = @extended
				$breturn = False
				ExitLoop
			EndIf
		EndIf
		$hinfile = FileOpen($ssourcefile, $fo_binary)
		If @error Then
			$ierror = 2
			$breturn = False
			ExitLoop
		EndIf
		$houtfile = FileOpen($sdestinationfile, $fo_overwrite + $fo_createpath + $fo_binary)
		If @error Then
			$ierror = 3
			$breturn = False
			ExitLoop
		EndIf
		Do
			$btempdata = FileRead($hinfile, 1024 * 1024)
			$iread += BinaryLen($btempdata)
			If $iread = $ifilesize Then
				$btempdata = _crypt_decryptdata($btempdata, $vcryptkey, $calg_userkey, True)
				If @error Then
					$ierror = @error + 400
					$iextended = @extended
					$breturn = False
				EndIf
				FileWrite($houtfile, $btempdata)
				ExitLoop 2
			Else
				$btempdata = _crypt_decryptdata($btempdata, $vcryptkey, $calg_userkey, False)
				If @error Then
					$ierror = @error + 500
					$iextended = @extended
					$breturn = False
					ExitLoop 2
				EndIf
				FileWrite($houtfile, $btempdata)
			EndIf
		Until False
	Until True
	If $ialg_id <> $calg_userkey Then _crypt_destroykey($vcryptkey)
	_crypt_shutdown()
	If $hinfile <> -1 Then FileClose($hinfile)
	If $houtfile <> -1 Then FileClose($houtfile)
	Return SetError($ierror, $iextended, $breturn)
EndFunc

Func _crypt_genrandom($pbuffer, $isize)
	_crypt_startup()
	Local $aret = DllCall(__crypt_dllhandle(), "bool", "CryptGenRandom", "handle", __crypt_context(), "dword", $isize, "struct*", $pbuffer)
	Local $ierror = @error + 10, $iextended = @extended
	_crypt_shutdown()
	If $ierror OR (NOT $aret[0]) Then
		Return SetError($ierror, $iextended, False)
	Else
		Return True
	EndIf
EndFunc

Func __crypt_refcount()
	Return $__g_acryptinternaldata[0]
EndFunc

Func __crypt_refcountinc()
	$__g_acryptinternaldata[0] += 1
EndFunc

Func __crypt_refcountdec()
	If $__g_acryptinternaldata[0] > 0 Then $__g_acryptinternaldata[0] -= 1
EndFunc

Func __crypt_dllhandle()
	Return $__g_acryptinternaldata[1]
EndFunc

Func __crypt_dllhandleset($hadvapi32)
	$__g_acryptinternaldata[1] = $hadvapi32
EndFunc

Func __crypt_context()
	Return $__g_acryptinternaldata[2]
EndFunc

Func __crypt_contextset($hcryptcontext)
	$__g_acryptinternaldata[2] = $hcryptcontext
EndFunc

Global Const $str_nocasesense = 0
Global Const $str_casesense = 1
Global Const $str_nocasesensebasic = 2
Global Const $str_stripleading = 1
Global Const $str_striptrailing = 2
Global Const $str_stripspaces = 4
Global Const $str_stripall = 8
Global Const $str_chrsplit = 0
Global Const $str_entiresplit = 1
Global Const $str_nocount = 2
Global Const $str_regexpmatch = 0
Global Const $str_regexparraymatch = 1
Global Const $str_regexparrayfullmatch = 2
Global Const $str_regexparrayglobalmatch = 3
Global Const $str_regexparrayglobalfullmatch = 4
Global Const $str_endisstart = 0
Global Const $str_endnotstart = 1




Func _stringrepeat($sstring, $irepeatcount)
	$irepeatcount = Int($irepeatcount)
	If StringLen($sstring) < 1 OR $irepeatcount < 0 Then Return SetError(1, 0, "")
	Local $sresult = ""
	While $irepeatcount > 1
		If BitAND($irepeatcount, 1) Then $sresult &= $sstring
		$sstring &= $sstring
		$irepeatcount = BitShift($irepeatcount, 1)
	WEnd
	Return $sstring & $sresult
EndFunc


Global Const $opt_coordsrelative = 0
Global Const $opt_coordsabsolute = 1
Global Const $opt_coordsclient = 2
Global Const $opt_errorsilent = 0
Global Const $opt_errorfatal = 1
Global Const $opt_capsnostore = 0
Global Const $opt_capsstore = 1
Global Const $opt_matchstart = 1
Global Const $opt_matchany = 2
Global Const $opt_matchexact = 3
Global Const $opt_matchadvanced = 4
Global Const $ccs_top = 1
Global Const $ccs_nomovey = 2
Global Const $ccs_bottom = 3
Global Const $ccs_noresize = 4
Global Const $ccs_noparentalign = 8
Global Const $ccs_nohilite = 16
Global Const $ccs_adjustable = 32
Global Const $ccs_nodivider = 64
Global Const $ccs_vert = 128
Global Const $ccs_left = 129
Global Const $ccs_nomovex = 130
Global Const $ccs_right = 131
Global Const $dt_drivetype = 1
Global Const $dt_ssdstatus = 2
Global Const $dt_bustype = 3
Global Const $objid_window = 0
Global Const $objid_titlebar = -2
Global Const $objid_sizegrip = -7
Global Const $objid_caret = -8
Global Const $objid_cursor = -9
Global Const $objid_alert = -10
Global Const $objid_sound = -11
Global Const $dlg_notitle = 1
Global Const $dlg_notontop = 2
Global Const $dlg_textleft = 4
Global Const $dlg_textright = 8
Global Const $dlg_moveable = 16
Global Const $dlg_textvcenter = 32
Global Const $idc_unknown = 0
Global Const $idc_appstarting = 1
Global Const $idc_arrow = 2
Global Const $idc_cross = 3
Global Const $idc_hand = 32649
Global Const $idc_help = 4
Global Const $idc_ibeam = 5
Global Const $idc_icon = 6
Global Const $idc_no = 7
Global Const $idc_size = 8
Global Const $idc_sizeall = 9
Global Const $idc_sizenesw = 10
Global Const $idc_sizens = 11
Global Const $idc_sizenwse = 12
Global Const $idc_sizewe = 13
Global Const $idc_uparrow = 14
Global Const $idc_wait = 15
Global Const $idi_application = 32512
Global Const $idi_asterisk = 32516
Global Const $idi_exclamation = 32515
Global Const $idi_hand = 32513
Global Const $idi_question = 32514
Global Const $idi_winlogo = 32517
Global Const $idi_shield = 32518
Global Const $idi_error = $idi_hand
Global Const $idi_information = $idi_asterisk
Global Const $idi_warning = $idi_exclamation
Global Const $sd_logoff = 0
Global Const $sd_shutdown = 1
Global Const $sd_reboot = 2
Global Const $sd_force = 4
Global Const $sd_powerdown = 8
Global Const $sd_forcehung = 16
Global Const $sd_standby = 32
Global Const $sd_hibernate = 64
Global Const $stdin_child = 1
Global Const $stdout_child = 2
Global Const $stderr_child = 4
Global Const $stderr_merged = 8
Global Const $stdio_inherit_parent = 16
Global Const $run_create_new_console = 65536
Global Const $ubound_dimensions = 0
Global Const $ubound_rows = 1
Global Const $ubound_columns = 2
Global Const $mouseeventf_absolute = 32768
Global Const $mouseeventf_move = 1
Global Const $mouseeventf_leftdown = 2
Global Const $mouseeventf_leftup = 4
Global Const $mouseeventf_rightdown = 8
Global Const $mouseeventf_rightup = 16
Global Const $mouseeventf_middledown = 32
Global Const $mouseeventf_middleup = 64
Global Const $mouseeventf_wheel = 2048
Global Const $mouseeventf_xdown = 128
Global Const $mouseeventf_xup = 256
Global Const $reg_none = 0
Global Const $reg_sz = 1
Global Const $reg_expand_sz = 2
Global Const $reg_binary = 3
Global Const $reg_dword = 4
Global Const $reg_dword_little_endian = 4
Global Const $reg_dword_big_endian = 5
Global Const $reg_link = 6
Global Const $reg_multi_sz = 7
Global Const $reg_resource_list = 8
Global Const $reg_full_resource_descriptor = 9
Global Const $reg_resource_requirements_list = 10
Global Const $reg_qword = 11
Global Const $reg_qword_little_endian = 11
Global Const $hwnd_bottom = 1
Global Const $hwnd_notopmost = -2
Global Const $hwnd_top = 0
Global Const $hwnd_topmost = -1
Global Const $swp_nosize = 1
Global Const $swp_nomove = 2
Global Const $swp_nozorder = 4
Global Const $swp_noredraw = 8
Global Const $swp_noactivate = 16
Global Const $swp_framechanged = 32
Global Const $swp_drawframe = 32
Global Const $swp_showwindow = 64
Global Const $swp_hidewindow = 128
Global Const $swp_nocopybits = 256
Global Const $swp_noownerzorder = 512
Global Const $swp_noreposition = 512
Global Const $swp_nosendchanging = 1024
Global Const $swp_defererase = 8192
Global Const $swp_asyncwindowpos = 16384
Global Const $keyword_default = 1
Global Const $keyword_null = 2
Global Const $mb_ok = 0
Global Const $mb_okcancel = 1
Global Const $mb_abortretryignore = 2
Global Const $mb_yesnocancel = 3
Global Const $mb_yesno = 4
Global Const $mb_retrycancel = 5
Global Const $mb_canceltrycontinue = 6
Global Const $mb_help = 16384
Global Const $mb_iconstop = 16
Global Const $mb_iconerror = 16
Global Const $mb_iconhand = 16
Global Const $mb_iconquestion = 32
Global Const $mb_iconexclamation = 48
Global Const $mb_iconwarning = 48
Global Const $mb_iconinformation = 64
Global Const $mb_iconasterisk = 64
Global Const $mb_usericon = 128
Global Const $mb_defbutton1 = 0
Global Const $mb_defbutton2 = 256
Global Const $mb_defbutton3 = 512
Global Const $mb_defbutton4 = 768
Global Const $mb_applmodal = 0
Global Const $mb_systemmodal = 4096
Global Const $mb_taskmodal = 8192
Global Const $mb_default_desktop_only = 131072
Global Const $mb_right = 524288
Global Const $mb_rtlreading = 1048576
Global Const $mb_setforeground = 65536
Global Const $mb_topmost = 262144
Global Const $mb_service_notification = 2097152
Global Const $mb_rightjustified = $mb_right
Global Const $idtimeout = -1
Global Const $idok = 1
Global Const $idcancel = 2
Global Const $idabort = 3
Global Const $idretry = 4
Global Const $idignore = 5
Global Const $idyes = 6
Global Const $idno = 7
Global Const $idclose = 8
Global Const $idhelp = 9
Global Const $idtryagain = 10
Global Const $idcontinue = 11

Func _arrayadd(ByRef $avarray, $vvalue, $istart = 0, $sdelim_item = "|", $sdelim_row = @CRLF, $hdatatype = 0)
	If $istart = Default Then $istart = 0
	If $sdelim_item = Default Then $sdelim_item = "|"
	If $sdelim_row = Default Then $sdelim_row = @CRLF
	If $hdatatype = Default Then $hdatatype = 0
	If NOT IsArray($avarray) Then Return SetError(1, 0, -1)
	Local $idim_1 = UBound($avarray, $ubound_rows)
	Switch UBound($avarray, $ubound_dimensions)
		Case 1
			If IsArray($vvalue) Then
				If UBound($vvalue, $ubound_dimensions) <> 1 Then Return SetError(5, 0, -1)
				$hdatatype = 0
			Else
				Local $atmp = StringSplit($vvalue, $sdelim_item, $str_nocount + $str_entiresplit)
				If UBound($atmp, $ubound_rows) = 1 Then
					$atmp[0] = $vvalue
					$hdatatype = 0
				EndIf
				$vvalue = $atmp
			EndIf
			Local $iadd = UBound($vvalue, $ubound_rows)
			ReDim $avarray[$idim_1 + $iadd]
			For $i = 0 To $iadd - 1
				If IsFunc($hdatatype) Then
					$avarray[$idim_1 + $i] = $hdatatype($vvalue[$i])
				Else
					$avarray[$idim_1 + $i] = $vvalue[$i]
				EndIf
			Next
			Return $idim_1 + $iadd - 1
		Case 2
			Local $idim_2 = UBound($avarray, $ubound_columns)
			If $istart < 0 OR $istart > $idim_2 - 1 Then Return SetError(4, 0, -1)
			Local $ivaldim_1, $ivaldim_2
			If IsArray($vvalue) Then
				If UBound($vvalue, $ubound_dimensions) <> 2 Then Return SetError(5, 0, -1)
				$ivaldim_1 = UBound($vvalue, $ubound_rows)
				$ivaldim_2 = UBound($vvalue, $ubound_columns)
				$hdatatype = 0
			Else
				Local $asplit_1 = StringSplit($vvalue, $sdelim_row, $str_nocount + $str_entiresplit)
				$ivaldim_1 = UBound($asplit_1, $ubound_rows)
				StringReplace($asplit_1[0], $sdelim_item, "")
				$ivaldim_2 = @extended + 1
				Local $atmp[$ivaldim_1][$ivaldim_2], $asplit_2
				For $i = 0 To $ivaldim_1 - 1
					$asplit_2 = StringSplit($asplit_1[$i], $sdelim_item, $str_nocount + $str_entiresplit)
					For $j = 0 To $ivaldim_2 - 1
						$atmp[$i][$j] = $asplit_2[$j]
					Next
				Next
				$vvalue = $atmp
			EndIf
			If UBound($vvalue, $ubound_columns) + $istart > UBound($avarray, $ubound_columns) Then Return SetError(3, 0, -1)
			ReDim $avarray[$idim_1 + $ivaldim_1][$idim_2]
			For $iwriteto_index = 0 To $ivaldim_1 - 1
				For $j = 0 To $idim_2 - 1
					If $j < $istart Then
						$avarray[$iwriteto_index + $idim_1][$j] = ""
					ElseIf $j - $istart > $ivaldim_2 - 1 Then
						$avarray[$iwriteto_index + $idim_1][$j] = ""
					Else
						If IsFunc($hdatatype) Then
							$avarray[$iwriteto_index + $idim_1][$j] = $hdatatype($vvalue[$iwriteto_index][$j - $istart])
						Else
							$avarray[$iwriteto_index + $idim_1][$j] = $vvalue[$iwriteto_index][$j - $istart]
						EndIf
					EndIf
				Next
			Next
		Case Else
			Return SetError(2, 0, -1)
	EndSwitch
	Return UBound($avarray, $ubound_rows) - 1
EndFunc

Func _arrayconcatenate(ByRef $avarray_tgt, Const ByRef $avarray_src, $istart = 0)
	If $istart = Default Then $istart = 0
	If NOT IsArray($avarray_tgt) Then Return SetError(1, 0, -1)
	If NOT IsArray($avarray_src) Then Return SetError(2, 0, -1)
	Local $idim_total_tgt = UBound($avarray_tgt, $ubound_dimensions)
	Local $idim_total_src = UBound($avarray_src, $ubound_dimensions)
	Local $idim_1_tgt = UBound($avarray_tgt, $ubound_rows)
	Local $idim_1_src = UBound($avarray_src, $ubound_rows)
	If $istart < 0 OR $istart > $idim_1_src - 1 Then Return SetError(6, 0, -1)
	Switch $idim_total_tgt
		Case 1
			If $idim_total_src <> 1 Then Return SetError(4, 0, -1)
			ReDim $avarray_tgt[$idim_1_tgt + $idim_1_src - $istart]
			For $i = $istart To $idim_1_src - 1
				$avarray_tgt[$idim_1_tgt + $i - $istart] = $avarray_src[$i]
			Next
		Case 2
			If $idim_total_src <> 2 Then Return SetError(4, 0, -1)
			Local $idim_2_tgt = UBound($avarray_tgt, $ubound_columns)
			If UBound($avarray_src, $ubound_columns) <> $idim_2_tgt Then Return SetError(5, 0, -1)
			ReDim $avarray_tgt[$idim_1_tgt + $idim_1_src - $istart][$idim_2_tgt]
			For $i = $istart To $idim_1_src - 1
				For $j = 0 To $idim_2_tgt - 1
					$avarray_tgt[$idim_1_tgt + $i - $istart][$j] = $avarray_src[$i][$j]
				Next
			Next
		Case Else
			Return SetError(3, 0, -1)
	EndSwitch
	Return UBound($avarray_tgt, $ubound_rows)
EndFunc

Func _arrayinsert(ByRef $avarray, $vrange, $vvalue = "", $istart = 0, $sdelim_item = "|", $sdelim_row = @CRLF, $hdatatype = 0)
	If $vvalue = Default Then $vvalue = ""
	If $istart = Default Then $istart = 0
	If $sdelim_item = Default Then $sdelim_item = "|"
	If $sdelim_row = Default Then $sdelim_row = @CRLF
	If $hdatatype = Default Then $hdatatype = 0
	If NOT IsArray($avarray) Then Return SetError(1, 0, -1)
	Local $idim_1 = UBound($avarray, $ubound_rows) - 1
	Local $asplit_1, $asplit_2
	If IsArray($vrange) Then
		If UBound($vrange, $ubound_dimensions) <> 1 OR UBound($vrange, $ubound_rows) < 2 Then Return SetError(4, 0, -1)
	Else
		Local $inumber
		$vrange = StringStripWS($vrange, 8)
		$asplit_1 = StringSplit($vrange, ";")
		$vrange = ""
		For $i = 1 To $asplit_1[0]
			If NOT StringRegExp($asplit_1[$i], "^\d+(-\d+)?$") Then Return SetError(3, 0, -1)
			$asplit_2 = StringSplit($asplit_1[$i], "-")
			Switch $asplit_2[0]
				Case 1
					$vrange &= $asplit_2[1] & ";"
				Case 2
					If Number($asplit_2[2]) >= Number($asplit_2[1]) Then
						$inumber = $asplit_2[1] - 1
						Do
							$inumber += 1
							$vrange &= $inumber & ";"
						Until $inumber = $asplit_2[2]
					EndIf
			EndSwitch
		Next
		$vrange = StringSplit(StringTrimRight($vrange, 1), ";")
	EndIf
	If $vrange[1] < 0 OR $vrange[$vrange[0]] > $idim_1 Then Return SetError(5, 0, -1)
	For $i = 2 To $vrange[0]
		If $vrange[$i] < $vrange[$i - 1] Then Return SetError(3, 0, -1)
	Next
	Local $icopyto_index = $idim_1 + $vrange[0]
	Local $iinsertpoint_index = $vrange[0]
	Local $iinsert_index = $vrange[$iinsertpoint_index]
	Switch UBound($avarray, $ubound_dimensions)
		Case 1
			ReDim $avarray[$idim_1 + $vrange[0] + 1]
			If IsArray($vvalue) Then
				If UBound($vvalue, $ubound_dimensions) <> 1 Then Return SetError(5, 0, -1)
				$hdatatype = 0
			Else
				Local $atmp = StringSplit($vvalue, $sdelim_item, $str_nocount + $str_entiresplit)
				If UBound($atmp, $ubound_rows) = 1 Then
					$atmp[0] = $vvalue
					$hdatatype = 0
				EndIf
				$vvalue = $atmp
			EndIf
			For $ireadfromindex = $idim_1 To 0 Step -1
				$avarray[$icopyto_index] = $avarray[$ireadfromindex]
				$icopyto_index -= 1
				$iinsert_index = $vrange[$iinsertpoint_index]
				While $ireadfromindex = $iinsert_index
					If $iinsertpoint_index <= UBound($vvalue, $ubound_rows) Then
						If IsFunc($hdatatype) Then
							$avarray[$icopyto_index] = $hdatatype($vvalue[$iinsertpoint_index - 1])
						Else
							$avarray[$icopyto_index] = $vvalue[$iinsertpoint_index - 1]
						EndIf
					Else
						$avarray[$icopyto_index] = ""
					EndIf
					$icopyto_index -= 1
					$iinsertpoint_index -= 1
					If $iinsertpoint_index = 0 Then ExitLoop 2
					$iinsert_index = $vrange[$iinsertpoint_index]
				WEnd
			Next
		Case 2
			Local $idim_2 = UBound($avarray, $ubound_columns)
			If $istart < 0 OR $istart > $idim_2 - 1 Then Return SetError(6, 0, -1)
			Local $ivaldim_1, $ivaldim_2
			If IsArray($vvalue) Then
				If UBound($vvalue, $ubound_dimensions) <> 2 Then Return SetError(7, 0, -1)
				$ivaldim_1 = UBound($vvalue, $ubound_rows)
				$ivaldim_2 = UBound($vvalue, $ubound_columns)
				$hdatatype = 0
			Else
				$asplit_1 = StringSplit($vvalue, $sdelim_row, $str_nocount + $str_entiresplit)
				$ivaldim_1 = UBound($asplit_1, $ubound_rows)
				StringReplace($asplit_1[0], $sdelim_item, "")
				$ivaldim_2 = @extended + 1
				Local $atmp[$ivaldim_1][$ivaldim_2]
				For $i = 0 To $ivaldim_1 - 1
					$asplit_2 = StringSplit($asplit_1[$i], $sdelim_item, $str_nocount + $str_entiresplit)
					For $j = 0 To $ivaldim_2 - 1
						$atmp[$i][$j] = $asplit_2[$j]
					Next
				Next
				$vvalue = $atmp
			EndIf
			If UBound($vvalue, $ubound_columns) + $istart > UBound($avarray, $ubound_columns) Then Return SetError(8, 0, -1)
			ReDim $avarray[$idim_1 + $vrange[0] + 1][$idim_2]
			For $ireadfromindex = $idim_1 To 0 Step -1
				For $j = 0 To $idim_2 - 1
					$avarray[$icopyto_index][$j] = $avarray[$ireadfromindex][$j]
				Next
				$icopyto_index -= 1
				$iinsert_index = $vrange[$iinsertpoint_index]
				While $ireadfromindex = $iinsert_index
					For $j = 0 To $idim_2 - 1
						If $j < $istart Then
							$avarray[$icopyto_index][$j] = ""
						ElseIf $j - $istart > $ivaldim_2 - 1 Then
							$avarray[$icopyto_index][$j] = ""
						Else
							If $iinsertpoint_index - 1 < $ivaldim_1 Then
								If IsFunc($hdatatype) Then
									$avarray[$icopyto_index][$j] = $hdatatype($vvalue[$iinsertpoint_index - 1][$j - $istart])
								Else
									$avarray[$icopyto_index][$j] = $vvalue[$iinsertpoint_index - 1][$j - $istart]
								EndIf
							Else
								$avarray[$icopyto_index][$j] = ""
							EndIf
						EndIf
					Next
					$icopyto_index -= 1
					$iinsertpoint_index -= 1
					If $iinsertpoint_index = 0 Then ExitLoop 2
					$iinsert_index = $vrange[$iinsertpoint_index]
				WEnd
			Next
		Case Else
			Return SetError(2, 0, -1)
	EndSwitch
	Return UBound($avarray, $ubound_rows)
EndFunc


Func _arrayreverse(ByRef $avarray, $istart = 0, $iend = 0)
	If $istart = Default Then $istart = 0
	If $iend = Default Then $iend = 0
	If NOT IsArray($avarray) Then Return SetError(1, 0, 0)
	If UBound($avarray, $ubound_dimensions) <> 1 Then Return SetError(3, 0, 0)
	If NOT UBound($avarray) Then Return SetError(4, 0, 0)
	Local $vtmp, $iubound = UBound($avarray) - 1
	If $iend < 1 OR $iend > $iubound Then $iend = $iubound
	If $istart < 0 Then $istart = 0
	If $istart > $iend Then Return SetError(2, 0, 0)
	For $i = $istart To Int(($istart + $iend - 1) / 2)
		$vtmp = $avarray[$i]
		$avarray[$i] = $avarray[$iend]
		$avarray[$iend] = $vtmp
		$iend -= 1
	Next
	Return 1
EndFunc

Func __arrayquicksort1d(ByRef $avarray, Const ByRef $istart, Const ByRef $iend)
	If $iend <= $istart Then Return
	Local $vtmp
	If ($iend - $istart) < 15 Then
		Local $vcur
		For $i = $istart + 1 To $iend
			$vtmp = $avarray[$i]
			If IsNumber($vtmp) Then
				For $j = $i - 1 To $istart Step -1
					$vcur = $avarray[$j]
					If ($vtmp >= $vcur AND IsNumber($vcur)) OR (NOT IsNumber($vcur) AND StringCompare($vtmp, $vcur) >= 0) Then ExitLoop
					$avarray[$j + 1] = $vcur
				Next
			Else
				For $j = $i - 1 To $istart Step -1
					If (StringCompare($vtmp, $avarray[$j]) >= 0) Then ExitLoop
					$avarray[$j + 1] = $avarray[$j]
				Next
			EndIf
			$avarray[$j + 1] = $vtmp
		Next
		Return
	EndIf
	Local $l = $istart, $r = $iend, $vpivot = $avarray[Int(($istart + $iend) / 2)], $bnum = IsNumber($vpivot)
	Do
		If $bnum Then
			While ($avarray[$l] < $vpivot AND IsNumber($avarray[$l])) OR (NOT IsNumber($avarray[$l]) AND StringCompare($avarray[$l], $vpivot) < 0)
				$l += 1
			WEnd
			While ($avarray[$r] > $vpivot AND IsNumber($avarray[$r])) OR (NOT IsNumber($avarray[$r]) AND StringCompare($avarray[$r], $vpivot) > 0)
				$r -= 1
			WEnd
		Else
			While (StringCompare($avarray[$l], $vpivot) < 0)
				$l += 1
			WEnd
			While (StringCompare($avarray[$r], $vpivot) > 0)
				$r -= 1
			WEnd
		EndIf
		If $l <= $r Then
			$vtmp = $avarray[$l]
			$avarray[$l] = $avarray[$r]
			$avarray[$r] = $vtmp
			$l += 1
			$r -= 1
		EndIf
	Until $l > $r
	__arrayquicksort1d($avarray, $istart, $r)
	__arrayquicksort1d($avarray, $l, $iend)
EndFunc

Func __arrayquicksort2d(ByRef $avarray, Const ByRef $istep, Const ByRef $istart, Const ByRef $iend, Const ByRef $isubitem, Const ByRef $isubmax)
	If $iend <= $istart Then Return
	Local $vtmp, $l = $istart, $r = $iend, $vpivot = $avarray[Int(($istart + $iend) / 2)][$isubitem], $bnum = IsNumber($vpivot)
	Do
		If $bnum Then
			While ($istep * ($avarray[$l][$isubitem] - $vpivot) < 0 AND IsNumber($avarray[$l][$isubitem])) OR (NOT IsNumber($avarray[$l][$isubitem]) AND $istep * StringCompare($avarray[$l][$isubitem], $vpivot) < 0)
				$l += 1
			WEnd
			While ($istep * ($avarray[$r][$isubitem] - $vpivot) > 0 AND IsNumber($avarray[$r][$isubitem])) OR (NOT IsNumber($avarray[$r][$isubitem]) AND $istep * StringCompare($avarray[$r][$isubitem], $vpivot) > 0)
				$r -= 1
			WEnd
		Else
			While ($istep * StringCompare($avarray[$l][$isubitem], $vpivot) < 0)
				$l += 1
			WEnd
			While ($istep * StringCompare($avarray[$r][$isubitem], $vpivot) > 0)
				$r -= 1
			WEnd
		EndIf
		If $l <= $r Then
			For $i = 0 To $isubmax
				$vtmp = $avarray[$l][$i]
				$avarray[$l][$i] = $avarray[$r][$i]
				$avarray[$r][$i] = $vtmp
			Next
			$l += 1
			$r -= 1
		EndIf
	Until $l > $r
	__arrayquicksort2d($avarray, $istep, $istart, $r, $isubitem, $isubmax)
	__arrayquicksort2d($avarray, $istep, $l, $iend, $isubitem, $isubmax)
EndFunc

Func __arraydualpivotsort(ByRef $aarray, $ipivot_left, $ipivot_right, $bleftmost = True)
	If $ipivot_left > $ipivot_right Then Return
	Local $ilength = $ipivot_right - $ipivot_left + 1
	Local $i, $j, $k, $iai, $iak, $ia1, $ia2, $ilast
	If $ilength < 45 Then
		If $bleftmost Then
			$i = $ipivot_left
			While $i < $ipivot_right
				$j = $i
				$iai = $aarray[$i + 1]
				While $iai < $aarray[$j]
					$aarray[$j + 1] = $aarray[$j]
					$j -= 1
					If $j + 1 = $ipivot_left Then ExitLoop
				WEnd
				$aarray[$j + 1] = $iai
				$i += 1
			WEnd
		Else
			While 1
				If $ipivot_left >= $ipivot_right Then Return 1
				$ipivot_left += 1
				If $aarray[$ipivot_left] < $aarray[$ipivot_left - 1] Then ExitLoop
			WEnd
			While 1
				$k = $ipivot_left
				$ipivot_left += 1
				If $ipivot_left > $ipivot_right Then ExitLoop
				$ia1 = $aarray[$k]
				$ia2 = $aarray[$ipivot_left]
				If $ia1 < $ia2 Then
					$ia2 = $ia1
					$ia1 = $aarray[$ipivot_left]
				EndIf
				$k -= 1
				While $ia1 < $aarray[$k]
					$aarray[$k + 2] = $aarray[$k]
					$k -= 1
				WEnd
				$aarray[$k + 2] = $ia1
				While $ia2 < $aarray[$k]
					$aarray[$k + 1] = $aarray[$k]
					$k -= 1
				WEnd
				$aarray[$k + 1] = $ia2
				$ipivot_left += 1
			WEnd
			$ilast = $aarray[$ipivot_right]
			$ipivot_right -= 1
			While $ilast < $aarray[$ipivot_right]
				$aarray[$ipivot_right + 1] = $aarray[$ipivot_right]
				$ipivot_right -= 1
			WEnd
			$aarray[$ipivot_right + 1] = $ilast
		EndIf
		Return 1
	EndIf
	Local $iseventh = BitShift($ilength, 3) + BitShift($ilength, 6) + 1
	Local $ie1, $ie2, $ie3, $ie4, $ie5, $t
	$ie3 = Ceiling(($ipivot_left + $ipivot_right) / 2)
	$ie2 = $ie3 - $iseventh
	$ie1 = $ie2 - $iseventh
	$ie4 = $ie3 + $iseventh
	$ie5 = $ie4 + $iseventh
	If $aarray[$ie2] < $aarray[$ie1] Then
		$t = $aarray[$ie2]
		$aarray[$ie2] = $aarray[$ie1]
		$aarray[$ie1] = $t
	EndIf
	If $aarray[$ie3] < $aarray[$ie2] Then
		$t = $aarray[$ie3]
		$aarray[$ie3] = $aarray[$ie2]
		$aarray[$ie2] = $t
		If $t < $aarray[$ie1] Then
			$aarray[$ie2] = $aarray[$ie1]
			$aarray[$ie1] = $t
		EndIf
	EndIf
	If $aarray[$ie4] < $aarray[$ie3] Then
		$t = $aarray[$ie4]
		$aarray[$ie4] = $aarray[$ie3]
		$aarray[$ie3] = $t
		If $t < $aarray[$ie2] Then
			$aarray[$ie3] = $aarray[$ie2]
			$aarray[$ie2] = $t
			If $t < $aarray[$ie1] Then
				$aarray[$ie2] = $aarray[$ie1]
				$aarray[$ie1] = $t
			EndIf
		EndIf
	EndIf
	If $aarray[$ie5] < $aarray[$ie4] Then
		$t = $aarray[$ie5]
		$aarray[$ie5] = $aarray[$ie4]
		$aarray[$ie4] = $t
		If $t < $aarray[$ie3] Then
			$aarray[$ie4] = $aarray[$ie3]
			$aarray[$ie3] = $t
			If $t < $aarray[$ie2] Then
				$aarray[$ie3] = $aarray[$ie2]
				$aarray[$ie2] = $t
				If $t < $aarray[$ie1] Then
					$aarray[$ie2] = $aarray[$ie1]
					$aarray[$ie1] = $t
				EndIf
			EndIf
		EndIf
	EndIf
	Local $iless = $ipivot_left
	Local $igreater = $ipivot_right
	If (($aarray[$ie1] <> $aarray[$ie2]) AND ($aarray[$ie2] <> $aarray[$ie3]) AND ($aarray[$ie3] <> $aarray[$ie4]) AND ($aarray[$ie4] <> $aarray[$ie5])) Then
		Local $ipivot_1 = $aarray[$ie2]
		Local $ipivot_2 = $aarray[$ie4]
		$aarray[$ie2] = $aarray[$ipivot_left]
		$aarray[$ie4] = $aarray[$ipivot_right]
		Do
			$iless += 1
		Until $aarray[$iless] >= $ipivot_1
		Do
			$igreater -= 1
		Until $aarray[$igreater] <= $ipivot_2
		$k = $iless
		While $k <= $igreater
			$iak = $aarray[$k]
			If $iak < $ipivot_1 Then
				$aarray[$k] = $aarray[$iless]
				$aarray[$iless] = $iak
				$iless += 1
			ElseIf $iak > $ipivot_2 Then
				While $aarray[$igreater] > $ipivot_2
					$igreater -= 1
					If $igreater + 1 = $k Then ExitLoop 2
				WEnd
				If $aarray[$igreater] < $ipivot_1 Then
					$aarray[$k] = $aarray[$iless]
					$aarray[$iless] = $aarray[$igreater]
					$iless += 1
				Else
					$aarray[$k] = $aarray[$igreater]
				EndIf
				$aarray[$igreater] = $iak
				$igreater -= 1
			EndIf
			$k += 1
		WEnd
		$aarray[$ipivot_left] = $aarray[$iless - 1]
		$aarray[$iless - 1] = $ipivot_1
		$aarray[$ipivot_right] = $aarray[$igreater + 1]
		$aarray[$igreater + 1] = $ipivot_2
		__arraydualpivotsort($aarray, $ipivot_left, $iless - 2, True)
		__arraydualpivotsort($aarray, $igreater + 2, $ipivot_right, False)
		If ($iless < $ie1) AND ($ie5 < $igreater) Then
			While $aarray[$iless] = $ipivot_1
				$iless += 1
			WEnd
			While $aarray[$igreater] = $ipivot_2
				$igreater -= 1
			WEnd
			$k = $iless
			While $k <= $igreater
				$iak = $aarray[$k]
				If $iak = $ipivot_1 Then
					$aarray[$k] = $aarray[$iless]
					$aarray[$iless] = $iak
					$iless += 1
				ElseIf $iak = $ipivot_2 Then
					While $aarray[$igreater] = $ipivot_2
						$igreater -= 1
						If $igreater + 1 = $k Then ExitLoop 2
					WEnd
					If $aarray[$igreater] = $ipivot_1 Then
						$aarray[$k] = $aarray[$iless]
						$aarray[$iless] = $ipivot_1
						$iless += 1
					Else
						$aarray[$k] = $aarray[$igreater]
					EndIf
					$aarray[$igreater] = $iak
					$igreater -= 1
				EndIf
				$k += 1
			WEnd
		EndIf
		__arraydualpivotsort($aarray, $iless, $igreater, False)
	Else
		Local $ipivot = $aarray[$ie3]
		$k = $iless
		While $k <= $igreater
			If $aarray[$k] = $ipivot Then
				$k += 1
				ContinueLoop
			EndIf
			$iak = $aarray[$k]
			If $iak < $ipivot Then
				$aarray[$k] = $aarray[$iless]
				$aarray[$iless] = $iak
				$iless += 1
			Else
				While $aarray[$igreater] > $ipivot
					$igreater -= 1
				WEnd
				If $aarray[$igreater] < $ipivot Then
					$aarray[$k] = $aarray[$iless]
					$aarray[$iless] = $aarray[$igreater]
					$iless += 1
				Else
					$aarray[$k] = $ipivot
				EndIf
				$aarray[$igreater] = $iak
				$igreater -= 1
			EndIf
			$k += 1
		WEnd
		__arraydualpivotsort($aarray, $ipivot_left, $iless - 1, True)
		__arraydualpivotsort($aarray, $igreater + 1, $ipivot_right, False)
	EndIf
EndFunc



Func _filelisttoarray($sfilepath, $sfilter = "*", $iflag = 0, $breturnpath = False)
	Local $sdelimiter = "|", $sfilelist = "", $sfilename = "", $sfullpath = ""
	$sfilepath = StringRegExpReplace($sfilepath, "[\\/]+$", "") & "\"
	If $iflag = Default Then $iflag = 0
	If $breturnpath Then $sfullpath = $sfilepath
	If $sfilter = Default Then $sfilter = "*"
	If NOT FileExists($sfilepath) Then Return SetError(1, 0, 0)
	If StringRegExp($sfilter, "[\\/:><\|]|(?s)^\s*$") Then Return SetError(2, 0, 0)
	If NOT ($iflag = 0 OR $iflag = 1 OR $iflag = 2) Then Return SetError(3, 0, 0)
	Local $hsearch = FileFindFirstFile($sfilepath & $sfilter)
	If @error Then Return SetError(4, 0, 0)
	While 1
		$sfilename = FileFindNextFile($hsearch)
		If @error Then ExitLoop
		If ($iflag + @extended = 2) Then ContinueLoop
		$sfilelist &= $sdelimiter & $sfullpath & $sfilename
	WEnd
	FileClose($hsearch)
	If $sfilelist = "" Then Return SetError(4, 0, 0)
	Return StringSplit(StringTrimLeft($sfilelist, 1), $sdelimiter)
EndFunc


Func _zip_unzipall($hzipfile, $hdestpath, $flag = 1)
	Local $dllchk = _zip_dllchk()
	If $dllchk <> 0 Then Return SetError($dllchk, 0, 0)
	If NOT _isfullpath($hzipfile) Then Return SetError(4, 0)
	If NOT FileExists($hzipfile) Then Return SetError(2, 0, 0)
	If NOT FileExists($hdestpath) Then DirCreate($hdestpath)
	Local $aarray[1]
	$oapp = ObjCreate("Shell.Application")
	$oapp.namespace($hdestpath).copyhere($oapp.namespace($hzipfile).items, 20)
	For $item In $oapp.namespace($hzipfile).items
		_arrayadd($aarray, $item)
	Next
	While 1
		If $flag = 1 Then _hide()
		If FileExists($hdestpath & "\" & $aarray[UBound($aarray) - 1]) Then
			Return SetError(0, 0, 1)
			ExitLoop
		EndIf
		Sleep(500)
	WEnd
EndFunc


Func _zip_dllchk()
	If NOT FileExists(@SystemDir & "\zipfldr.dll") Then Return 2
	If NOT RegRead("HKEY_CLASSES_ROOT\CLSID\{E88DCCE0-B7B3-11d1-A9F0-00AA0060FA31}", "") Then Return 3
	Return 0
EndFunc


Func _isfullpath($path)
	If StringInStr($path, ":\") Then
		Return True
	Else
		Return False
	EndIf
EndFunc

Func _hide()
	If ControlGetHandle("[CLASS:#32770]", "", "[CLASS:SysAnimate32; INSTANCE:1]") <> "" AND WinGetState("[CLASS:#32770]") <> @SW_HIDE Then
		$hwnd = WinGetHandle("[CLASS:#32770]")
		WinSetState($hwnd, "", @SW_HIDE)
	EndIf
EndFunc

Global Const $se_assignprimarytoken_name = "SeAssignPrimaryTokenPrivilege"
Global Const $se_audit_name = "SeAuditPrivilege"
Global Const $se_backup_name = "SeBackupPrivilege"
Global Const $se_change_notify_name = "SeChangeNotifyPrivilege"
Global Const $se_create_global_name = "SeCreateGlobalPrivilege"
Global Const $se_create_pagefile_name = "SeCreatePagefilePrivilege"
Global Const $se_create_permanent_name = "SeCreatePermanentPrivilege"
Global Const $se_create_symbolic_link_name = "SeCreateSymbolicLinkPrivilege"
Global Const $se_create_token_name = "SeCreateTokenPrivilege"
Global Const $se_debug_name = "SeDebugPrivilege"
Global Const $se_enable_delegation_name = "SeEnableDelegationPrivilege"
Global Const $se_impersonate_name = "SeImpersonatePrivilege"
Global Const $se_inc_base_priority_name = "SeIncreaseBasePriorityPrivilege"
Global Const $se_inc_working_set_name = "SeIncreaseWorkingSetPrivilege"
Global Const $se_increase_quota_name = "SeIncreaseQuotaPrivilege"
Global Const $se_load_driver_name = "SeLoadDriverPrivilege"
Global Const $se_lock_memory_name = "SeLockMemoryPrivilege"
Global Const $se_machine_account_name = "SeMachineAccountPrivilege"
Global Const $se_manage_volume_name = "SeManageVolumePrivilege"
Global Const $se_prof_single_process_name = "SeProfileSingleProcessPrivilege"
Global Const $se_relabel_name = "SeRelabelPrivilege"
Global Const $se_remote_shutdown_name = "SeRemoteShutdownPrivilege"
Global Const $se_restore_name = "SeRestorePrivilege"
Global Const $se_security_name = "SeSecurityPrivilege"
Global Const $se_shutdown_name = "SeShutdownPrivilege"
Global Const $se_sync_agent_name = "SeSyncAgentPrivilege"
Global Const $se_system_environment_name = "SeSystemEnvironmentPrivilege"
Global Const $se_system_profile_name = "SeSystemProfilePrivilege"
Global Const $se_systemtime_name = "SeSystemtimePrivilege"
Global Const $se_take_ownership_name = "SeTakeOwnershipPrivilege"
Global Const $se_tcb_name = "SeTcbPrivilege"
Global Const $se_time_zone_name = "SeTimeZonePrivilege"
Global Const $se_trusted_credman_access_name = "SeTrustedCredManAccessPrivilege"
Global Const $se_unsolicited_input_name = "SeUnsolicitedInputPrivilege"
Global Const $se_undock_name = "SeUndockPrivilege"
Global Const $se_privilege_enabled_by_default = 1
Global Const $se_privilege_enabled = 2
Global Const $se_privilege_removed = 4
Global Const $se_privilege_used_for_access = -2147483648
Global Const $se_group_mandatory = 1
Global Const $se_group_enabled_by_default = 2
Global Const $se_group_enabled = 4
Global Const $se_group_owner = 8
Global Const $se_group_use_for_deny_only = 16
Global Const $se_group_integrity = 32
Global Const $se_group_integrity_enabled = 64
Global Const $se_group_resource = 536870912
Global Const $se_group_logon_id = -1073741824
Global Enum $tokenprimary = 1, $tokenimpersonation
Global Enum $securityanonymous = 0, $securityidentification, $securityimpersonation, $securitydelegation
Global Enum $tokenuser = 1, $tokengroups, $tokenprivileges, $tokenowner, $tokenprimarygroup, $tokendefaultdacl, $tokensource, $tokentype, $tokenimpersonationlevel, $tokenstatistics, $tokenrestrictedsids, $tokensessionid, $tokengroupsandprivileges, $tokensessionreference, $tokensandboxinert, $tokenauditpolicy, $tokenorigin, $tokenelevationtype, $tokenlinkedtoken, $tokenelevation, $tokenhasrestrictions, $tokenaccessinformation, $tokenvirtualizationallowed, $tokenvirtualizationenabled, $tokenintegritylevel, $tokenuiaccess, $tokenmandatorypolicy, $tokenlogonsid
Global Const $token_assign_primary = 1
Global Const $token_duplicate = 2
Global Const $token_impersonate = 4
Global Const $token_query = 8
Global Const $token_query_source = 16
Global Const $token_adjust_privileges = 32
Global Const $token_adjust_groups = 64
Global Const $token_adjust_default = 128
Global Const $token_adjust_sessionid = 256
Global Const $token_all_access = 983551
Global Const $token_read = 131080
Global Const $token_write = 131296
Global Const $token_execute = 131072
Global Const $token_has_traverse_privilege = 1
Global Const $token_has_backup_privilege = 2
Global Const $token_has_restore_privilege = 4
Global Const $token_has_admin_group = 8
Global Const $token_is_restricted = 16
Global Const $token_session_not_referenced = 32
Global Const $token_sandbox_inert = 64
Global Const $token_has_impersonate_privilege = 128
Global Const $rights_delete = 65536
Global Const $read_control = 131072
Global Const $write_dac = 262144
Global Const $write_owner = 524288
Global Const $synchronize = 1048576
Global Const $access_system_security = 16777216
Global Const $standard_rights_required = 983040
Global Const $standard_rights_read = $read_control
Global Const $standard_rights_write = $read_control
Global Const $standard_rights_execute = $read_control
Global Const $standard_rights_all = 2031616
Global Const $specific_rights_all = 65535
Global Enum $not_used_access = 0, $grant_access, $set_access, $deny_access, $revoke_access, $set_audit_success, $set_audit_failure
Global Enum $trustee_is_unknown = 0, $trustee_is_user, $trustee_is_group, $trustee_is_domain, $trustee_is_alias, $trustee_is_well_known_group, $trustee_is_deleted, $trustee_is_invalid, $trustee_is_computer
Global Const $logon_with_profile = 1
Global Const $logon_netcredentials_only = 2
Global Enum $sidtypeuser = 1, $sidtypegroup, $sidtypedomain, $sidtypealias, $sidtypewellknowngroup, $sidtypedeletedaccount, $sidtypeinvalid, $sidtypeunknown, $sidtypecomputer, $sidtypelabel
Global Const $sid_administrators = "S-1-5-32-544"
Global Const $sid_users = "S-1-5-32-545"
Global Const $sid_guests = "S-1-5-32-546"
Global Const $sid_account_operators = "S-1-5-32-548"
Global Const $sid_server_operators = "S-1-5-32-549"
Global Const $sid_print_operators = "S-1-5-32-550"
Global Const $sid_backup_operators = "S-1-5-32-551"
Global Const $sid_replicator = "S-1-5-32-552"
Global Const $sid_owner = "S-1-3-0"
Global Const $sid_everyone = "S-1-1-0"
Global Const $sid_network = "S-1-5-2"
Global Const $sid_interactive = "S-1-5-4"
Global Const $sid_system = "S-1-5-18"
Global Const $sid_authenticated_users = "S-1-5-11"
Global Const $sid_schannel_authentication = "S-1-5-64-14"
Global Const $sid_digest_authentication = "S-1-5-64-21"
Global Const $sid_nt_service = "S-1-5-80"
Global Const $sid_untrusted_mandatory_level = "S-1-16-0"
Global Const $sid_low_mandatory_level = "S-1-16-4096"
Global Const $sid_medium_mandatory_level = "S-1-16-8192"
Global Const $sid_medium_plus_mandatory_level = "S-1-16-8448"
Global Const $sid_high_mandatory_level = "S-1-16-12288"
Global Const $sid_system_mandatory_level = "S-1-16-16384"
Global Const $sid_protected_process_mandatory_level = "S-1-16-20480"
Global Const $sid_secure_process_mandatory_level = "S-1-16-28672"
Global Const $sid_all_services = "S-1-5-80-0"

Func _winapi_getlasterror($ierror = @error, $iextended = @extended)
	Local $aresult = DllCall("kernel32.dll", "dword", "GetLastError")
	Return SetError($ierror, $iextended, $aresult[0])
EndFunc

Func _winapi_setlasterror($ierrorcode, $ierror = @error, $iextended = @extended)
	DllCall("kernel32.dll", "none", "SetLastError", "dword", $ierrorcode)
	Return SetError($ierror, $iextended, NULL )
EndFunc

Func _security__adjusttokenprivileges($htoken, $bdisableall, $pnewstate, $ibufferlen, $pprevstate = 0, $prequired = 0)
	Local $acall = DllCall("advapi32.dll", "bool", "AdjustTokenPrivileges", "handle", $htoken, "bool", $bdisableall, "struct*", $pnewstate, "dword", $ibufferlen, "struct*", $pprevstate, "struct*", $prequired)
	If @error Then Return SetError(@error, @extended, False)
	Return NOT ($acall[0] = 0)
EndFunc



Func _security__getlengthsid($psid)
	If NOT _security__isvalidsid($psid) Then Return SetError(@error + 10, @extended, 0)
	Local $acall = DllCall("advapi32.dll", "dword", "GetLengthSid", "struct*", $psid)
	If @error Then Return SetError(@error, @extended, 0)
	Return $acall[0]
EndFunc

Func _security__impersonateself($ilevel = $securityimpersonation)
	Local $acall = DllCall("advapi32.dll", "bool", "ImpersonateSelf", "int", $ilevel)
	If @error Then Return SetError(@error, @extended, False)
	Return NOT ($acall[0] = 0)
EndFunc

Func _security__isvalidsid($psid)
	Local $acall = DllCall("advapi32.dll", "bool", "IsValidSid", "struct*", $psid)
	If @error Then Return SetError(@error, @extended, False)
	Return NOT ($acall[0] = 0)
EndFunc

Func _security__lookupaccountname($saccount, $ssystem = "")
	Local $tdata = DllStructCreate("byte SID[256]")
	Local $acall = DllCall("advapi32.dll", "bool", "LookupAccountNameW", "wstr", $ssystem, "wstr", $saccount, "struct*", $tdata, "dword*", DllStructGetSize($tdata), "wstr", "", "dword*", DllStructGetSize($tdata), "int*", 0)
	If @error OR NOT $acall[0] Then Return SetError(@error, @extended, 0)
	Local $aacct[3]
	$aacct[0] = _security__sidtostringsid(DllStructGetPtr($tdata, "SID"))
	$aacct[1] = $acall[5]
	$aacct[2] = $acall[7]
	Return $aacct
EndFunc

Func _security__lookupaccountsid($vsid, $ssystem = "")
	Local $psid, $aacct[3]
	If IsString($vsid) Then
		$psid = _security__stringsidtosid($vsid)
	Else
		$psid = $vsid
	EndIf
	If NOT _security__isvalidsid($psid) Then Return SetError(@error + 10, @extended, 0)
	Local $stypesystem = "ptr"
	If $ssystem Then $stypesystem = "wstr"
	Local $acall = DllCall("advapi32.dll", "bool", "LookupAccountSidW", $stypesystem, $ssystem, "struct*", $psid, "wstr", "", "dword*", 65536, "wstr", "", "dword*", 65536, "int*", 0)
	If @error OR NOT $acall[0] Then Return SetError(@error, @extended, 0)
	Local $aacct[3]
	$aacct[0] = $acall[3]
	$aacct[1] = $acall[5]
	$aacct[2] = $acall[7]
	Return $aacct
EndFunc

Func _security__lookupprivilegevalue($ssystem, $sname)
	Local $acall = DllCall("advapi32.dll", "bool", "LookupPrivilegeValueW", "wstr", $ssystem, "wstr", $sname, "int64*", 0)
	If @error OR NOT $acall[0] Then Return SetError(@error, @extended, 0)
	Return $acall[3]
EndFunc

Func _security__openprocesstoken($hprocess, $iaccess)
	Local $acall = DllCall("advapi32.dll", "bool", "OpenProcessToken", "handle", $hprocess, "dword", $iaccess, "handle*", 0)
	If @error OR NOT $acall[0] Then Return SetError(@error, @extended, 0)
	Return $acall[3]
EndFunc

Func _security__openthreadtoken($iaccess, $hthread = 0, $bopenasself = False)
	If $hthread = 0 Then
		Local $aresult = DllCall("kernel32.dll", "handle", "GetCurrentThread")
		If @error Then Return SetError(@error + 10, @extended, 0)
		$hthread = $aresult[0]
	EndIf
	Local $acall = DllCall("advapi32.dll", "bool", "OpenThreadToken", "handle", $hthread, "dword", $iaccess, "bool", $bopenasself, "handle*", 0)
	If @error OR NOT $acall[0] Then Return SetError(@error, @extended, 0)
	Return $acall[4]
EndFunc

Func _security__openthreadtokenex($iaccess, $hthread = 0, $bopenasself = False)
	Local $htoken = _security__openthreadtoken($iaccess, $hthread, $bopenasself)
	If $htoken = 0 Then
		Local Const $error_no_token = 1008
		If _winapi_getlasterror() <> $error_no_token Then Return SetError(20, _winapi_getlasterror(), 0)
		If NOT _security__impersonateself() Then Return SetError(@error + 10, _winapi_getlasterror(), 0)
		$htoken = _security__openthreadtoken($iaccess, $hthread, $bopenasself)
		If $htoken = 0 Then Return SetError(@error, _winapi_getlasterror(), 0)
	EndIf
	Return $htoken
EndFunc

Func _security__setprivilege($htoken, $sprivilege, $benable)
	Local $iluid = _security__lookupprivilegevalue("", $sprivilege)
	If $iluid = 0 Then Return SetError(@error + 10, @extended, False)
	Local Const $tagtoken_privileges = "dword Count;align 4;int64 LUID;dword Attributes"
	Local $tcurrstate = DllStructCreate($tagtoken_privileges)
	Local $icurrstate = DllStructGetSize($tcurrstate)
	Local $tprevstate = DllStructCreate($tagtoken_privileges)
	Local $iprevstate = DllStructGetSize($tprevstate)
	Local $trequired = DllStructCreate("int Data")
	DllStructSetData($tcurrstate, "Count", 1)
	DllStructSetData($tcurrstate, "LUID", $iluid)
	If NOT _security__adjusttokenprivileges($htoken, False, $tcurrstate, $icurrstate, $tprevstate, $trequired) Then Return SetError(2, @error, False)
	DllStructSetData($tprevstate, "Count", 1)
	DllStructSetData($tprevstate, "LUID", $iluid)
	Local $iattributes = DllStructGetData($tprevstate, "Attributes")
	If $benable Then
		$iattributes = BitOR($iattributes, $se_privilege_enabled)
	Else
		$iattributes = BitAND($iattributes, BitNOT($se_privilege_enabled))
	EndIf
	DllStructSetData($tprevstate, "Attributes", $iattributes)
	If NOT _security__adjusttokenprivileges($htoken, False, $tprevstate, $iprevstate, $tcurrstate, $trequired) Then Return SetError(3, @error, False)
	Return True
EndFunc

Func _security__settokeninformation($htoken, $itokeninformation, $vtokeninformation, $itokeninformationlength)
	Local $acall = DllCall("advapi32.dll", "bool", "SetTokenInformation", "handle", $htoken, "int", $itokeninformation, "struct*", $vtokeninformation, "dword", $itokeninformationlength)
	If @error OR NOT $acall[0] Then Return SetError(@error, @extended, False)
	Return True
EndFunc

Func _security__sidtostringsid($psid)
	If NOT _security__isvalidsid($psid) Then Return SetError(@error + 10, 0, "")
	Local $acall = DllCall("advapi32.dll", "bool", "ConvertSidToStringSidW", "struct*", $psid, "ptr*", 0)
	If @error OR NOT $acall[0] Then Return SetError(@error, @extended, "")
	Local $pstringsid = $acall[2]
	Local $alen = DllCall("kernel32.dll", "int", "lstrlenW", "struct*", $pstringsid)
	Local $ssid = DllStructGetData(DllStructCreate("wchar Text[" & $alen[0] + 1 & "]", $pstringsid), "Text")
	DllCall("kernel32.dll", "handle", "LocalFree", "handle", $pstringsid)
	Return $ssid
EndFunc

Func _security__sidtypestr($itype)
	Switch $itype
		Case $sidtypeuser
			Return "User"
		Case $sidtypegroup
			Return "Group"
		Case $sidtypedomain
			Return "Domain"
		Case $sidtypealias
			Return "Alias"
		Case $sidtypewellknowngroup
			Return "Well Known Group"
		Case $sidtypedeletedaccount
			Return "Deleted Account"
		Case $sidtypeinvalid
			Return "Invalid"
		Case $sidtypeunknown
			Return "Unknown Type"
		Case $sidtypecomputer
			Return "Computer"
		Case $sidtypelabel
			Return "A mandatory integrity label SID"
		Case Else
			Return "Unknown SID Type"
	EndSwitch
EndFunc

Func _security__stringsidtosid($ssid)
	Local $acall = DllCall("advapi32.dll", "bool", "ConvertStringSidToSidW", "wstr", $ssid, "ptr*", 0)
	If @error OR NOT $acall[0] Then Return SetError(@error, @extended, 0)
	Local $psid = $acall[2]
	Local $tbuffer = DllStructCreate("byte Data[" & _security__getlengthsid($psid) & "]", $psid)
	Local $tsid = DllStructCreate("byte Data[" & DllStructGetSize($tbuffer) & "]")
	DllStructSetData($tsid, "Data", DllStructGetData($tbuffer, "Data"))
	DllCall("kernel32.dll", "handle", "LocalFree", "handle", $psid)
	Return $tsid
EndFunc

Func _sendmessage($hwnd, $imsg, $wparam = 0, $lparam = 0, $ireturn = 0, $wparamtype = "wparam", $lparamtype = "lparam", $sreturntype = "lresult")
	Local $aresult = DllCall("user32.dll", $sreturntype, "SendMessageW", "hwnd", $hwnd, "uint", $imsg, $wparamtype, $wparam, $lparamtype, $lparam)
	If @error Then Return SetError(@error, @extended, "")
	If $ireturn >= 0 AND $ireturn <= 4 Then Return $aresult[$ireturn]
	Return $aresult
EndFunc

Func _sendmessagea($hwnd, $imsg, $wparam = 0, $lparam = 0, $ireturn = 0, $wparamtype = "wparam", $lparamtype = "lparam", $sreturntype = "lresult")
	Local $aresult = DllCall("user32.dll", $sreturntype, "SendMessageA", "hwnd", $hwnd, "uint", $imsg, $wparamtype, $wparam, $lparamtype, $lparam)
	If @error Then Return SetError(@error, @extended, "")
	If $ireturn >= 0 AND $ireturn <= 4 Then Return $aresult[$ireturn]
	Return $aresult
EndFunc

Global Const $tagpoint = "struct;long X;long Y;endstruct"
Global Const $tagrect = "struct;long Left;long Top;long Right;long Bottom;endstruct"
Global Const $tagsize = "struct;long X;long Y;endstruct"
Global Const $tagmargins = "int cxLeftWidth;int cxRightWidth;int cyTopHeight;int cyBottomHeight"
Global Const $tagfiletime = "struct;dword Lo;dword Hi;endstruct"
Global Const $tagsystemtime = "struct;word Year;word Month;word Dow;word Day;word Hour;word Minute;word Second;word MSeconds;endstruct"
Global Const $tagtime_zone_information = "struct;long Bias;wchar StdName[32];word StdDate[8];long StdBias;wchar DayName[32];word DayDate[8];long DayBias;endstruct"
Global Const $tagnmhdr = "struct;hwnd hWndFrom;uint_ptr IDFrom;INT Code;endstruct"
Global Const $tagcomboboxexitem = "uint Mask;int_ptr Item;ptr Text;int TextMax;int Image;int SelectedImage;int OverlayImage;" & "int Indent;lparam Param"
Global Const $tagnmcbedragbegin = $tagnmhdr & ";int ItemID;wchar szText[260]"
Global Const $tagnmcbeendedit = $tagnmhdr & ";bool fChanged;int NewSelection;wchar szText[260];int Why"
Global Const $tagnmcomboboxex = $tagnmhdr & ";uint Mask;int_ptr Item;ptr Text;int TextMax;int Image;" & "int SelectedImage;int OverlayImage;int Indent;lparam Param"
Global Const $tagdtprange = "word MinYear;word MinMonth;word MinDOW;word MinDay;word MinHour;word MinMinute;" & "word MinSecond;word MinMSecond;word MaxYear;word MaxMonth;word MaxDOW;word MaxDay;word MaxHour;" & "word MaxMinute;word MaxSecond;word MaxMSecond;bool MinValid;bool MaxValid"
Global Const $tagnmdatetimechange = $tagnmhdr & ";dword Flag;" & $tagsystemtime
Global Const $tagnmdatetimeformat = $tagnmhdr & ";ptr Format;" & $tagsystemtime & ";ptr pDisplay;wchar Display[64]"
Global Const $tagnmdatetimeformatquery = $tagnmhdr & ";ptr Format;struct;long SizeX;long SizeY;endstruct"
Global Const $tagnmdatetimekeydown = $tagnmhdr & ";int VirtKey;ptr Format;" & $tagsystemtime
Global Const $tagnmdatetimestring = $tagnmhdr & ";ptr UserString;" & $tagsystemtime & ";dword Flags"
Global Const $tageventlogrecord = "dword Length;dword Reserved;dword RecordNumber;dword TimeGenerated;dword TimeWritten;dword EventID;" & "word EventType;word NumStrings;word EventCategory;word ReservedFlags;dword ClosingRecordNumber;dword StringOffset;" & "dword UserSidLength;dword UserSidOffset;dword DataLength;dword DataOffset"
Global Const $taggdip_effectparams_blur = "float Radius; bool ExpandEdge"
Global Const $taggdip_effectparams_brightnesscontrast = "int BrightnessLevel; int ContrastLevel"
Global Const $taggdip_effectparams_colorbalance = "int CyanRed; int MagentaGreen; int YellowBlue"
Global Const $taggdip_effectparams_colorcurve = "int Adjustment; int Channel; int AdjustValue"
Global Const $taggdip_effectparams_colorlut = "byte LutB[256]; byte LutG[256]; byte LutR[256]; byte LutA[256]"
Global Const $taggdip_effectparams_huesaturationlightness = "int HueLevel; int SaturationLevel; int LightnessLevel"
Global Const $taggdip_effectparams_levels = "int Highlight; int Midtone; int Shadow"
Global Const $taggdip_effectparams_redeyecorrection = "uint NumberOfAreas; ptr Areas"
Global Const $taggdip_effectparams_sharpen = "float Radius; float Amount"
Global Const $taggdip_effectparams_tint = "int Hue; int Amount"
Global Const $taggdipbitmapdata = "uint Width;uint Height;int Stride;int Format;ptr Scan0;uint_ptr Reserved"
Global Const $taggdipcolormatrix = "float m[25]"
Global Const $taggdipencoderparam = "struct;byte GUID[16];ulong NumberOfValues;ulong Type;ptr Values;endstruct"
Global Const $taggdipencoderparams = "uint Count;" & $taggdipencoderparam
Global Const $taggdiprectf = "struct;float X;float Y;float Width;float Height;endstruct"
Global Const $taggdipstartupinput = "uint Version;ptr Callback;bool NoThread;bool NoCodecs"
Global Const $taggdipstartupoutput = "ptr HookProc;ptr UnhookProc"
Global Const $taggdipimagecodecinfo = "byte CLSID[16];byte FormatID[16];ptr CodecName;ptr DllName;ptr FormatDesc;ptr FileExt;" & "ptr MimeType;dword Flags;dword Version;dword SigCount;dword SigSize;ptr SigPattern;ptr SigMask"
Global Const $taggdippencoderparams = "uint Count;byte Params[1]"
Global Const $taghditem = "uint Mask;int XY;ptr Text;handle hBMP;int TextMax;int Fmt;lparam Param;int Image;int Order;uint Type;ptr pFilter;uint State"
Global Const $tagnmhddispinfo = $tagnmhdr & ";int Item;uint Mask;ptr Text;int TextMax;int Image;lparam lParam"
Global Const $tagnmhdfilterbtnclick = $tagnmhdr & ";int Item;" & $tagrect
Global Const $tagnmheader = $tagnmhdr & ";int Item;int Button;ptr pItem"
Global Const $taggetipaddress = "byte Field4;byte Field3;byte Field2;byte Field1"
Global Const $tagnmipaddress = $tagnmhdr & ";int Field;int Value"
Global Const $taglvfindinfo = "struct;uint Flags;ptr Text;lparam Param;" & $tagpoint & ";uint Direction;endstruct"
Global Const $taglvhittestinfo = $tagpoint & ";uint Flags;int Item;int SubItem;int iGroup"
Global Const $taglvitem = "struct;uint Mask;int Item;int SubItem;uint State;uint StateMask;ptr Text;int TextMax;int Image;lparam Param;" & "int Indent;int GroupID;uint Columns;ptr pColumns;ptr piColFmt;int iGroup;endstruct"
Global Const $tagnmlistview = $tagnmhdr & ";int Item;int SubItem;uint NewState;uint OldState;uint Changed;" & "struct;long ActionX;long ActionY;endstruct;lparam Param"
Global Const $tagnmlvcustomdraw = "struct;" & $tagnmhdr & ";dword dwDrawStage;handle hdc;" & $tagrect & ";dword_ptr dwItemSpec;uint uItemState;lparam lItemlParam;endstruct" & ";dword clrText;dword clrTextBk;int iSubItem;dword dwItemType;dword clrFace;int iIconEffect;" & "int iIconPhase;int iPartId;int iStateId;struct;long TextLeft;long TextTop;long TextRight;long TextBottom;endstruct;uint uAlign"
Global Const $tagnmlvdispinfo = $tagnmhdr & ";" & $taglvitem
Global Const $tagnmlvfinditem = $tagnmhdr & ";int Start;" & $taglvfindinfo
Global Const $tagnmlvgetinfotip = $tagnmhdr & ";dword Flags;ptr Text;int TextMax;int Item;int SubItem;lparam lParam"
Global Const $tagnmitemactivate = $tagnmhdr & ";int Index;int SubItem;uint NewState;uint OldState;uint Changed;" & $tagpoint & ";lparam lParam;uint KeyFlags"
Global Const $tagnmlvkeydown = "align 1;" & $tagnmhdr & ";word VKey;uint Flags"
Global Const $tagnmlvscroll = $tagnmhdr & ";int DX;int DY"
Global Const $tagmchittestinfo = "uint Size;" & $tagpoint & ";uint Hit;" & $tagsystemtime & ";" & $tagrect & ";int iOffset;int iRow;int iCol"
Global Const $tagmcmonthrange = "word MinYear;word MinMonth;word MinDOW;word MinDay;word MinHour;word MinMinute;word MinSecond;" & "word MinMSeconds;word MaxYear;word MaxMonth;word MaxDOW;word MaxDay;word MaxHour;word MaxMinute;word MaxSecond;" & "word MaxMSeconds;short Span"
Global Const $tagmcrange = "word MinYear;word MinMonth;word MinDOW;word MinDay;word MinHour;word MinMinute;word MinSecond;" & "word MinMSeconds;word MaxYear;word MaxMonth;word MaxDOW;word MaxDay;word MaxHour;word MaxMinute;word MaxSecond;" & "word MaxMSeconds;short MinSet;short MaxSet"
Global Const $tagmcselrange = "word MinYear;word MinMonth;word MinDOW;word MinDay;word MinHour;word MinMinute;word MinSecond;" & "word MinMSeconds;word MaxYear;word MaxMonth;word MaxDOW;word MaxDay;word MaxHour;word MaxMinute;word MaxSecond;" & "word MaxMSeconds"
Global Const $tagnmdaystate = $tagnmhdr & ";" & $tagsystemtime & ";int DayState;ptr pDayState"
Global Const $tagnmselchange = $tagnmhdr & ";struct;word BegYear;word BegMonth;word BegDOW;word BegDay;word BegHour;word BegMinute;word BegSecond;word BegMSeconds;endstruct;" & "struct;word EndYear;word EndMonth;word EndDOW;word EndDay;word EndHour;word EndMinute;word EndSecond;word EndMSeconds;endstruct"
Global Const $tagnmobjectnotify = $tagnmhdr & ";int Item;ptr piid;ptr pObject;long Result;dword dwFlags"
Global Const $tagnmtckeydown = "align 1;" & $tagnmhdr & ";word VKey;uint Flags"
Global Const $tagtvitem = "struct;uint Mask;handle hItem;uint State;uint StateMask;ptr Text;int TextMax;int Image;int SelectedImage;" & "int Children;lparam Param;endstruct"
Global Const $tagtvitemex = "struct;" & $tagtvitem & ";int Integral;uint uStateEx;hwnd hwnd;int iExpandedImage;int iReserved;endstruct"
Global Const $tagnmtreeview = $tagnmhdr & ";uint Action;" & "struct;uint OldMask;handle OldhItem;uint OldState;uint OldStateMask;" & "ptr OldText;int OldTextMax;int OldImage;int OldSelectedImage;int OldChildren;lparam OldParam;endstruct;" & "struct;uint NewMask;handle NewhItem;uint NewState;uint NewStateMask;" & "ptr NewText;int NewTextMax;int NewImage;int NewSelectedImage;int NewChildren;lparam NewParam;endstruct;" & "struct;long PointX;long PointY;endstruct"
Global Const $tagnmtvcustomdraw = "struct;" & $tagnmhdr & ";dword DrawStage;handle HDC;" & $tagrect & ";dword_ptr ItemSpec;uint ItemState;lparam ItemParam;endstruct" & ";dword ClrText;dword ClrTextBk;int Level"
Global Const $tagnmtvdispinfo = $tagnmhdr & ";" & $tagtvitem
Global Const $tagnmtvgetinfotip = $tagnmhdr & ";ptr Text;int TextMax;handle hItem;lparam lParam"
Global Const $tagnmtvitemchange = $tagnmhdr & ";uint Changed;handle hItem;uint StateNew;uint StateOld;lparam lParam;"
Global Const $tagtvhittestinfo = $tagpoint & ";uint Flags;handle Item"
Global Const $tagnmtvkeydown = "align 1;" & $tagnmhdr & ";word VKey;uint Flags"
Global Const $tagnmmouse = $tagnmhdr & ";dword_ptr ItemSpec;dword_ptr ItemData;" & $tagpoint & ";lparam HitInfo"
Global Const $tagtoken_privileges = "dword Count;align 4;int64 LUID;dword Attributes"
Global Const $tagimageinfo = "handle hBitmap;handle hMask;int Unused1;int Unused2;" & $tagrect
Global Const $tagmenuinfo = "dword Size;INT Mask;dword Style;uint YMax;handle hBack;dword ContextHelpID;ulong_ptr MenuData"
Global Const $tagmenuiteminfo = "uint Size;uint Mask;uint Type;uint State;uint ID;handle SubMenu;handle BmpChecked;handle BmpUnchecked;" & "ulong_ptr ItemData;ptr TypeData;uint CCH;handle BmpItem"
Global Const $tagrebarbandinfo = "uint cbSize;uint fMask;uint fStyle;dword clrFore;dword clrBack;ptr lpText;uint cch;" & "int iImage;hwnd hwndChild;uint cxMinChild;uint cyMinChild;uint cx;handle hbmBack;uint wID;uint cyChild;uint cyMaxChild;" & "uint cyIntegral;uint cxIdeal;lparam lParam;uint cxHeader" & ((@OSVersion = "WIN_XP") ? "" : ";" & $tagrect & ";uint uChevronState")
Global Const $tagnmrebarautobreak = $tagnmhdr & ";uint uBand;uint wID;lparam lParam;uint uMsg;uint fStyleCurrent;bool fAutoBreak"
Global Const $tagnmrbautosize = $tagnmhdr & ";bool fChanged;" & "struct;long TargetLeft;long TargetTop;long TargetRight;long TargetBottom;endstruct;" & "struct;long ActualLeft;long ActualTop;long ActualRight;long ActualBottom;endstruct"
Global Const $tagnmrebar = $tagnmhdr & ";dword dwMask;uint uBand;uint fStyle;uint wID;lparam lParam"
Global Const $tagnmrebarchevron = $tagnmhdr & ";uint uBand;uint wID;lparam lParam;" & $tagrect & ";lparam lParamNM"
Global Const $tagnmrebarchildsize = $tagnmhdr & ";uint uBand;uint wID;" & "struct;long CLeft;long CTop;long CRight;long CBottom;endstruct;" & "struct;long BLeft;long BTop;long BRight;long BBottom;endstruct"
Global Const $tagcolorscheme = "dword Size;dword BtnHighlight;dword BtnShadow"
Global Const $tagnmtoolbar = $tagnmhdr & ";int iItem;" & "struct;int iBitmap;int idCommand;byte fsState;byte fsStyle;dword_ptr dwData;int_ptr iString;endstruct" & ";int cchText;ptr pszText;" & $tagrect
Global Const $tagnmtbhotitem = $tagnmhdr & ";int idOld;int idNew;dword dwFlags"
Global Const $tagtbbutton = "int Bitmap;int Command;byte State;byte Style;dword_ptr Param;int_ptr String"
Global Const $tagtbbuttoninfo = "uint Size;dword Mask;int Command;int Image;byte State;byte Style;word CX;dword_ptr Param;ptr Text;int TextMax"
Global Const $tagnetresource = "dword Scope;dword Type;dword DisplayType;dword Usage;ptr LocalName;ptr RemoteName;ptr Comment;ptr Provider"
Global Const $tagoverlapped = "ulong_ptr Internal;ulong_ptr InternalHigh;struct;dword Offset;dword OffsetHigh;endstruct;handle hEvent"
Global Const $tagopenfilename = "dword StructSize;hwnd hwndOwner;handle hInstance;ptr lpstrFilter;ptr lpstrCustomFilter;" & "dword nMaxCustFilter;dword nFilterIndex;ptr lpstrFile;dword nMaxFile;ptr lpstrFileTitle;dword nMaxFileTitle;" & "ptr lpstrInitialDir;ptr lpstrTitle;dword Flags;word nFileOffset;word nFileExtension;ptr lpstrDefExt;lparam lCustData;" & "ptr lpfnHook;ptr lpTemplateName;ptr pvReserved;dword dwReserved;dword FlagsEx"
Global Const $tagbitmapinfoheader = "struct;dword biSize;long biWidth;long biHeight;word biPlanes;word biBitCount;" & "dword biCompression;dword biSizeImage;long biXPelsPerMeter;long biYPelsPerMeter;dword biClrUsed;dword biClrImportant;endstruct"
Global Const $tagbitmapinfo = $tagbitmapinfoheader & ";dword biRGBQuad[1]"
Global Const $tagblendfunction = "byte Op;byte Flags;byte Alpha;byte Format"
Global Const $tagguid = "struct;ulong Data1;ushort Data2;ushort Data3;byte Data4[8];endstruct"
Global Const $tagwindowplacement = "uint length;uint flags;uint showCmd;long ptMinPosition[2];long ptMaxPosition[2];long rcNormalPosition[4]"
Global Const $tagwindowpos = "hwnd hWnd;hwnd InsertAfter;int X;int Y;int CX;int CY;uint Flags"
Global Const $tagscrollinfo = "uint cbSize;uint fMask;int nMin;int nMax;uint nPage;int nPos;int nTrackPos"
Global Const $tagscrollbarinfo = "dword cbSize;" & $tagrect & ";int dxyLineButton;int xyThumbTop;" & "int xyThumbBottom;int reserved;dword rgstate[6]"
Global Const $taglogfont = "struct;long Height;long Width;long Escapement;long Orientation;long Weight;byte Italic;byte Underline;" & "byte Strikeout;byte CharSet;byte OutPrecision;byte ClipPrecision;byte Quality;byte PitchAndFamily;wchar FaceName[32];endstruct"
Global Const $tagkbdllhookstruct = "dword vkCode;dword scanCode;dword flags;dword time;ulong_ptr dwExtraInfo"
Global Const $tagprocess_information = "handle hProcess;handle hThread;dword ProcessID;dword ThreadID"
Global Const $tagstartupinfo = "dword Size;ptr Reserved1;ptr Desktop;ptr Title;dword X;dword Y;dword XSize;dword YSize;dword XCountChars;" & "dword YCountChars;dword FillAttribute;dword Flags;word ShowWindow;word Reserved2;ptr Reserved3;handle StdInput;" & "handle StdOutput;handle StdError"
Global Const $tagsecurity_attributes = "dword Length;ptr Descriptor;bool InheritHandle"
Global Const $tagwin32_find_data = "dword dwFileAttributes;dword ftCreationTime[2];dword ftLastAccessTime[2];dword ftLastWriteTime[2];dword nFileSizeHigh;dword nFileSizeLow;dword dwReserved0;dword dwReserved1;wchar cFileName[260];wchar cAlternateFileName[14]"
Global Const $tagtextmetric = "long tmHeight;long tmAscent;long tmDescent;long tmInternalLeading;long tmExternalLeading;" & "long tmAveCharWidth;long tmMaxCharWidth;long tmWeight;long tmOverhang;long tmDigitizedAspectX;long tmDigitizedAspectY;" & "wchar tmFirstChar;wchar tmLastChar;wchar tmDefaultChar;wchar tmBreakChar;byte tmItalic;byte tmUnderlined;byte tmStruckOut;" & "byte tmPitchAndFamily;byte tmCharSet"
Global Const $hgdi_error = Ptr(-1)
Global Const $invalid_handle_value = Ptr(-1)
Global Const $clr_invalid = -1
Global Const $null_brush = 5
Global Const $null_pen = 8
Global Const $black_brush = 4
Global Const $dkgray_brush = 3
Global Const $dc_brush = 18
Global Const $gray_brush = 2
Global Const $hollow_brush = $null_brush
Global Const $ltgray_brush = 1
Global Const $white_brush = 0
Global Const $black_pen = 7
Global Const $dc_pen = 19
Global Const $white_pen = 6
Global Const $ansi_fixed_font = 11
Global Const $ansi_var_font = 12
Global Const $device_default_font = 14
Global Const $default_gui_font = 17
Global Const $oem_fixed_font = 10
Global Const $system_font = 13
Global Const $system_fixed_font = 16
Global Const $default_palette = 15
Global Const $mb_precomposed = 1
Global Const $mb_composite = 2
Global Const $mb_useglyphchars = 4
Global Const $ulw_alpha = 2
Global Const $ulw_colorkey = 1
Global Const $ulw_opaque = 4
Global Const $ulw_ex_noresize = 8
Global Const $wh_callwndproc = 4
Global Const $wh_callwndprocret = 12
Global Const $wh_cbt = 5
Global Const $wh_debug = 9
Global Const $wh_foregroundidle = 11
Global Const $wh_getmessage = 3
Global Const $wh_journalplayback = 1
Global Const $wh_journalrecord = 0
Global Const $wh_keyboard = 2
Global Const $wh_keyboard_ll = 13
Global Const $wh_mouse = 7
Global Const $wh_mouse_ll = 14
Global Const $wh_msgfilter = -1
Global Const $wh_shell = 10
Global Const $wh_sysmsgfilter = 6
Global Const $wpf_asyncwindowplacement = 4
Global Const $wpf_restoretomaximized = 2
Global Const $wpf_setminposition = 1
Global Const $kf_extended = 256
Global Const $kf_altdown = 8192
Global Const $kf_up = 32768
Global Const $llkhf_extended = BitShift($kf_extended, 8)
Global Const $llkhf_injected = 16
Global Const $llkhf_altdown = BitShift($kf_altdown, 8)
Global Const $llkhf_up = BitShift($kf_up, 8)
Global Const $ofn_allowmultiselect = 512
Global Const $ofn_createprompt = 8192
Global Const $ofn_dontaddtorecent = 33554432
Global Const $ofn_enablehook = 32
Global Const $ofn_enableincludenotify = 4194304
Global Const $ofn_enablesizing = 8388608
Global Const $ofn_enabletemplate = 64
Global Const $ofn_enabletemplatehandle = 128
Global Const $ofn_explorer = 524288
Global Const $ofn_extensiondifferent = 1024
Global Const $ofn_filemustexist = 4096
Global Const $ofn_forceshowhidden = 268435456
Global Const $ofn_hidereadonly = 4
Global Const $ofn_longnames = 2097152
Global Const $ofn_nochangedir = 8
Global Const $ofn_nodereferencelinks = 1048576
Global Const $ofn_nolongnames = 262144
Global Const $ofn_nonetworkbutton = 131072
Global Const $ofn_noreadonlyreturn = 32768
Global Const $ofn_notestfilecreate = 65536
Global Const $ofn_novalidate = 256
Global Const $ofn_overwriteprompt = 2
Global Const $ofn_pathmustexist = 2048
Global Const $ofn_readonly = 1
Global Const $ofn_shareaware = 16384
Global Const $ofn_showhelp = 16
Global Const $ofn_ex_noplacesbar = 1
Global Const $tmpf_fixed_pitch = 1
Global Const $tmpf_vector = 2
Global Const $tmpf_truetype = 4
Global Const $tmpf_device = 8
Global Const $duplicate_close_source = 1
Global Const $duplicate_same_access = 2
Global Const $di_mask = 1
Global Const $di_image = 2
Global Const $di_normal = 3
Global Const $di_compat = 4
Global Const $di_defaultsize = 8
Global Const $di_nomirror = 16
Global Const $display_device_attached_to_desktop = 1
Global Const $display_device_multi_driver = 2
Global Const $display_device_primary_device = 4
Global Const $display_device_mirroring_driver = 8
Global Const $display_device_vga_compatible = 16
Global Const $display_device_removable = 32
Global Const $display_device_disconnect = 33554432
Global Const $display_device_remote = 67108864
Global Const $display_device_modespruned = 134217728
Global Const $flashw_caption = 1
Global Const $flashw_tray = 2
Global Const $flashw_timer = 4
Global Const $flashw_timernofg = 12
Global Const $format_message_allocate_buffer = 256
Global Const $format_message_ignore_inserts = 512
Global Const $format_message_from_string = 1024
Global Const $format_message_from_hmodule = 2048
Global Const $format_message_from_system = 4096
Global Const $format_message_argument_array = 8192
Global Const $gw_hwndfirst = 0
Global Const $gw_hwndlast = 1
Global Const $gw_hwndnext = 2
Global Const $gw_hwndprev = 3
Global Const $gw_owner = 4
Global Const $gw_child = 5
Global Const $gw_enabledpopup = 6
Global Const $gwl_wndproc = -4
Global Const $gwl_hinstance = -6
Global Const $gwl_hwndparent = -8
Global Const $gwl_id = -12
Global Const $gwl_style = -16
Global Const $gwl_exstyle = -20
Global Const $gwl_userdata = -21
Global Const $std_cut = 0
Global Const $std_copy = 1
Global Const $std_paste = 2
Global Const $std_undo = 3
Global Const $std_redow = 4
Global Const $std_delete = 5
Global Const $std_filenew = 6
Global Const $std_fileopen = 7
Global Const $std_filesave = 8
Global Const $std_printpre = 9
Global Const $std_properties = 10
Global Const $std_help = 11
Global Const $std_find = 12
Global Const $std_replace = 13
Global Const $std_print = 14
Global Const $image_bitmap = 0
Global Const $image_icon = 1
Global Const $image_cursor = 2
Global Const $image_enhmetafile = 3
Global Const $kb_sendspecial = 0
Global Const $kb_sendraw = 1
Global Const $kb_capsoff = 0
Global Const $kb_capson = 1
Global Const $dont_resolve_dll_references = 1
Global Const $load_library_as_datafile = 2
Global Const $load_with_altered_search_path = 8
Global Const $load_ignore_code_authz_level = 16
Global Const $load_library_as_datafile_exclusive = 64
Global Const $load_library_as_image_resource = 32
Global Const $load_library_search_application_dir = 512
Global Const $load_library_search_default_dirs = 4096
Global Const $load_library_search_dll_load_dir = 256
Global Const $load_library_search_system32 = 2048
Global Const $load_library_search_user_dirs = 1024
Global Const $s_ok = 0
Global Const $e_abort = -2147467260
Global Const $e_accessdenied = -2147024891
Global Const $e_fail = -2147467259
Global Const $e_handle = -2147024890
Global Const $e_invalidarg = -2147024809
Global Const $e_nointerface = -2147467262
Global Const $e_notimpl = -2147467263
Global Const $e_outofmemory = -2147024882
Global Const $e_pointer = -2147467261
Global Const $e_unexpected = -2147418113
Global Const $lr_defaultcolor = 0
Global Const $lr_monochrome = 1
Global Const $lr_color = 2
Global Const $lr_copyreturnorg = 4
Global Const $lr_copydeleteorg = 8
Global Const $lr_loadfromfile = 16
Global Const $lr_loadtransparent = 32
Global Const $lr_defaultsize = 64
Global Const $lr_vgacolor = 128
Global Const $lr_loadmap3dcolors = 4096
Global Const $lr_createdibsection = 8192
Global Const $lr_copyfromresource = 16384
Global Const $lr_shared = 32768
Global Const $obm_trtype = 32732
Global Const $obm_lfarrowi = 32734
Global Const $obm_rgarrowi = 32735
Global Const $obm_dnarrowi = 32736
Global Const $obm_uparrowi = 32737
Global Const $obm_combo = 32738
Global Const $obm_mnarrow = 32739
Global Const $obm_lfarrowd = 32740
Global Const $obm_rgarrowd = 32741
Global Const $obm_dnarrowd = 32742
Global Const $obm_uparrowd = 32743
Global Const $obm_restored = 32744
Global Const $obm_zoomd = 32745
Global Const $obm_reduced = 32746
Global Const $obm_restore = 32747
Global Const $obm_zoom = 32748
Global Const $obm_reduce = 32749
Global Const $obm_lfarrow = 32750
Global Const $obm_rgarrow = 32751
Global Const $obm_dnarrow = 32752
Global Const $obm_uparrow = 32753
Global Const $obm_close = 32754
Global Const $obm_old_restore = 32755
Global Const $obm_old_zoom = 32756
Global Const $obm_old_reduce = 32757
Global Const $obm_btncorners = 32758
Global Const $obm_checkboxes = 32759
Global Const $obm_check = 32760
Global Const $obm_btsize = 32761
Global Const $obm_old_lfarrow = 32762
Global Const $obm_old_rgarrow = 32763
Global Const $obm_old_dnarrow = 32764
Global Const $obm_old_uparrow = 32765
Global Const $obm_size = 32766
Global Const $obm_old_close = 32767
Global Const $oic_sample = 32512
Global Const $oic_hand = 32513
Global Const $oic_ques = 32514
Global Const $oic_bang = 32515
Global Const $oic_note = 32516
Global Const $oic_winlogo = 32517
Global Const $oic_warning = $oic_bang
Global Const $oic_error = $oic_hand
Global Const $oic_information = $oic_note
Global $__g_ainprocess_winapi[64][2] = [[0, 0]]
Global $__g_awinlist_winapi[64][2] = [[0, 0]]
Global Const $__winapiconstant_wm_setfont = 48
Global Const $__winapiconstant_fw_normal = 400
Global Const $__winapiconstant_default_charset = 1
Global Const $__winapiconstant_out_default_precis = 0
Global Const $__winapiconstant_clip_default_precis = 0
Global Const $__winapiconstant_default_quality = 0
Global Const $__winapiconstant_logpixelsx = 88
Global Const $__winapiconstant_logpixelsy = 90
Global Const $tagcursorinfo = "dword Size;dword Flags;handle hCursor;" & $tagpoint
Global Const $tagdisplay_device = "dword Size;wchar Name[32];wchar String[128];dword Flags;wchar ID[128];wchar Key[128]"
Global Const $tagflashwinfo = "uint Size;hwnd hWnd;dword Flags;uint Count;dword TimeOut"
Global Const $tagiconinfo = "bool Icon;dword XHotSpot;dword YHotSpot;handle hMask;handle hColor"
Global Const $tagmemorystatusex = "dword Length;dword MemoryLoad;" & "uint64 TotalPhys;uint64 AvailPhys;uint64 TotalPageFile;uint64 AvailPageFile;" & "uint64 TotalVirtual;uint64 AvailVirtual;uint64 AvailExtendedVirtual"

Func _winapi_attachconsole($ipid = -1)
	Local $aresult = DllCall("kernel32.dll", "bool", "AttachConsole", "dword", $ipid)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_attachthreadinput($iattach, $iattachto, $battach)
	Local $aresult = DllCall("user32.dll", "bool", "AttachThreadInput", "dword", $iattach, "dword", $iattachto, "bool", $battach)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_beep($ifreq = 500, $iduration = 1000)
	Local $aresult = DllCall("kernel32.dll", "bool", "Beep", "dword", $ifreq, "dword", $iduration)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_bitblt($hdestdc, $ixdest, $iydest, $iwidth, $iheight, $hsrcdc, $ixsrc, $iysrc, $irop)
	Local $aresult = DllCall("gdi32.dll", "bool", "BitBlt", "handle", $hdestdc, "int", $ixdest, "int", $iydest, "int", $iwidth, "int", $iheight, "handle", $hsrcdc, "int", $ixsrc, "int", $iysrc, "dword", $irop)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_callnexthookex($hhk, $icode, $wparam, $lparam)
	Local $aresult = DllCall("user32.dll", "lresult", "CallNextHookEx", "handle", $hhk, "int", $icode, "wparam", $wparam, "lparam", $lparam)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_callwindowproc($pprevwndfunc, $hwnd, $imsg, $wparam, $lparam)
	Local $aresult = DllCall("user32.dll", "lresult", "CallWindowProc", "ptr", $pprevwndfunc, "hwnd", $hwnd, "uint", $imsg, "wparam", $wparam, "lparam", $lparam)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_clienttoscreen($hwnd, ByRef $tpoint)
	Local $aret = DllCall("user32.dll", "bool", "ClientToScreen", "hwnd", $hwnd, "struct*", $tpoint)
	If @error OR NOT $aret[0] Then Return SetError(@error + 10, @extended, 0)
	Return $tpoint
EndFunc

Func _winapi_closehandle($hobject)
	Local $aresult = DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $hobject)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_combinergn($hrgndest, $hrgnsrc1, $hrgnsrc2, $icombinemode)
	Local $aresult = DllCall("gdi32.dll", "int", "CombineRgn", "handle", $hrgndest, "handle", $hrgnsrc1, "handle", $hrgnsrc2, "int", $icombinemode)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_commdlgextendederror()
	Local Const $cderr_dialogfailure = 65535
	Local Const $cderr_findresfailure = 6
	Local Const $cderr_initialization = 2
	Local Const $cderr_loadresfailure = 7
	Local Const $cderr_loadstrfailure = 5
	Local Const $cderr_lockresfailure = 8
	Local Const $cderr_memallocfailure = 9
	Local Const $cderr_memlockfailure = 10
	Local Const $cderr_nohinstance = 4
	Local Const $cderr_nohook = 11
	Local Const $cderr_notemplate = 3
	Local Const $cderr_registermsgfail = 12
	Local Const $cderr_structsize = 1
	Local Const $fnerr_buffertoosmall = 12291
	Local Const $fnerr_invalidfilename = 12290
	Local Const $fnerr_subclassfailure = 12289
	Local $aresult = DllCall("comdlg32.dll", "dword", "CommDlgExtendedError")
	If NOT @error Then
		Switch $aresult[0]
			Case $cderr_dialogfailure
				Return SetError($aresult[0], 0, "The dialog box could not be created." & @LF & "The common dialog box function's call to the DialogBox function failed." & @LF & "For example, this error occurs if the common dialog box call specifies an invalid window handle.")
			Case $cderr_findresfailure
				Return SetError($aresult[0], 0, "The common dialog box function failed to find a specified resource.")
			Case $cderr_initialization
				Return SetError($aresult[0], 0, "The common dialog box function failed during initialization." & @LF & "This error often occurs when sufficient memory is not available.")
			Case $cderr_loadresfailure
				Return SetError($aresult[0], 0, "The common dialog box function failed to load a specified resource.")
			Case $cderr_loadstrfailure
				Return SetError($aresult[0], 0, "The common dialog box function failed to load a specified string.")
			Case $cderr_lockresfailure
				Return SetError($aresult[0], 0, "The common dialog box function failed to lock a specified resource.")
			Case $cderr_memallocfailure
				Return SetError($aresult[0], 0, "The common dialog box function was unable to allocate memory for internal structures.")
			Case $cderr_memlockfailure
				Return SetError($aresult[0], 0, "The common dialog box function was unable to lock the memory associated with a handle.")
			Case $cderr_nohinstance
				Return SetError($aresult[0], 0, "The ENABLETEMPLATE flag was set in the Flags member of the initialization structure for the corresponding common dialog box," & @LF & "but you failed to provide a corresponding instance handle.")
			Case $cderr_nohook
				Return SetError($aresult[0], 0, "The ENABLEHOOK flag was set in the Flags member of the initialization structure for the corresponding common dialog box," & @LF & "but you failed to provide a pointer to a corresponding hook procedure.")
			Case $cderr_notemplate
				Return SetError($aresult[0], 0, "The ENABLETEMPLATE flag was set in the Flags member of the initialization structure for the corresponding common dialog box," & @LF & "but you failed to provide a corresponding template.")
			Case $cderr_registermsgfail
				Return SetError($aresult[0], 0, "The RegisterWindowMessage function returned an error code when it was called by the common dialog box function.")
			Case $cderr_structsize
				Return SetError($aresult[0], 0, "The lStructSize member of the initialization structure for the corresponding common dialog box is invalid")
			Case $fnerr_buffertoosmall
				Return SetError($aresult[0], 0, "The buffer pointed to by the lpstrFile member of the OPENFILENAME structure is too small for the file name specified by the user." & @LF & "The first two bytes of the lpstrFile buffer contain an integer value specifying the size, in TCHARs, required to receive the full name.")
			Case $fnerr_invalidfilename
				Return SetError($aresult[0], 0, "A file name is invalid.")
			Case $fnerr_subclassfailure
				Return SetError($aresult[0], 0, "An attempt to subclass a list box failed because sufficient memory was not available.")
		EndSwitch
	EndIf
	Return SetError(@error, @extended, "0x" & Hex($aresult[0]))
EndFunc

Func _winapi_copyicon($hicon)
	Local $aresult = DllCall("user32.dll", "handle", "CopyIcon", "handle", $hicon)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createbitmap($iwidth, $iheight, $iplanes = 1, $ibitsperpel = 1, $pbits = 0)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateBitmap", "int", $iwidth, "int", $iheight, "uint", $iplanes, "uint", $ibitsperpel, "ptr", $pbits)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createcompatiblebitmap($hdc, $iwidth, $iheight)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateCompatibleBitmap", "handle", $hdc, "int", $iwidth, "int", $iheight)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createcompatibledc($hdc)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateCompatibleDC", "handle", $hdc)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createevent($pattributes = 0, $bmanualreset = True, $binitialstate = True, $sname = "")
	Local $snametype = "wstr"
	If $sname = "" Then
		$sname = 0
		$snametype = "ptr"
	EndIf
	Local $aresult = DllCall("kernel32.dll", "handle", "CreateEventW", "ptr", $pattributes, "bool", $bmanualreset, "bool", $binitialstate, $snametype, $sname)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createfile($sfilename, $icreation, $iaccess = 4, $ishare = 0, $iattributes = 0, $psecurity = 0)
	Local $ida = 0, $ism = 0, $icd = 0, $ifa = 0
	If BitAND($iaccess, 1) <> 0 Then $ida = BitOR($ida, $generic_execute)
	If BitAND($iaccess, 2) <> 0 Then $ida = BitOR($ida, $generic_read)
	If BitAND($iaccess, 4) <> 0 Then $ida = BitOR($ida, $generic_write)
	If BitAND($ishare, 1) <> 0 Then $ism = BitOR($ism, $file_share_delete)
	If BitAND($ishare, 2) <> 0 Then $ism = BitOR($ism, $file_share_read)
	If BitAND($ishare, 4) <> 0 Then $ism = BitOR($ism, $file_share_write)
	Switch $icreation
		Case 0
			$icd = $create_new
		Case 1
			$icd = $create_always
		Case 2
			$icd = $open_existing
		Case 3
			$icd = $open_always
		Case 4
			$icd = $truncate_existing
	EndSwitch
	If BitAND($iattributes, 1) <> 0 Then $ifa = BitOR($ifa, $file_attribute_archive)
	If BitAND($iattributes, 2) <> 0 Then $ifa = BitOR($ifa, $file_attribute_hidden)
	If BitAND($iattributes, 4) <> 0 Then $ifa = BitOR($ifa, $file_attribute_readonly)
	If BitAND($iattributes, 8) <> 0 Then $ifa = BitOR($ifa, $file_attribute_system)
	Local $aresult = DllCall("kernel32.dll", "handle", "CreateFileW", "wstr", $sfilename, "dword", $ida, "dword", $ism, "ptr", $psecurity, "dword", $icd, "dword", $ifa, "ptr", 0)
	If @error OR ($aresult[0] = $invalid_handle_value) Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createfont($iheight, $iwidth, $iescape = 0, $iorientn = 0, $iweight = $__winapiconstant_fw_normal, $bitalic = False, $bunderline = False, $bstrikeout = False, $icharset = $__winapiconstant_default_charset, $ioutputprec = $__winapiconstant_out_default_precis, $iclipprec = $__winapiconstant_clip_default_precis, $iquality = $__winapiconstant_default_quality, $ipitch = 0, $sface = "Arial")
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateFontW", "int", $iheight, "int", $iwidth, "int", $iescape, "int", $iorientn, "int", $iweight, "dword", $bitalic, "dword", $bunderline, "dword", $bstrikeout, "dword", $icharset, "dword", $ioutputprec, "dword", $iclipprec, "dword", $iquality, "dword", $ipitch, "wstr", $sface)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createfontindirect($tlogfont)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateFontIndirectW", "struct*", $tlogfont)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createpen($ipenstyle, $iwidth, $ncolor)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreatePen", "int", $ipenstyle, "int", $iwidth, "INT", $ncolor)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createprocess($sappname, $scommand, $psecurity, $pthread, $binherit, $iflags, $penviron, $sdir, $pstartupinfo, $pprocess)
	Local $tcommand = 0
	Local $sappnametype = "wstr", $sdirtype = "wstr"
	If $sappname = "" Then
		$sappnametype = "ptr"
		$sappname = 0
	EndIf
	If $scommand <> "" Then
		$tcommand = DllStructCreate("wchar Text[" & 260 + 1 & "]")
		DllStructSetData($tcommand, "Text", $scommand)
	EndIf
	If $sdir = "" Then
		$sdirtype = "ptr"
		$sdir = 0
	EndIf
	Local $aresult = DllCall("kernel32.dll", "bool", "CreateProcessW", $sappnametype, $sappname, "struct*", $tcommand, "ptr", $psecurity, "ptr", $pthread, "bool", $binherit, "dword", $iflags, "ptr", $penviron, $sdirtype, $sdir, "ptr", $pstartupinfo, "ptr", $pprocess)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_createrectrgn($ileftrect, $itoprect, $irightrect, $ibottomrect)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateRectRgn", "int", $ileftrect, "int", $itoprect, "int", $irightrect, "int", $ibottomrect)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createroundrectrgn($ileftrect, $itoprect, $irightrect, $ibottomrect, $iwidthellipse, $iheightellipse)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateRoundRectRgn", "int", $ileftrect, "int", $itoprect, "int", $irightrect, "int", $ibottomrect, "int", $iwidthellipse, "int", $iheightellipse)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createsolidbitmap($hwnd, $icolor, $iwidth, $iheight, $brgb = 1)
	Local $hdc = _winapi_getdc($hwnd)
	Local $hdestdc = _winapi_createcompatibledc($hdc)
	Local $hbitmap = _winapi_createcompatiblebitmap($hdc, $iwidth, $iheight)
	Local $hold = _winapi_selectobject($hdestdc, $hbitmap)
	Local $trect = DllStructCreate($tagrect)
	DllStructSetData($trect, 1, 0)
	DllStructSetData($trect, 2, 0)
	DllStructSetData($trect, 3, $iwidth)
	DllStructSetData($trect, 4, $iheight)
	If $brgb Then
		$icolor = BitOR(BitAND($icolor, 65280), BitShift(BitAND($icolor, 255), -16), BitShift(BitAND($icolor, 16711680), 16))
	EndIf
	Local $hbrush = _winapi_createsolidbrush($icolor)
	If NOT _winapi_fillrect($hdestdc, $trect, $hbrush) Then
		_winapi_deleteobject($hbitmap)
		$hbitmap = 0
	EndIf
	_winapi_deleteobject($hbrush)
	_winapi_releasedc($hwnd, $hdc)
	_winapi_selectobject($hdestdc, $hold)
	_winapi_deletedc($hdestdc)
	If NOT $hbitmap Then Return SetError(1, 0, 0)
	Return $hbitmap
EndFunc

Func _winapi_createsolidbrush($ncolor)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateSolidBrush", "INT", $ncolor)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createwindowex($iexstyle, $sclass, $sname, $istyle, $ix, $iy, $iwidth, $iheight, $hparent, $hmenu = 0, $hinstance = 0, $pparam = 0)
	If $hinstance = 0 Then $hinstance = _winapi_getmodulehandle("")
	Local $aresult = DllCall("user32.dll", "hwnd", "CreateWindowExW", "dword", $iexstyle, "wstr", $sclass, "wstr", $sname, "dword", $istyle, "int", $ix, "int", $iy, "int", $iwidth, "int", $iheight, "hwnd", $hparent, "handle", $hmenu, "handle", $hinstance, "ptr", $pparam)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_defwindowproc($hwnd, $imsg, $iwparam, $ilparam)
	Local $aresult = DllCall("user32.dll", "lresult", "DefWindowProc", "hwnd", $hwnd, "uint", $imsg, "wparam", $iwparam, "lparam", $ilparam)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_deletedc($hdc)
	Local $aresult = DllCall("gdi32.dll", "bool", "DeleteDC", "handle", $hdc)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_deleteobject($hobject)
	Local $aresult = DllCall("gdi32.dll", "bool", "DeleteObject", "handle", $hobject)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_destroyicon($hicon)
	Local $aresult = DllCall("user32.dll", "bool", "DestroyIcon", "handle", $hicon)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_destroywindow($hwnd)
	Local $aresult = DllCall("user32.dll", "bool", "DestroyWindow", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_drawedge($hdc, $prect, $iedgetype, $iflags)
	Local $aresult = DllCall("user32.dll", "bool", "DrawEdge", "handle", $hdc, "ptr", $prect, "uint", $iedgetype, "uint", $iflags)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_drawframecontrol($hdc, $prect, $itype, $istate)
	Local $aresult = DllCall("user32.dll", "bool", "DrawFrameControl", "handle", $hdc, "ptr", $prect, "uint", $itype, "uint", $istate)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_drawicon($hdc, $ix, $iy, $hicon)
	Local $aresult = DllCall("user32.dll", "bool", "DrawIcon", "handle", $hdc, "int", $ix, "int", $iy, "handle", $hicon)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_drawiconex($hdc, $ix, $iy, $hicon, $iwidth = 0, $iheight = 0, $istep = 0, $hbrush = 0, $iflags = 3)
	Local $ioptions
	Switch $iflags
		Case 1
			$ioptions = $di_mask
		Case 2
			$ioptions = $di_image
		Case 3
			$ioptions = $di_normal
		Case 4
			$ioptions = $di_compat
		Case 5
			$ioptions = $di_defaultsize
		Case Else
			$ioptions = $di_nomirror
	EndSwitch
	Local $aresult = DllCall("user32.dll", "bool", "DrawIconEx", "handle", $hdc, "int", $ix, "int", $iy, "handle", $hicon, "int", $iwidth, "int", $iheight, "uint", $istep, "handle", $hbrush, "uint", $ioptions)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_drawline($hdc, $ix1, $iy1, $ix2, $iy2)
	_winapi_moveto($hdc, $ix1, $iy1)
	If @error Then Return SetError(@error, @extended, False)
	_winapi_lineto($hdc, $ix2, $iy2)
	If @error Then Return SetError(@error + 10, @extended, False)
	Return True
EndFunc

Func _winapi_drawtext($hdc, $stext, ByRef $trect, $iflags)
	Local $aresult = DllCall("user32.dll", "int", "DrawTextW", "handle", $hdc, "wstr", $stext, "int", -1, "struct*", $trect, "uint", $iflags)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_duplicatehandle($hsourceprocesshandle, $hsourcehandle, $htargetprocesshandle, $idesiredaccess, $binherithandle, $ioptions)
	Local $aresult = DllCall("kernel32.dll", "bool", "DuplicateHandle", "handle", $hsourceprocesshandle, "handle", $hsourcehandle, "handle", $htargetprocesshandle, "handle*", 0, "dword", $idesiredaccess, "bool", $binherithandle, "dword", $ioptions)
	If @error OR NOT $aresult[0] Then Return SetError(@error, @extended, 0)
	Return $aresult[4]
EndFunc

Func _winapi_enablewindow($hwnd, $benable = True)
	Local $aresult = DllCall("user32.dll", "bool", "EnableWindow", "hwnd", $hwnd, "bool", $benable)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_enumdisplaydevices($sdevice, $idevnum)
	Local $tname = 0, $iflags = 0, $adevice[5]
	If $sdevice <> "" Then
		$tname = DllStructCreate("wchar Text[" & StringLen($sdevice) + 1 & "]")
		DllStructSetData($tname, "Text", $sdevice)
	EndIf
	Local $tdevice = DllStructCreate($tagdisplay_device)
	Local $idevice = DllStructGetSize($tdevice)
	DllStructSetData($tdevice, "Size", $idevice)
	Local $aret = DllCall("user32.dll", "bool", "EnumDisplayDevicesW", "struct*", $tname, "dword", $idevnum, "struct*", $tdevice, "dword", 1)
	If @error OR NOT $aret[0] Then Return SetError(@error + 10, @extended, 0)
	Local $in = DllStructGetData($tdevice, "Flags")
	If BitAND($in, $display_device_attached_to_desktop) <> 0 Then $iflags = BitOR($iflags, 1)
	If BitAND($in, $display_device_primary_device) <> 0 Then $iflags = BitOR($iflags, 2)
	If BitAND($in, $display_device_mirroring_driver) <> 0 Then $iflags = BitOR($iflags, 4)
	If BitAND($in, $display_device_vga_compatible) <> 0 Then $iflags = BitOR($iflags, 8)
	If BitAND($in, $display_device_removable) <> 0 Then $iflags = BitOR($iflags, 16)
	If BitAND($in, $display_device_modespruned) <> 0 Then $iflags = BitOR($iflags, 32)
	$adevice[0] = True
	$adevice[1] = DllStructGetData($tdevice, "Name")
	$adevice[2] = DllStructGetData($tdevice, "String")
	$adevice[3] = $iflags
	$adevice[4] = DllStructGetData($tdevice, "ID")
	Return $adevice
EndFunc

Func _winapi_enumwindows($bvisible = True, $hwnd = Default)
	__winapi_enumwindowsinit()
	If $hwnd = Default Then $hwnd = _winapi_getdesktopwindow()
	__winapi_enumwindowschild($hwnd, $bvisible)
	Return $__g_awinlist_winapi
EndFunc

Func __winapi_enumwindowsadd($hwnd, $sclass = "")
	If $sclass = "" Then $sclass = _winapi_getclassname($hwnd)
	$__g_awinlist_winapi[0][0] += 1
	Local $icount = $__g_awinlist_winapi[0][0]
	If $icount >= $__g_awinlist_winapi[0][1] Then
		ReDim $__g_awinlist_winapi[$icount + 64][2]
		$__g_awinlist_winapi[0][1] += 64
	EndIf
	$__g_awinlist_winapi[$icount][0] = $hwnd
	$__g_awinlist_winapi[$icount][1] = $sclass
EndFunc

Func __winapi_enumwindowschild($hwnd, $bvisible = True)
	$hwnd = _winapi_getwindow($hwnd, $gw_child)
	While $hwnd <> 0
		If (NOT $bvisible) OR _winapi_iswindowvisible($hwnd) Then
			__winapi_enumwindowsadd($hwnd)
			__winapi_enumwindowschild($hwnd, $bvisible)
		EndIf
		$hwnd = _winapi_getwindow($hwnd, $gw_hwndnext)
	WEnd
EndFunc

Func __winapi_enumwindowsinit()
	ReDim $__g_awinlist_winapi[64][2]
	$__g_awinlist_winapi[0][0] = 0
	$__g_awinlist_winapi[0][1] = 64
EndFunc

Func _winapi_enumwindowspopup()
	__winapi_enumwindowsinit()
	Local $hwnd = _winapi_getwindow(_winapi_getdesktopwindow(), $gw_child)
	Local $sclass
	While $hwnd <> 0
		If _winapi_iswindowvisible($hwnd) Then
			$sclass = _winapi_getclassname($hwnd)
			If $sclass = "#32768" Then
				__winapi_enumwindowsadd($hwnd)
			ElseIf $sclass = "ToolbarWindow32" Then
				__winapi_enumwindowsadd($hwnd)
			ElseIf $sclass = "ToolTips_Class32" Then
				__winapi_enumwindowsadd($hwnd)
			ElseIf $sclass = "BaseBar" Then
				__winapi_enumwindowschild($hwnd)
			EndIf
		EndIf
		$hwnd = _winapi_getwindow($hwnd, $gw_hwndnext)
	WEnd
	Return $__g_awinlist_winapi
EndFunc

Func _winapi_enumwindowstop()
	__winapi_enumwindowsinit()
	Local $hwnd = _winapi_getwindow(_winapi_getdesktopwindow(), $gw_child)
	While $hwnd <> 0
		If _winapi_iswindowvisible($hwnd) Then __winapi_enumwindowsadd($hwnd)
		$hwnd = _winapi_getwindow($hwnd, $gw_hwndnext)
	WEnd
	Return $__g_awinlist_winapi
EndFunc

Func _winapi_expandenvironmentstrings($sstring)
	Local $aresult = DllCall("kernel32.dll", "dword", "ExpandEnvironmentStringsW", "wstr", $sstring, "wstr", "", "dword", 4096)
	If @error OR NOT $aresult[0] Then Return SetError(@error + 10, @extended, "")
	Return $aresult[2]
EndFunc

Func _winapi_extracticonex($sfile, $iindex, $plarge, $psmall, $iicons)
	Local $aresult = DllCall("shell32.dll", "uint", "ExtractIconExW", "wstr", $sfile, "int", $iindex, "struct*", $plarge, "struct*", $psmall, "uint", $iicons)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_fatalappexit($smessage)
	DllCall("kernel32.dll", "none", "FatalAppExitW", "uint", 0, "wstr", $smessage)
	If @error Then Return SetError(@error, @extended)
EndFunc

Func _winapi_fillrect($hdc, $prect, $hbrush)
	Local $aresult
	If IsPtr($hbrush) Then
		$aresult = DllCall("user32.dll", "int", "FillRect", "handle", $hdc, "struct*", $prect, "handle", $hbrush)
	Else
		$aresult = DllCall("user32.dll", "int", "FillRect", "handle", $hdc, "struct*", $prect, "dword_ptr", $hbrush)
	EndIf
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_findexecutable($sfilename, $sdirectory = "")
	Local $aresult = DllCall("shell32.dll", "INT", "FindExecutableW", "wstr", $sfilename, "wstr", $sdirectory, "wstr", "")
	If @error Then Return SetError(@error, @extended, "")
	If $aresult[0] <= 32 Then Return SetError(10, $aresult[0], "")
	Return SetExtended($aresult[0], $aresult[3])
EndFunc

Func _winapi_findwindow($sclassname, $swindowname)
	Local $aresult = DllCall("user32.dll", "hwnd", "FindWindowW", "wstr", $sclassname, "wstr", $swindowname)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_flashwindow($hwnd, $binvert = True)
	Local $aresult = DllCall("user32.dll", "bool", "FlashWindow", "hwnd", $hwnd, "bool", $binvert)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_flashwindowex($hwnd, $iflags = 3, $icount = 3, $itimeout = 0)
	Local $tflash = DllStructCreate($tagflashwinfo)
	Local $iflash = DllStructGetSize($tflash)
	Local $imode = 0
	If BitAND($iflags, 1) <> 0 Then $imode = BitOR($imode, $flashw_caption)
	If BitAND($iflags, 2) <> 0 Then $imode = BitOR($imode, $flashw_tray)
	If BitAND($iflags, 4) <> 0 Then $imode = BitOR($imode, $flashw_timer)
	If BitAND($iflags, 8) <> 0 Then $imode = BitOR($imode, $flashw_timernofg)
	DllStructSetData($tflash, "Size", $iflash)
	DllStructSetData($tflash, "hWnd", $hwnd)
	DllStructSetData($tflash, "Flags", $imode)
	DllStructSetData($tflash, "Count", $icount)
	DllStructSetData($tflash, "Timeout", $itimeout)
	Local $aresult = DllCall("user32.dll", "bool", "FlashWindowEx", "struct*", $tflash)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_floattoint($nfloat)
	Local $tfloat = DllStructCreate("float")
	Local $tint = DllStructCreate("int", DllStructGetPtr($tfloat))
	DllStructSetData($tfloat, 1, $nfloat)
	Return DllStructGetData($tint, 1)
EndFunc

Func _winapi_flushfilebuffers($hfile)
	Local $aresult = DllCall("kernel32.dll", "bool", "FlushFileBuffers", "handle", $hfile)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_formatmessage($iflags, $psource, $imessageid, $ilanguageid, ByRef $pbuffer, $isize, $varguments)
	Local $sbuffertype = "struct*"
	If IsString($pbuffer) Then $sbuffertype = "wstr"
	Local $aresult = DllCall("Kernel32.dll", "dword", "FormatMessageW", "dword", $iflags, "ptr", $psource, "dword", $imessageid, "dword", $ilanguageid, $sbuffertype, $pbuffer, "dword", $isize, "ptr", $varguments)
	If @error OR NOT $aresult[0] Then Return SetError(@error + 10, @extended, 0)
	If $sbuffertype = "wstr" Then $pbuffer = $aresult[5]
	Return $aresult[0]
EndFunc

Func _winapi_framerect($hdc, $prect, $hbrush)
	Local $aresult = DllCall("user32.dll", "int", "FrameRect", "handle", $hdc, "ptr", $prect, "handle", $hbrush)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_freelibrary($hmodule)
	Local $aresult = DllCall("kernel32.dll", "bool", "FreeLibrary", "handle", $hmodule)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_getancestor($hwnd, $iflags = 1)
	Local $aresult = DllCall("user32.dll", "hwnd", "GetAncestor", "hwnd", $hwnd, "uint", $iflags)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getasynckeystate($ikey)
	Local $aresult = DllCall("user32.dll", "short", "GetAsyncKeyState", "int", $ikey)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getbkmode($hdc)
	Local $aresult = DllCall("gdi32.dll", "int", "GetBkMode", "handle", $hdc)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getclassname($hwnd)
	If NOT IsHWnd($hwnd) Then $hwnd = GUICtrlGetHandle($hwnd)
	Local $aresult = DllCall("user32.dll", "int", "GetClassNameW", "hwnd", $hwnd, "wstr", "", "int", 4096)
	If @error OR NOT $aresult[0] Then Return SetError(@error, @extended, "")
	Return SetExtended($aresult[0], $aresult[2])
EndFunc

Func _winapi_getclientheight($hwnd)
	Local $trect = _winapi_getclientrect($hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return DllStructGetData($trect, "Bottom") - DllStructGetData($trect, "Top")
EndFunc

Func _winapi_getclientwidth($hwnd)
	Local $trect = _winapi_getclientrect($hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return DllStructGetData($trect, "Right") - DllStructGetData($trect, "Left")
EndFunc

Func _winapi_getclientrect($hwnd)
	Local $trect = DllStructCreate($tagrect)
	Local $aret = DllCall("user32.dll", "bool", "GetClientRect", "hwnd", $hwnd, "struct*", $trect)
	If @error OR NOT $aret[0] Then Return SetError(@error + 10, @extended, 0)
	Return $trect
EndFunc

Func _winapi_getcurrentprocess()
	Local $aresult = DllCall("kernel32.dll", "handle", "GetCurrentProcess")
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getcurrentprocessid()
	Local $aresult = DllCall("kernel32.dll", "dword", "GetCurrentProcessId")
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getcurrentthread()
	Local $aresult = DllCall("kernel32.dll", "handle", "GetCurrentThread")
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getcurrentthreadid()
	Local $aresult = DllCall("kernel32.dll", "dword", "GetCurrentThreadId")
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getcursorinfo()
	Local $tcursor = DllStructCreate($tagcursorinfo)
	Local $icursor = DllStructGetSize($tcursor)
	DllStructSetData($tcursor, "Size", $icursor)
	Local $aret = DllCall("user32.dll", "bool", "GetCursorInfo", "struct*", $tcursor)
	If @error OR NOT $aret[0] Then Return SetError(@error + 10, @extended, 0)
	Local $acursor[5]
	$acursor[0] = True
	$acursor[1] = DllStructGetData($tcursor, "Flags") <> 0
	$acursor[2] = DllStructGetData($tcursor, "hCursor")
	$acursor[3] = DllStructGetData($tcursor, "X")
	$acursor[4] = DllStructGetData($tcursor, "Y")
	Return $acursor
EndFunc

Func _winapi_getdc($hwnd)
	Local $aresult = DllCall("user32.dll", "handle", "GetDC", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getdesktopwindow()
	Local $aresult = DllCall("user32.dll", "hwnd", "GetDesktopWindow")
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getdevicecaps($hdc, $iindex)
	Local $aresult = DllCall("gdi32.dll", "int", "GetDeviceCaps", "handle", $hdc, "int", $iindex)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getdibits($hdc, $hbmp, $istartscan, $iscanlines, $pbits, $pbi, $iusage)
	Local $aresult = DllCall("gdi32.dll", "int", "GetDIBits", "handle", $hdc, "handle", $hbmp, "uint", $istartscan, "uint", $iscanlines, "ptr", $pbits, "ptr", $pbi, "uint", $iusage)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_getdlgctrlid($hwnd)
	Local $aresult = DllCall("user32.dll", "int", "GetDlgCtrlID", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getdlgitem($hwnd, $iitemid)
	Local $aresult = DllCall("user32.dll", "hwnd", "GetDlgItem", "hwnd", $hwnd, "int", $iitemid)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getfilesizeex($hfile)
	Local $aresult = DllCall("kernel32.dll", "bool", "GetFileSizeEx", "handle", $hfile, "int64*", 0)
	If @error OR NOT $aresult[0] Then Return SetError(@error, @extended, -1)
	Return $aresult[2]
EndFunc

Func _winapi_getfocus()
	Local $aresult = DllCall("user32.dll", "hwnd", "GetFocus")
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getforegroundwindow()
	Local $aresult = DllCall("user32.dll", "hwnd", "GetForegroundWindow")
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getguiresources($iflag = 0, $hprocess = -1)
	If $hprocess = -1 Then $hprocess = _winapi_getcurrentprocess()
	Local $aresult = DllCall("user32.dll", "dword", "GetGuiResources", "handle", $hprocess, "dword", $iflag)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_geticoninfo($hicon)
	Local $tinfo = DllStructCreate($tagiconinfo)
	Local $aret = DllCall("user32.dll", "bool", "GetIconInfo", "handle", $hicon, "struct*", $tinfo)
	If @error OR NOT $aret[0] Then Return SetError(@error + 10, @extended, 0)
	Local $aicon[6]
	$aicon[0] = True
	$aicon[1] = DllStructGetData($tinfo, "Icon") <> 0
	$aicon[2] = DllStructGetData($tinfo, "XHotSpot")
	$aicon[3] = DllStructGetData($tinfo, "YHotSpot")
	$aicon[4] = DllStructGetData($tinfo, "hMask")
	$aicon[5] = DllStructGetData($tinfo, "hColor")
	Return $aicon
EndFunc

Func _winapi_getlasterrormessage()
	Local $ilasterror = _winapi_getlasterror()
	Local $tbufferptr = DllStructCreate("ptr")
	Local $ncount = _winapi_formatmessage(BitOR($format_message_allocate_buffer, $format_message_from_system), 0, $ilasterror, 0, $tbufferptr, 0, 0)
	If @error Then Return SetError(@error, 0, "")
	Local $stext = ""
	Local $pbuffer = DllStructGetData($tbufferptr, 1)
	If $pbuffer Then
		If $ncount > 0 Then
			Local $tbuffer = DllStructCreate("wchar[" & ($ncount + 1) & "]", $pbuffer)
			$stext = DllStructGetData($tbuffer, 1)
		EndIf
		_winapi_localfree($pbuffer)
	EndIf
	Return $stext
EndFunc

Func _winapi_getlayeredwindowattributes($hwnd, ByRef $itranscolor, ByRef $itransparency, $bcolorref = False)
	$itranscolor = -1
	$itransparency = -1
	Local $aresult = DllCall("user32.dll", "bool", "GetLayeredWindowAttributes", "hwnd", $hwnd, "INT*", $itranscolor, "byte*", $itransparency, "dword*", 0)
	If @error OR NOT $aresult[0] Then Return SetError(@error, @extended, 0)
	If NOT $bcolorref Then
		$aresult[2] = Int(BinaryMid($aresult[2], 3, 1) & BinaryMid($aresult[2], 2, 1) & BinaryMid($aresult[2], 1, 1))
	EndIf
	$itranscolor = $aresult[2]
	$itransparency = $aresult[3]
	Return $aresult[4]
EndFunc

Func _winapi_getmodulehandle($smodulename)
	Local $smodulenametype = "wstr"
	If $smodulename = "" Then
		$smodulename = 0
		$smodulenametype = "ptr"
	EndIf
	Local $aresult = DllCall("kernel32.dll", "handle", "GetModuleHandleW", $smodulenametype, $smodulename)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getmousepos($btoclient = False, $hwnd = 0)
	Local $imode = Opt("MouseCoordMode", 1)
	Local $apos = MouseGetPos()
	Opt("MouseCoordMode", $imode)
	Local $tpoint = DllStructCreate($tagpoint)
	DllStructSetData($tpoint, "X", $apos[0])
	DllStructSetData($tpoint, "Y", $apos[1])
	If $btoclient AND NOT _winapi_screentoclient($hwnd, $tpoint) Then Return SetError(@error + 20, @extended, 0)
	Return $tpoint
EndFunc

Func _winapi_getmouseposx($btoclient = False, $hwnd = 0)
	Local $tpoint = _winapi_getmousepos($btoclient, $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return DllStructGetData($tpoint, "X")
EndFunc

Func _winapi_getmouseposy($btoclient = False, $hwnd = 0)
	Local $tpoint = _winapi_getmousepos($btoclient, $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return DllStructGetData($tpoint, "Y")
EndFunc

Func _winapi_getobject($hobject, $isize, $pobject)
	Local $aresult = DllCall("gdi32.dll", "int", "GetObjectW", "handle", $hobject, "int", $isize, "ptr", $pobject)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getopenfilename($stitle = "", $sfilter = "All files (*.*)", $sinitaldir = ".", $sdefaultfile = "", $sdefaultext = "", $ifilterindex = 1, $iflags = 0, $iflagsex = 0, $hwndowner = 0)
	Local $ipathlen = 4096
	Local $inulls = 0
	Local $tofn = DllStructCreate($tagopenfilename)
	Local $afiles[1] = [0]
	Local $iflag = $iflags
	Local $asflines = StringSplit($sfilter, "|")
	Local $asfilter[$asflines[0] * 2 + 1]
	Local $istart, $ifinal, $tagfilter
	$asfilter[0] = $asflines[0] * 2
	For $i = 1 To $asflines[0]
		$istart = StringInStr($asflines[$i], "(", 0, 1)
		$ifinal = StringInStr($asflines[$i], ")", 0, -1)
		$asfilter[$i * 2 - 1] = StringStripWS(StringLeft($asflines[$i], $istart - 1), $str_stripleading + $str_striptrailing)
		$asfilter[$i * 2] = StringStripWS(StringTrimRight(StringTrimLeft($asflines[$i], $istart), StringLen($asflines[$i]) - $ifinal + 1), $str_stripleading + $str_striptrailing)
		$tagfilter &= "wchar[" & StringLen($asfilter[$i * 2 - 1]) + 1 & "];wchar[" & StringLen($asfilter[$i * 2]) + 1 & "];"
	Next
	Local $ttitle = DllStructCreate("wchar Title[" & StringLen($stitle) + 1 & "]")
	Local $tinitialdir = DllStructCreate("wchar InitDir[" & StringLen($sinitaldir) + 1 & "]")
	Local $tfilter = DllStructCreate($tagfilter & "wchar")
	Local $tpath = DllStructCreate("wchar Path[" & $ipathlen & "]")
	Local $textn = DllStructCreate("wchar Extension[" & StringLen($sdefaultext) + 1 & "]")
	For $i = 1 To $asfilter[0]
		DllStructSetData($tfilter, $i, $asfilter[$i])
	Next
	DllStructSetData($ttitle, "Title", $stitle)
	DllStructSetData($tinitialdir, "InitDir", $sinitaldir)
	DllStructSetData($tpath, "Path", $sdefaultfile)
	DllStructSetData($textn, "Extension", $sdefaultext)
	DllStructSetData($tofn, "StructSize", DllStructGetSize($tofn))
	DllStructSetData($tofn, "hwndOwner", $hwndowner)
	DllStructSetData($tofn, "lpstrFilter", DllStructGetPtr($tfilter))
	DllStructSetData($tofn, "nFilterIndex", $ifilterindex)
	DllStructSetData($tofn, "lpstrFile", DllStructGetPtr($tpath))
	DllStructSetData($tofn, "nMaxFile", $ipathlen)
	DllStructSetData($tofn, "lpstrInitialDir", DllStructGetPtr($tinitialdir))
	DllStructSetData($tofn, "lpstrTitle", DllStructGetPtr($ttitle))
	DllStructSetData($tofn, "Flags", $iflag)
	DllStructSetData($tofn, "lpstrDefExt", DllStructGetPtr($textn))
	DllStructSetData($tofn, "FlagsEx", $iflagsex)
	Local $ares = DllCall("comdlg32.dll", "bool", "GetOpenFileNameW", "struct*", $tofn)
	If @error OR NOT $ares[0] Then Return SetError(@error + 10, @extended, $afiles)
	If BitAND($iflags, $ofn_allowmultiselect) = $ofn_allowmultiselect AND BitAND($iflags, $ofn_explorer) = $ofn_explorer Then
		For $x = 1 To $ipathlen
			If DllStructGetData($tpath, "Path", $x) = Chr(0) Then
				DllStructSetData($tpath, "Path", "|", $x)
				$inulls += 1
			Else
				$inulls = 0
			EndIf
			If $inulls = 2 Then ExitLoop
		Next
		DllStructSetData($tpath, "Path", Chr(0), $x - 1)
		$afiles = StringSplit(DllStructGetData($tpath, "Path"), "|")
		If $afiles[0] = 1 Then Return __winapi_parsefiledialogpath(DllStructGetData($tpath, "Path"))
		Return StringSplit(DllStructGetData($tpath, "Path"), "|")
	ElseIf BitAND($iflags, $ofn_allowmultiselect) = $ofn_allowmultiselect Then
		$afiles = StringSplit(DllStructGetData($tpath, "Path"), " ")
		If $afiles[0] = 1 Then Return __winapi_parsefiledialogpath(DllStructGetData($tpath, "Path"))
		Return StringSplit(StringReplace(DllStructGetData($tpath, "Path"), " ", "|"), "|")
	Else
		Return __winapi_parsefiledialogpath(DllStructGetData($tpath, "Path"))
	EndIf
EndFunc

Func _winapi_getoverlappedresult($hfile, $poverlapped, ByRef $ibytes, $bwait = False)
	Local $aresult = DllCall("kernel32.dll", "bool", "GetOverlappedResult", "handle", $hfile, "ptr", $poverlapped, "dword*", 0, "bool", $bwait)
	If @error OR NOT $aresult[0] Then Return SetError(@error, @extended, False)
	$ibytes = $aresult[3]
	Return $aresult[0]
EndFunc

Func _winapi_getparent($hwnd)
	Local $aresult = DllCall("user32.dll", "hwnd", "GetParent", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getprocaddress($hmodule, $vname)
	Local $stype = "str"
	If IsNumber($vname) Then $stype = "word"
	Local $aresult = DllCall("kernel32.dll", "ptr", "GetProcAddress", "handle", $hmodule, $stype, $vname)
	If @error OR NOT $aresult[0] Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getprocessaffinitymask($hprocess)
	Local $aresult = DllCall("kernel32.dll", "bool", "GetProcessAffinityMask", "handle", $hprocess, "dword_ptr*", 0, "dword_ptr*", 0)
	If @error OR NOT $aresult[0] Then Return SetError(@error + 10, @extended, 0)
	Local $amask[3]
	$amask[0] = True
	$amask[1] = $aresult[2]
	$amask[2] = $aresult[3]
	Return $amask
EndFunc

Func _winapi_getsavefilename($stitle = "", $sfilter = "All files (*.*)", $sinitaldir = ".", $sdefaultfile = "", $sdefaultext = "", $ifilterindex = 1, $iflags = 0, $iflagsex = 0, $hwndowner = 0)
	Local $ipathlen = 4096
	Local $tofn = DllStructCreate($tagopenfilename)
	Local $afiles[1] = [0]
	Local $iflag = $iflags
	Local $asflines = StringSplit($sfilter, "|")
	Local $asfilter[$asflines[0] * 2 + 1]
	Local $istart, $ifinal, $tagfilter
	$asfilter[0] = $asflines[0] * 2
	For $i = 1 To $asflines[0]
		$istart = StringInStr($asflines[$i], "(", 0, 1)
		$ifinal = StringInStr($asflines[$i], ")", 0, -1)
		$asfilter[$i * 2 - 1] = StringStripWS(StringLeft($asflines[$i], $istart - 1), $str_stripleading + $str_striptrailing)
		$asfilter[$i * 2] = StringStripWS(StringTrimRight(StringTrimLeft($asflines[$i], $istart), StringLen($asflines[$i]) - $ifinal + 1), $str_stripleading + $str_striptrailing)
		$tagfilter &= "wchar[" & StringLen($asfilter[$i * 2 - 1]) + 1 & "];wchar[" & StringLen($asfilter[$i * 2]) + 1 & "];"
	Next
	Local $ttitle = DllStructCreate("wchar Title[" & StringLen($stitle) + 1 & "]")
	Local $tinitialdir = DllStructCreate("wchar InitDir[" & StringLen($sinitaldir) + 1 & "]")
	Local $tfilter = DllStructCreate($tagfilter & "wchar")
	Local $tpath = DllStructCreate("wchar Path[" & $ipathlen & "]")
	Local $textn = DllStructCreate("wchar Extension[" & StringLen($sdefaultext) + 1 & "]")
	For $i = 1 To $asfilter[0]
		DllStructSetData($tfilter, $i, $asfilter[$i])
	Next
	DllStructSetData($ttitle, "Title", $stitle)
	DllStructSetData($tinitialdir, "InitDir", $sinitaldir)
	DllStructSetData($tpath, "Path", $sdefaultfile)
	DllStructSetData($textn, "Extension", $sdefaultext)
	DllStructSetData($tofn, "StructSize", DllStructGetSize($tofn))
	DllStructSetData($tofn, "hwndOwner", $hwndowner)
	DllStructSetData($tofn, "lpstrFilter", DllStructGetPtr($tfilter))
	DllStructSetData($tofn, "nFilterIndex", $ifilterindex)
	DllStructSetData($tofn, "lpstrFile", DllStructGetPtr($tpath))
	DllStructSetData($tofn, "nMaxFile", $ipathlen)
	DllStructSetData($tofn, "lpstrInitialDir", DllStructGetPtr($tinitialdir))
	DllStructSetData($tofn, "lpstrTitle", DllStructGetPtr($ttitle))
	DllStructSetData($tofn, "Flags", $iflag)
	DllStructSetData($tofn, "lpstrDefExt", DllStructGetPtr($textn))
	DllStructSetData($tofn, "FlagsEx", $iflagsex)
	Local $ares = DllCall("comdlg32.dll", "bool", "GetSaveFileNameW", "struct*", $tofn)
	If @error OR NOT $ares[0] Then Return SetError(@error + 10, @extended, $afiles)
	Return __winapi_parsefiledialogpath(DllStructGetData($tpath, "Path"))
EndFunc

Func _winapi_getstockobject($iobject)
	Local $aresult = DllCall("gdi32.dll", "handle", "GetStockObject", "int", $iobject)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getstdhandle($istdhandle)
	If $istdhandle < 0 OR $istdhandle > 2 Then Return SetError(2, 0, -1)
	Local Const $ahandle[3] = [-10, -11, -12]
	Local $aresult = DllCall("kernel32.dll", "handle", "GetStdHandle", "dword", $ahandle[$istdhandle])
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_getsyscolor($iindex)
	Local $aresult = DllCall("user32.dll", "INT", "GetSysColor", "int", $iindex)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getsyscolorbrush($iindex)
	Local $aresult = DllCall("user32.dll", "handle", "GetSysColorBrush", "int", $iindex)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getsystemmetrics($iindex)
	Local $aresult = DllCall("user32.dll", "int", "GetSystemMetrics", "int", $iindex)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_gettextextentpoint32($hdc, $stext)
	Local $tsize = DllStructCreate($tagsize)
	Local $isize = StringLen($stext)
	Local $aret = DllCall("gdi32.dll", "bool", "GetTextExtentPoint32W", "handle", $hdc, "wstr", $stext, "int", $isize, "struct*", $tsize)
	If @error OR NOT $aret[0] Then Return SetError(@error + 10, @extended, 0)
	Return $tsize
EndFunc

Func _winapi_gettextmetrics($hdc)
	Local $ttextmetric = DllStructCreate($tagtextmetric)
	Local $aret = DllCall("gdi32.dll", "bool", "GetTextMetricsW", "handle", $hdc, "struct*", $ttextmetric)
	If @error OR NOT $aret[0] Then Return SetError(@error + 10, @extended, 0)
	Return $ttextmetric
EndFunc

Func _winapi_getwindow($hwnd, $icmd)
	Local $aresult = DllCall("user32.dll", "hwnd", "GetWindow", "hwnd", $hwnd, "uint", $icmd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getwindowdc($hwnd)
	Local $aresult = DllCall("user32.dll", "handle", "GetWindowDC", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getwindowheight($hwnd)
	Local $trect = _winapi_getwindowrect($hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return DllStructGetData($trect, "Bottom") - DllStructGetData($trect, "Top")
EndFunc

Func _winapi_getwindowlong($hwnd, $iindex)
	Local $sfuncname = "GetWindowLongW"
	If @AutoItX64 Then $sfuncname = "GetWindowLongPtrW"
	Local $aresult = DllCall("user32.dll", "long_ptr", $sfuncname, "hwnd", $hwnd, "int", $iindex)
	If @error OR NOT $aresult[0] Then Return SetError(@error + 10, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getwindowplacement($hwnd)
	Local $twindowplacement = DllStructCreate($tagwindowplacement)
	DllStructSetData($twindowplacement, "length", DllStructGetSize($twindowplacement))
	Local $aret = DllCall("user32.dll", "bool", "GetWindowPlacement", "hwnd", $hwnd, "struct*", $twindowplacement)
	If @error OR NOT $aret[0] Then Return SetError(@error + 10, @extended, 0)
	Return $twindowplacement
EndFunc

Func _winapi_getwindowrect($hwnd)
	Local $trect = DllStructCreate($tagrect)
	Local $aret = DllCall("user32.dll", "bool", "GetWindowRect", "hwnd", $hwnd, "struct*", $trect)
	If @error OR NOT $aret[0] Then Return SetError(@error + 10, @extended, 0)
	Return $trect
EndFunc

Func _winapi_getwindowrgn($hwnd, $hrgn)
	Local $aresult = DllCall("user32.dll", "int", "GetWindowRgn", "hwnd", $hwnd, "handle", $hrgn)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getwindowtext($hwnd)
	Local $aresult = DllCall("user32.dll", "int", "GetWindowTextW", "hwnd", $hwnd, "wstr", "", "int", 4096)
	If @error OR NOT $aresult[0] Then Return SetError(@error + 10, @extended, "")
	Return SetExtended($aresult[0], $aresult[2])
EndFunc

Func _winapi_getwindowthreadprocessid($hwnd, ByRef $ipid)
	Local $aresult = DllCall("user32.dll", "dword", "GetWindowThreadProcessId", "hwnd", $hwnd, "dword*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	$ipid = $aresult[2]
	Return $aresult[0]
EndFunc

Func _winapi_getwindowwidth($hwnd)
	Local $trect = _winapi_getwindowrect($hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return DllStructGetData($trect, "Right") - DllStructGetData($trect, "Left")
EndFunc

Func _winapi_getxyfrompoint(ByRef $tpoint, ByRef $ix, ByRef $iy)
	$ix = DllStructGetData($tpoint, "X")
	$iy = DllStructGetData($tpoint, "Y")
EndFunc

Func _winapi_globalmemorystatus()
	Local $tmem = DllStructCreate($tagmemorystatusex)
	DllStructSetData($tmem, 1, DllStructGetSize($tmem))
	Local $aret = DllCall("kernel32.dll", "bool", "GlobalMemoryStatusEx", "struct*", $tmem)
	If @error OR NOT $aret[0] Then Return SetError(@error + 10, @extended, 0)
	Local $amem[7]
	$amem[0] = DllStructGetData($tmem, 2)
	$amem[1] = DllStructGetData($tmem, 3)
	$amem[2] = DllStructGetData($tmem, 4)
	$amem[3] = DllStructGetData($tmem, 5)
	$amem[4] = DllStructGetData($tmem, 6)
	$amem[5] = DllStructGetData($tmem, 7)
	$amem[6] = DllStructGetData($tmem, 8)
	Return $amem
EndFunc

Func _winapi_guidfromstring($sguid)
	Local $tguid = DllStructCreate($tagguid)
	_winapi_guidfromstringex($sguid, $tguid)
	If @error Then Return SetError(@error + 10, @extended, 0)
	Return $tguid
EndFunc

Func _winapi_guidfromstringex($sguid, $pguid)
	Local $aresult = DllCall("ole32.dll", "long", "CLSIDFromString", "wstr", $sguid, "struct*", $pguid)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_hiword($ilong)
	Return BitShift($ilong, 16)
EndFunc

Func _winapi_inprocess($hwnd, ByRef $hlastwnd)
	If $hwnd = $hlastwnd Then Return True
	For $ii = $__g_ainprocess_winapi[0][0] To 1 Step -1
		If $hwnd = $__g_ainprocess_winapi[$ii][0] Then
			If $__g_ainprocess_winapi[$ii][1] Then
				$hlastwnd = $hwnd
				Return True
			Else
				Return False
			EndIf
		EndIf
	Next
	Local $ipid
	_winapi_getwindowthreadprocessid($hwnd, $ipid)
	Local $icount = $__g_ainprocess_winapi[0][0] + 1
	If $icount >= 64 Then $icount = 1
	$__g_ainprocess_winapi[0][0] = $icount
	$__g_ainprocess_winapi[$icount][0] = $hwnd
	$__g_ainprocess_winapi[$icount][1] = ($ipid = @AutoItPID)
	Return $__g_ainprocess_winapi[$icount][1]
EndFunc

Func _winapi_inttofloat($iint)
	Local $tint = DllStructCreate("int")
	Local $tfloat = DllStructCreate("float", DllStructGetPtr($tint))
	DllStructSetData($tint, 1, $iint)
	Return DllStructGetData($tfloat, 1)
EndFunc

Func _winapi_isclassname($hwnd, $sclassname)
	Local $sseparator = Opt("GUIDataSeparatorChar")
	Local $aclassname = StringSplit($sclassname, $sseparator)
	If NOT IsHWnd($hwnd) Then $hwnd = GUICtrlGetHandle($hwnd)
	Local $sclasscheck = _winapi_getclassname($hwnd)
	For $x = 1 To UBound($aclassname) - 1
		If StringUpper(StringMid($sclasscheck, 1, StringLen($aclassname[$x]))) = StringUpper($aclassname[$x]) Then Return True
	Next
	Return False
EndFunc


Func _winapi_iswindowvisible($hwnd)
	Local $aresult = DllCall("user32.dll", "bool", "IsWindowVisible", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_lineto($hdc, $ix, $iy)
	Local $aresult = DllCall("gdi32.dll", "bool", "LineTo", "handle", $hdc, "int", $ix, "int", $iy)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_loadbitmap($hinstance, $sbitmap)
	Local $sbitmaptype = "int"
	If IsString($sbitmap) Then $sbitmaptype = "wstr"
	Local $aresult = DllCall("user32.dll", "handle", "LoadBitmapW", "handle", $hinstance, $sbitmaptype, $sbitmap)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_loadimage($hinstance, $simage, $itype, $ixdesired, $iydesired, $iload)
	Local $aresult, $simagetype = "int"
	If IsString($simage) Then $simagetype = "wstr"
	$aresult = DllCall("user32.dll", "handle", "LoadImageW", "handle", $hinstance, $simagetype, $simage, "uint", $itype, "int", $ixdesired, "int", $iydesired, "uint", $iload)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_loadlibrary($sfilename)
	Local $aresult = DllCall("kernel32.dll", "handle", "LoadLibraryW", "wstr", $sfilename)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_loadlibraryex($sfilename, $iflags = 0)
	Local $aresult = DllCall("kernel32.dll", "handle", "LoadLibraryExW", "wstr", $sfilename, "ptr", 0, "dword", $iflags)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_loadshell32icon($iiconid)
	Local $ticons = DllStructCreate("ptr Data")
	Local $iicons = _winapi_extracticonex("shell32.dll", $iiconid, 0, $ticons, 1)
	If @error Then Return SetError(@error, @extended, 0)
	If $iicons <= 0 Then Return SetError(10, 0, 0)
	Return DllStructGetData($ticons, "Data")
EndFunc

Func _winapi_loadstring($hinstance, $istringid)
	Local $aresult = DllCall("user32.dll", "int", "LoadStringW", "handle", $hinstance, "uint", $istringid, "wstr", "", "int", 4096)
	If @error OR NOT $aresult[0] Then Return SetError(@error + 10, @extended, "")
	Return SetExtended($aresult[0], $aresult[3])
EndFunc

Func _winapi_localfree($hmem)
	Local $aresult = DllCall("kernel32.dll", "handle", "LocalFree", "handle", $hmem)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_loword($ilong)
	Return BitAND($ilong, 65535)
EndFunc

Func _winapi_makelangid($iprimary, $isub)
	Return BitOR(BitShift($isub, -10), $iprimary)
EndFunc

Func _winapi_makelcid($ilgid, $isrtid)
	Return BitOR(BitShift($isrtid, -16), $ilgid)
EndFunc

Func _winapi_makelong($ilo, $ihi)
	Return BitOR(BitShift($ihi, -16), BitAND($ilo, 65535))
EndFunc

Func _winapi_makeqword($ilodword, $ihidword)
	Local $tint64 = DllStructCreate("uint64")
	Local $tdwords = DllStructCreate("dword;dword", DllStructGetPtr($tint64))
	DllStructSetData($tdwords, 1, $ilodword)
	DllStructSetData($tdwords, 2, $ihidword)
	Return DllStructGetData($tint64, 1)
EndFunc

Func _winapi_messagebeep($itype = 1)
	Local $isound
	Switch $itype
		Case 1
			$isound = 0
		Case 2
			$isound = 16
		Case 3
			$isound = 32
		Case 4
			$isound = 48
		Case 5
			$isound = 64
		Case Else
			$isound = -1
	EndSwitch
	Local $aresult = DllCall("user32.dll", "bool", "MessageBeep", "uint", $isound)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_msgbox($iflags, $stitle, $stext)
	BlockInput(0)
	MsgBox($iflags, $stitle, $stext & "      ")
EndFunc

Func _winapi_mouse_event($iflags, $ix = 0, $iy = 0, $idata = 0, $iextrainfo = 0)
	DllCall("user32.dll", "none", "mouse_event", "dword", $iflags, "dword", $ix, "dword", $iy, "dword", $idata, "ulong_ptr", $iextrainfo)
	If @error Then Return SetError(@error, @extended)
EndFunc

Func _winapi_moveto($hdc, $ix, $iy)
	Local $aresult = DllCall("gdi32.dll", "bool", "MoveToEx", "handle", $hdc, "int", $ix, "int", $iy, "ptr", 0)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_movewindow($hwnd, $ix, $iy, $iwidth, $iheight, $brepaint = True)
	Local $aresult = DllCall("user32.dll", "bool", "MoveWindow", "hwnd", $hwnd, "int", $ix, "int", $iy, "int", $iwidth, "int", $iheight, "bool", $brepaint)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_muldiv($inumber, $inumerator, $idenominator)
	Local $aresult = DllCall("kernel32.dll", "int", "MulDiv", "int", $inumber, "int", $inumerator, "int", $idenominator)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_multibytetowidechar($stext, $icodepage = 0, $iflags = 0, $bretstring = False)
	Local $stexttype = "str"
	If NOT IsString($stext) Then $stexttype = "struct*"
	Local $aresult = DllCall("kernel32.dll", "int", "MultiByteToWideChar", "uint", $icodepage, "dword", $iflags, $stexttype, $stext, "int", -1, "ptr", 0, "int", 0)
	If @error OR NOT $aresult[0] Then Return SetError(@error + 10, @extended, 0)
	Local $iout = $aresult[0]
	Local $tout = DllStructCreate("wchar[" & $iout & "]")
	$aresult = DllCall("kernel32.dll", "int", "MultiByteToWideChar", "uint", $icodepage, "dword", $iflags, $stexttype, $stext, "int", -1, "struct*", $tout, "int", $iout)
	If @error OR NOT $aresult[0] Then Return SetError(@error + 20, @extended, 0)
	If $bretstring Then Return DllStructGetData($tout, 1)
	Return $tout
EndFunc

Func _winapi_multibytetowidecharex($stext, $ptext, $icodepage = 0, $iflags = 0)
	Local $aresult = DllCall("kernel32.dll", "int", "MultiByteToWideChar", "uint", $icodepage, "dword", $iflags, "STR", $stext, "int", -1, "struct*", $ptext, "int", (StringLen($stext) + 1) * 2)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_openprocess($iaccess, $binherit, $ipid, $bdebugpriv = False)
	Local $aresult = DllCall("kernel32.dll", "handle", "OpenProcess", "dword", $iaccess, "bool", $binherit, "dword", $ipid)
	If @error Then Return SetError(@error, @extended, 0)
	If $aresult[0] Then Return $aresult[0]
	If NOT $bdebugpriv Then Return SetError(100, 0, 0)
	Local $htoken = _security__openthreadtokenex(BitOR($token_adjust_privileges, $token_query))
	If @error Then Return SetError(@error + 10, @extended, 0)
	_security__setprivilege($htoken, "SeDebugPrivilege", True)
	Local $ierror = @error
	Local $iextended = @extended
	Local $iret = 0
	If NOT @error Then
		$aresult = DllCall("kernel32.dll", "handle", "OpenProcess", "dword", $iaccess, "bool", $binherit, "dword", $ipid)
		$ierror = @error
		$iextended = @extended
		If $aresult[0] Then $iret = $aresult[0]
		_security__setprivilege($htoken, "SeDebugPrivilege", False)
		If @error Then
			$ierror = @error + 20
			$iextended = @extended
		EndIf
	Else
		$ierror = @error + 30
	EndIf
	_winapi_closehandle($htoken)
	Return SetError($ierror, $iextended, $iret)
EndFunc

Func __winapi_parsefiledialogpath($spath)
	Local $afiles[3]
	$afiles[0] = 2
	Local $stemp = StringMid($spath, 1, StringInStr($spath, "\", 0, -1) - 1)
	$afiles[1] = $stemp
	$afiles[2] = StringMid($spath, StringInStr($spath, "\", 0, -1) + 1)
	Return $afiles
EndFunc

Func _winapi_pathfindonpath(Const $sfile, $aextrapaths = "", Const $spathdelimiter = @LF)
	Local $iextracount = 0
	If IsString($aextrapaths) Then
		If StringLen($aextrapaths) Then
			$aextrapaths = StringSplit($aextrapaths, $spathdelimiter, $str_entiresplit + $str_nocount)
			$iextracount = UBound($aextrapaths, $ubound_rows)
		EndIf
	ElseIf IsArray($aextrapaths) Then
		$iextracount = UBound($aextrapaths)
	EndIf
	Local $tpaths, $tpathptrs
	If $iextracount Then
		Local $tagstruct = ""
		For $path In $aextrapaths
			$tagstruct &= "wchar[" & StringLen($path) + 1 & "];"
		Next
		$tpaths = DllStructCreate($tagstruct)
		$tpathptrs = DllStructCreate("ptr[" & $iextracount + 1 & "]")
		For $i = 1 To $iextracount
			DllStructSetData($tpaths, $i, $aextrapaths[$i - 1])
			DllStructSetData($tpathptrs, 1, DllStructGetPtr($tpaths, $i), $i)
		Next
		DllStructSetData($tpathptrs, 1, Ptr(0), $iextracount + 1)
	EndIf
	Local $aresult = DllCall("shlwapi.dll", "bool", "PathFindOnPathW", "wstr", $sfile, "struct*", $tpathptrs)
	If @error OR NOT $aresult[0] Then Return SetError(@error + 10, @extended, $sfile)
	Return $aresult[1]
EndFunc

Func _winapi_pointfromrect(ByRef $trect, $bcenter = True)
	Local $ix1 = DllStructGetData($trect, "Left")
	Local $iy1 = DllStructGetData($trect, "Top")
	Local $ix2 = DllStructGetData($trect, "Right")
	Local $iy2 = DllStructGetData($trect, "Bottom")
	If $bcenter Then
		$ix1 = $ix1 + (($ix2 - $ix1) / 2)
		$iy1 = $iy1 + (($iy2 - $iy1) / 2)
	EndIf
	Local $tpoint = DllStructCreate($tagpoint)
	DllStructSetData($tpoint, "X", $ix1)
	DllStructSetData($tpoint, "Y", $iy1)
	Return $tpoint
EndFunc

Func _winapi_postmessage($hwnd, $imsg, $iwparam, $ilparam)
	Local $aresult = DllCall("user32.dll", "bool", "PostMessage", "hwnd", $hwnd, "uint", $imsg, "wparam", $iwparam, "lparam", $ilparam)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_primarylangid($ilgid)
	Return BitAND($ilgid, 1023)
EndFunc

Func _winapi_ptinrect(ByRef $trect, ByRef $tpoint)
	Local $aresult = DllCall("user32.dll", "bool", "PtInRect", "struct*", $trect, "struct", $tpoint)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_readfile($hfile, $pbuffer, $itoread, ByRef $iread, $poverlapped = 0)
	Local $aresult = DllCall("kernel32.dll", "bool", "ReadFile", "handle", $hfile, "ptr", $pbuffer, "dword", $itoread, "dword*", 0, "ptr", $poverlapped)
	If @error Then Return SetError(@error, @extended, False)
	$iread = $aresult[4]
	Return $aresult[0]
EndFunc

Func _winapi_readprocessmemory($hprocess, $pbaseaddress, $pbuffer, $isize, ByRef $iread)
	Local $aresult = DllCall("kernel32.dll", "bool", "ReadProcessMemory", "handle", $hprocess, "ptr", $pbaseaddress, "ptr", $pbuffer, "ulong_ptr", $isize, "ulong_ptr*", 0)
	If @error Then Return SetError(@error, @extended, False)
	$iread = $aresult[5]
	Return $aresult[0]
EndFunc

Func _winapi_rectisempty(ByRef $trect)
	Return (DllStructGetData($trect, "Left") = 0) AND (DllStructGetData($trect, "Top") = 0) AND (DllStructGetData($trect, "Right") = 0) AND (DllStructGetData($trect, "Bottom") = 0)
EndFunc

Func _winapi_redrawwindow($hwnd, $trect = 0, $hregion = 0, $iflags = 5)
	Local $aresult = DllCall("user32.dll", "bool", "RedrawWindow", "hwnd", $hwnd, "struct*", $trect, "handle", $hregion, "uint", $iflags)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_registerwindowmessage($smessage)
	Local $aresult = DllCall("user32.dll", "uint", "RegisterWindowMessageW", "wstr", $smessage)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_releasecapture()
	Local $aresult = DllCall("user32.dll", "bool", "ReleaseCapture")
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_releasedc($hwnd, $hdc)
	Local $aresult = DllCall("user32.dll", "int", "ReleaseDC", "hwnd", $hwnd, "handle", $hdc)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_screentoclient($hwnd, ByRef $tpoint)
	Local $aresult = DllCall("user32.dll", "bool", "ScreenToClient", "hwnd", $hwnd, "struct*", $tpoint)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_selectobject($hdc, $hgdiobj)
	Local $aresult = DllCall("gdi32.dll", "handle", "SelectObject", "handle", $hdc, "handle", $hgdiobj)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setbkcolor($hdc, $icolor)
	Local $aresult = DllCall("gdi32.dll", "INT", "SetBkColor", "handle", $hdc, "INT", $icolor)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_setbkmode($hdc, $ibkmode)
	Local $aresult = DllCall("gdi32.dll", "int", "SetBkMode", "handle", $hdc, "int", $ibkmode)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_setcapture($hwnd)
	Local $aresult = DllCall("user32.dll", "hwnd", "SetCapture", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_setcursor($hcursor)
	Local $aresult = DllCall("user32.dll", "handle", "SetCursor", "handle", $hcursor)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_setdefaultprinter($sprinter)
	Local $aresult = DllCall("winspool.drv", "bool", "SetDefaultPrinterW", "wstr", $sprinter)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setdibits($hdc, $hbmp, $istartscan, $iscanlines, $pbits, $pbmi, $icoloruse = 0)
	Local $aresult = DllCall("gdi32.dll", "int", "SetDIBits", "handle", $hdc, "handle", $hbmp, "uint", $istartscan, "uint", $iscanlines, "ptr", $pbits, "ptr", $pbmi, "INT", $icoloruse)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setendoffile($hfile)
	Local $aresult = DllCall("kernel32.dll", "bool", "SetEndOfFile", "handle", $hfile)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setevent($hevent)
	Local $aresult = DllCall("kernel32.dll", "bool", "SetEvent", "handle", $hevent)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setfilepointer($hfile, $ipos, $imethod = 0)
	Local $aresult = DllCall("kernel32.dll", "INT", "SetFilePointer", "handle", $hfile, "long", $ipos, "ptr", 0, "long", $imethod)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_setfocus($hwnd)
	Local $aresult = DllCall("user32.dll", "hwnd", "SetFocus", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_setfont($hwnd, $hfont, $bredraw = True)
	_sendmessage($hwnd, $__winapiconstant_wm_setfont, $hfont, $bredraw, 0, "hwnd")
EndFunc

Func _winapi_sethandleinformation($hobject, $imask, $iflags)
	Local $aresult = DllCall("kernel32.dll", "bool", "SetHandleInformation", "handle", $hobject, "dword", $imask, "dword", $iflags)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setlayeredwindowattributes($hwnd, $itranscolor, $itransgui = 255, $iflags = 3, $bcolorref = False)
	If $iflags = Default OR $iflags = "" OR $iflags < 0 Then $iflags = 3
	If NOT $bcolorref Then
		$itranscolor = Int(BinaryMid($itranscolor, 3, 1) & BinaryMid($itranscolor, 2, 1) & BinaryMid($itranscolor, 1, 1))
	EndIf
	Local $aresult = DllCall("user32.dll", "bool", "SetLayeredWindowAttributes", "hwnd", $hwnd, "INT", $itranscolor, "byte", $itransgui, "dword", $iflags)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setparent($hwndchild, $hwndparent)
	Local $aresult = DllCall("user32.dll", "hwnd", "SetParent", "hwnd", $hwndchild, "hwnd", $hwndparent)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_setprocessaffinitymask($hprocess, $imask)
	Local $aresult = DllCall("kernel32.dll", "bool", "SetProcessAffinityMask", "handle", $hprocess, "ulong_ptr", $imask)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setsyscolors($velements, $vcolors)
	Local $bisearray = IsArray($velements), $biscarray = IsArray($vcolors)
	Local $ielementnum
	If NOT $biscarray AND NOT $bisearray Then
		$ielementnum = 1
	ElseIf $biscarray OR $bisearray Then
		If NOT $biscarray OR NOT $bisearray Then Return SetError(-1, -1, False)
		If UBound($velements) <> UBound($vcolors) Then Return SetError(-1, -1, False)
		$ielementnum = UBound($velements)
	EndIf
	Local $telements = DllStructCreate("int Element[" & $ielementnum & "]")
	Local $tcolors = DllStructCreate("INT NewColor[" & $ielementnum & "]")
	If NOT $bisearray Then
		DllStructSetData($telements, "Element", $velements, 1)
	Else
		For $x = 0 To $ielementnum - 1
			DllStructSetData($telements, "Element", $velements[$x], $x + 1)
		Next
	EndIf
	If NOT $biscarray Then
		DllStructSetData($tcolors, "NewColor", $vcolors, 1)
	Else
		For $x = 0 To $ielementnum - 1
			DllStructSetData($tcolors, "NewColor", $vcolors[$x], $x + 1)
		Next
	EndIf
	Local $aresult = DllCall("user32.dll", "bool", "SetSysColors", "int", $ielementnum, "struct*", $telements, "struct*", $tcolors)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_settextcolor($hdc, $icolor)
	Local $aresult = DllCall("gdi32.dll", "INT", "SetTextColor", "handle", $hdc, "INT", $icolor)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_setwindowlong($hwnd, $iindex, $ivalue)
	_winapi_setlasterror(0)
	Local $sfuncname = "SetWindowLongW"
	If @AutoItX64 Then $sfuncname = "SetWindowLongPtrW"
	Local $aresult = DllCall("user32.dll", "long_ptr", $sfuncname, "hwnd", $hwnd, "int", $iindex, "long_ptr", $ivalue)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_setwindowplacement($hwnd, $pwindowplacement)
	Local $aresult = DllCall("user32.dll", "bool", "SetWindowPlacement", "hwnd", $hwnd, "ptr", $pwindowplacement)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setwindowpos($hwnd, $hafter, $ix, $iy, $icx, $icy, $iflags)
	Local $aresult = DllCall("user32.dll", "bool", "SetWindowPos", "hwnd", $hwnd, "hwnd", $hafter, "int", $ix, "int", $iy, "int", $icx, "int", $icy, "uint", $iflags)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setwindowrgn($hwnd, $hrgn, $bredraw = True)
	Local $aresult = DllCall("user32.dll", "int", "SetWindowRgn", "hwnd", $hwnd, "handle", $hrgn, "bool", $bredraw)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setwindowshookex($idhook, $pfn, $hmod, $ithreadid = 0)
	Local $aresult = DllCall("user32.dll", "handle", "SetWindowsHookEx", "int", $idhook, "ptr", $pfn, "handle", $hmod, "dword", $ithreadid)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_setwindowtext($hwnd, $stext)
	Local $aresult = DllCall("user32.dll", "bool", "SetWindowTextW", "hwnd", $hwnd, "wstr", $stext)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_showcursor($bshow)
	Local $aresult = DllCall("user32.dll", "int", "ShowCursor", "bool", $bshow)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_showerror($stext, $bexit = True)
	_winapi_msgbox($mb_systemmodal, "Error", $stext)
	If $bexit Then Exit
EndFunc

Func _winapi_showmsg($stext)
	_winapi_msgbox($mb_systemmodal, "Information", $stext)
EndFunc

Func _winapi_showwindow($hwnd, $icmdshow = 5)
	Local $aresult = DllCall("user32.dll", "bool", "ShowWindow", "hwnd", $hwnd, "int", $icmdshow)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_stringfromguid($pguid)
	Local $aresult = DllCall("ole32.dll", "int", "StringFromGUID2", "struct*", $pguid, "wstr", "", "int", 40)
	If @error OR NOT $aresult[0] Then Return SetError(@error, @extended, "")
	Return SetExtended($aresult[0], $aresult[2])
EndFunc

Func _winapi_stringlena(Const ByRef $tstring)
	Local $aresult = DllCall("kernel32.dll", "int", "lstrlenA", "struct*", $tstring)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_stringlenw(Const ByRef $tstring)
	Local $aresult = DllCall("kernel32.dll", "int", "lstrlenW", "struct*", $tstring)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_sublangid($ilgid)
	Return BitShift($ilgid, 10)
EndFunc

Func _winapi_systemparametersinfo($iaction, $iparam = 0, $vparam = 0, $iwinini = 0)
	Local $aresult = DllCall("user32.dll", "bool", "SystemParametersInfoW", "uint", $iaction, "uint", $iparam, "ptr", $vparam, "uint", $iwinini)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_twipsperpixelx()
	Local $hdc, $itwipsperpixelx
	$hdc = _winapi_getdc(0)
	$itwipsperpixelx = 1440 / _winapi_getdevicecaps($hdc, $__winapiconstant_logpixelsx)
	_winapi_releasedc(0, $hdc)
	Return $itwipsperpixelx
EndFunc

Func _winapi_twipsperpixely()
	Local $hdc, $itwipsperpixely
	$hdc = _winapi_getdc(0)
	$itwipsperpixely = 1440 / _winapi_getdevicecaps($hdc, $__winapiconstant_logpixelsy)
	_winapi_releasedc(0, $hdc)
	Return $itwipsperpixely
EndFunc

Func _winapi_unhookwindowshookex($hhk)
	Local $aresult = DllCall("user32.dll", "bool", "UnhookWindowsHookEx", "handle", $hhk)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_updatelayeredwindow($hwnd, $hdcdest, $pptdest, $psize, $hdcsrce, $pptsrce, $irgb, $pblend, $iflags)
	Local $aresult = DllCall("user32.dll", "bool", "UpdateLayeredWindow", "hwnd", $hwnd, "handle", $hdcdest, "ptr", $pptdest, "ptr", $psize, "handle", $hdcsrce, "ptr", $pptsrce, "dword", $irgb, "ptr", $pblend, "dword", $iflags)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_updatewindow($hwnd)
	Local $aresult = DllCall("user32.dll", "bool", "UpdateWindow", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_waitforinputidle($hprocess, $itimeout = -1)
	Local $aresult = DllCall("user32.dll", "dword", "WaitForInputIdle", "handle", $hprocess, "dword", $itimeout)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_waitformultipleobjects($icount, $phandles, $bwaitall = False, $itimeout = -1)
	Local $aresult = DllCall("kernel32.dll", "INT", "WaitForMultipleObjects", "dword", $icount, "ptr", $phandles, "bool", $bwaitall, "dword", $itimeout)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_waitforsingleobject($hhandle, $itimeout = -1)
	Local $aresult = DllCall("kernel32.dll", "INT", "WaitForSingleObject", "handle", $hhandle, "dword", $itimeout)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_widechartomultibyte($punicode, $icodepage = 0, $bretstring = True)
	Local $sunicodetype = "wstr"
	If NOT IsString($punicode) Then $sunicodetype = "struct*"
	Local $aresult = DllCall("kernel32.dll", "int", "WideCharToMultiByte", "uint", $icodepage, "dword", 0, $sunicodetype, $punicode, "int", -1, "ptr", 0, "int", 0, "ptr", 0, "ptr", 0)
	If @error OR NOT $aresult[0] Then Return SetError(@error + 20, @extended, "")
	Local $tmultibyte = DllStructCreate("char[" & $aresult[0] & "]")
	$aresult = DllCall("kernel32.dll", "int", "WideCharToMultiByte", "uint", $icodepage, "dword", 0, $sunicodetype, $punicode, "int", -1, "struct*", $tmultibyte, "int", $aresult[0], "ptr", 0, "ptr", 0)
	If @error OR NOT $aresult[0] Then Return SetError(@error + 10, @extended, "")
	If $bretstring Then Return DllStructGetData($tmultibyte, 1)
	Return $tmultibyte
EndFunc

Func _winapi_windowfrompoint(ByRef $tpoint)
	Local $aresult = DllCall("user32.dll", "hwnd", "WindowFromPoint", "struct", $tpoint)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_writeconsole($hconsole, $stext)
	Local $aresult = DllCall("kernel32.dll", "bool", "WriteConsoleW", "handle", $hconsole, "wstr", $stext, "dword", StringLen($stext), "dword*", 0, "ptr", 0)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_writefile($hfile, $pbuffer, $itowrite, ByRef $iwritten, $poverlapped = 0)
	Local $aresult = DllCall("kernel32.dll", "bool", "WriteFile", "handle", $hfile, "ptr", $pbuffer, "dword", $itowrite, "dword*", 0, "ptr", $poverlapped)
	If @error Then Return SetError(@error, @extended, False)
	$iwritten = $aresult[4]
	Return $aresult[0]
EndFunc

Func _winapi_writeprocessmemory($hprocess, $pbaseaddress, $pbuffer, $isize, ByRef $iwritten, $sbuffer = "ptr")
	Local $aresult = DllCall("kernel32.dll", "bool", "WriteProcessMemory", "handle", $hprocess, "ptr", $pbaseaddress, $sbuffer, $pbuffer, "ulong_ptr", $isize, "ulong_ptr*", 0)
	If @error Then Return SetError(@error, @extended, False)
	$iwritten = $aresult[5]
	Return $aresult[0]
EndFunc
Global $icarai = 1
Func DesCriptString($msgcriptografada,$chave)
	$buffer = $msgcriptografada
	Global $icarai
	$msgcriptografada = BinaryToString($msgcriptografada)
	$resultado = _Crypt_DecryptData($msgcriptografada, $chave, $CALG_AES_256)
	$resultado = BinaryToString($resultado)
	$seila = FileOpen("hola" & $icarai & ".txt", 2)
	$icarai += 1
	FileWrite($seila,$resultado & "	" & "DesCriptString('" & $buffer & "','63504267791308182131')")
	FileClose($seila)
	Return $resultado
EndFunc
DesCriptString('0xDFAC504535F5E850E471DB3F2B6F7528','63504267791308182131')